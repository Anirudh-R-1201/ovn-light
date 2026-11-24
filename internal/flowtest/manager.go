// SPDX-License-Identifier: Apache-2.0
package flowtest

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/trozet/ovn-light/internal/model"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

const namespace = "ovn-light-tests"
const jobName = "cross-node-tcp"
const runLabel = "ovn-light.io/run"

type Request struct {
	SourceNode      string `json:"sourceNode"`
	DestinationNode string `json:"destinationNode"`
	Network         string `json:"network"`
	Test            string `json:"test"`
	Case            string `json:"case"`
}
type Status struct {
	Enabled bool `json:"enabled"`
	Run     *Run `json:"run,omitempty"`
}
type Manager struct {
	client                    kubernetes.Interface
	image, device, rdma, file string
	wake                      chan struct{}
	operation                 sync.Mutex
	mu                        sync.Mutex
	run                       *Run
}

func New(client kubernetes.Interface, image, device, rdma, dir string) (*Manager, error) {
	for _, device := range []string{device, rdma} {
		if device != "" && (len(validation.IsQualifiedName(device)) > 0 || !strings.Contains(device, "/") || strings.HasPrefix(device, "kubernetes.io/")) {
			return nil, fmt.Errorf("invalid traffic test device resource")
		}
	}
	m := &Manager{rdma: rdma, wake: make(chan struct{}, 1), client: client, image: image, device: device, file: filepath.Join(dir, "traffic-test.json")}
	raw, err := os.ReadFile(m.file)
	if err == nil {
		err = json.Unmarshal(raw, &m.run)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if m.run != nil && m.run.Test == "" && m.run.Case == "" {
		// Earlier releases stored only the cross-node TCP profile.
		m.run.Test, m.run.Case = defaultTest, crossPod
	}
	return m, nil
}
func (m *Manager) saveLocked() error {
	b, err := json.Marshal(m.run)
	if err != nil {
		return err
	}
	if err = os.WriteFile(m.file+".tmp", b, 0600); err != nil {
		return err
	}
	return os.Rename(m.file+".tmp", m.file)
}
func (m *Manager) Status() Status {
	if m == nil {
		return Status{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	result := Status{Enabled: true}
	if m.run != nil {
		b, _ := json.Marshal(m.run)
		_ = json.Unmarshal(b, &result.Run)
	}
	return result
}
func (m *Manager) Observe(v model.View, r model.OffloadReport, pods []core.Pod) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.run != nil && m.run.Finished == nil {
		m.run.observe(v, r, pods)
	}
}

func jobSpec(image, device, id string, q Request) *batch.Job {
	profile, _ := lookupProfile(q.Test)
	testCase, _ := lookupCase(q.Case)
	labels := map[string]string{runLabel: id, "app.kubernetes.io/managed-by": "ovn-light"}
	runner := core.Container{
		Name: "runner", Image: image, ImagePullPolicy: core.PullIfNotPresent,
		Env: []core.EnvVar{
			{Name: "RUN_ID", Value: id},
			{Name: "TEST_IMAGE", Value: image},
			{Name: "TEST_TYPE", Value: profile.ID},
			{Name: "TEST_CASE", Value: testCase.ID},
			{Name: "TEST_SECONDS", Value: fmt.Sprint(profile.Seconds)},
			{Name: "SOURCE_NODE", Value: q.SourceNode},
			{Name: "DESTINATION_NODE", Value: q.DestinationNode},
			{Name: "DEVICE_RESOURCE", Value: device},
			{Name: "JOB_UID", ValueFrom: &core.EnvVarSource{FieldRef: &core.ObjectFieldSelector{
				FieldPath: "metadata.labels['batch.kubernetes.io/controller-uid']",
			}}},
		},
		SecurityContext: &core.SecurityContext{
			AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true),
			Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}},
		},
		Resources: core.ResourceRequirements{
			Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("10m"), core.ResourceMemory: resource.MustParse("32Mi")},
			Limits:   core.ResourceList{core.ResourceCPU: resource.MustParse("500m"), core.ResourceMemory: resource.MustParse("160Mi")},
		},
		VolumeMounts: []core.VolumeMount{{Name: "tmp", MountPath: "/tmp"}},
	}
	return &batch.Job{
		ObjectMeta: meta.ObjectMeta{Name: jobName, Labels: labels, Annotations: map[string]string{
			"ovn-light.io/test": profile.ID, "ovn-light.io/case": testCase.ID,
			"ovn-light.io/source": q.SourceNode, "ovn-light.io/destination": q.DestinationNode,
		}},
		Spec: batch.JobSpec{
			BackoffLimit: ptr.To(int32(0)), ActiveDeadlineSeconds: ptr.To(int64(340)), TTLSecondsAfterFinished: ptr.To(int32(60)),
			Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: core.PodSpec{
				RestartPolicy: core.RestartPolicyNever, ServiceAccountName: "traffic-runner",
				Containers: []core.Container{runner}, TerminationGracePeriodSeconds: ptr.To(int64(2)),
				SecurityContext: &core.PodSecurityContext{
					RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(10001)),
					SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault},
				},
				Volumes: []core.Volume{{Name: "tmp", VolumeSource: core.VolumeSource{EmptyDir: &core.EmptyDirVolumeSource{
					SizeLimit: resource.NewQuantity(16<<20, resource.BinarySI),
				}}}},
			}},
		},
	}
}

func runFromJob(j *batch.Job) *Run {
	src, dst := j.Annotations["ovn-light.io/source"], j.Annotations["ovn-light.io/destination"]
	nodes := []NodeEvidence{{Node: src, State: "unknown"}}
	if src != dst {
		nodes = append(nodes, NodeEvidence{Node: dst, State: "unknown"})
	}
	profile, _ := lookupProfile(j.Annotations["ovn-light.io/test"])
	testCase, _ := lookupCase(j.Annotations["ovn-light.io/case"])
	return &Run{Test: profile.ID, Case: testCase.ID, ID: j.Labels[runLabel], JobUID: string(j.UID), Network: "default", Phase: "running", Source: Endpoint{Node: src}, Destination: Endpoint{Node: dst}, Started: j.CreationTimestamp.Time, Nodes: nodes}
}
func (m *Manager) Start(ctx context.Context, q Request) (Status, error) {
	if m == nil {
		return Status{}, fmt.Errorf("traffic tests are disabled")
	}
	profile, ok := lookupProfile(q.Test)
	if !ok {
		return Status{}, fmt.Errorf("unknown suite test %q", q.Test)
	}
	testCase, ok := lookupCase(q.Case)
	if !ok || testCase.Service && !profile.Service {
		return Status{}, fmt.Errorf("unsupported test case for %s", profile.Name)
	}
	if q.Network != "default" {
		return Status{}, fmt.Errorf("choose the default network")
	}
	if (q.SourceNode == q.DestinationNode) != testCase.SameNode {
		return Status{}, fmt.Errorf("node selection must match the test case %s", testCase.ID)
	}
	dev := m.device
	if profile.RDMA {
		dev = m.rdma
		if dev == "" {
			return Status{}, fmt.Errorf("configure the RDMA device resource to enable this test")
		}
	}
	m.operation.Lock()
	defer m.operation.Unlock()
	if s := m.Status(); s.Run != nil && s.Run.Finished == nil {
		return s, fmt.Errorf("a traffic test is already running")
	}
	nodeNames := []string{q.SourceNode}
	if !testCase.SameNode {
		nodeNames = append(nodeNames, q.DestinationNode)
	}
	for _, name := range nodeNames {
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return Status{}, fmt.Errorf("invalid node name")
		}
		n, err := m.client.CoreV1().Nodes().Get(ctx, name, meta.GetOptions{})
		if err != nil {
			return Status{}, err
		}
		if !readyNode(n) {
			return Status{}, fmt.Errorf("%s must be a schedulable Ready Linux node", name)
		}
		if dev != "" {
			needed := int64(1)
			if testCase.SameNode {
				needed = 2
			}
			qty := n.Status.Allocatable[core.ResourceName(dev)]
			if qty.Value() < needed {
				return Status{}, fmt.Errorf("%s needs %d allocatable %s devices", name, needed, dev)
			}
		}
	}
	// TFT reuses its pod and Service names. Job deletion can finish while an
	// endpoint still terminates, so keep a new run from attaching to it.
	selector := meta.ListOptions{LabelSelector: runLabel, Limit: 1}
	pods, err := m.client.CoreV1().Pods(namespace).List(ctx, selector)
	if err != nil {
		return Status{}, err
	}
	if len(pods.Items) > 0 {
		return m.Status(), fmt.Errorf("previous test pods are being cleaned up; try again shortly")
	}
	if testCase.Service {
		services, err := m.client.CoreV1().Services(namespace).List(ctx, selector)
		if err != nil {
			return Status{}, err
		}
		if len(services.Items) > 0 {
			return m.Status(), fmt.Errorf("previous test Service is being cleaned up; try again shortly")
		}
	}
	id := strings.ToLower(rand.Text())
	j, err := m.client.BatchV1().Jobs(namespace).Create(ctx, jobSpec(m.image, dev, id, q), meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return m.Status(), fmt.Errorf("a test is running or its pods are being cleaned up")
	}
	if err != nil {
		return Status{}, err
	}
	m.mu.Lock()
	m.run = runFromJob(j)
	err = m.saveLocked()
	m.mu.Unlock()
	if err != nil {
		log.Printf("persist traffic test: %v", err)
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
	return m.Status(), nil
}

func (m *Manager) Monitor(ctx context.Context) {
	// A fixed Job name serializes runs across server restarts. Recover a Job
	// created just before the server could write its local result file.
	for {
		err := m.reconcile(ctx)
		if err != nil && ctx.Err() == nil {
			log.Printf("traffic test: %v", err)
		}
		m.mu.Lock()
		active := m.run != nil && m.run.Finished == nil
		m.mu.Unlock()
		var retry <-chan time.Time
		if err != nil || active {
			retry = time.After(4 * time.Second)
		}
		select {
		case <-m.wake:
		case <-ctx.Done():
			return
		case <-retry:
		}
	}
}
func (m *Manager) reconcile(ctx context.Context) error {
	m.operation.Lock()
	defer m.operation.Unlock()
	jobs := m.client.BatchV1().Jobs(namespace)
	j, err := jobs.Get(ctx, jobName, meta.GetOptions{})
	if apierrors.IsNotFound(err) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.run != nil && m.run.Finished == nil {
			now := time.Now().UTC()
			m.run.Finished = &now
			m.run.Phase = "failed"
			m.run.Traffic = &Traffic{Error: "The test Job disappeared before its result was recorded."}
			return m.saveLocked()
		}
		return nil
	}
	if err != nil {
		return err
	}
	if j.Labels["app.kubernetes.io/managed-by"] != "ovn-light" || j.Labels[runLabel] == "" {
		return nil
	}
	m.mu.Lock()
	if m.run == nil || m.run.JobUID != string(j.UID) {
		m.run = runFromJob(j)
	}
	finished := m.run.Finished != nil
	m.mu.Unlock()
	if !finished {
		terminal, complete := false, false
		reason := ""
		for _, c := range j.Status.Conditions {
			if c.Status == core.ConditionTrue && (c.Type == batch.JobComplete || c.Type == batch.JobFailed) {
				terminal, complete = true, c.Type == batch.JobComplete
				reason = strings.TrimSpace(c.Reason + " " + c.Message)
				break
			}
		}
		if !terminal {
			return nil
		}
		result := Traffic{Error: reason}
		pods, err := m.client.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{LabelSelector: "batch.kubernetes.io/controller-uid=" + string(j.UID)})
		if err != nil {
			return err
		}
		for _, p := range pods.Items {
			if !meta.IsControlledBy(&p, j) {
				continue
			}
			for _, c := range p.Status.ContainerStatuses {
				if t := c.State.Terminated; c.Name == "runner" && t != nil {
					var rec Traffic
					if json.Unmarshal([]byte(t.Message), &rec) == nil {
						result = rec
					}
					profile, _ := lookupProfile(m.run.Test)
					legacy := result.Test == "" && result.Case == "" && profile.ID == defaultTest && m.run.Case == crossPod
					if !legacy && (result.Test != m.run.Test || result.Case != m.run.Case) && result.Delivered {
						result.Delivered = false
						result.Error = "The runner returned a different test or case. Update the runner image."
					}
					if !complete || t.ExitCode != 0 || (profile.ID == defaultTest || profile.ID == "iperf-udp") && result.Bytes <= 0 {
						result.Delivered = false
					}
				}
			}
		}
		m.mu.Lock()
		now := time.Now().UTC()
		m.run.Finished = &now
		m.run.Traffic = &result
		m.run.Phase = "completed"
		if !result.Delivered {
			m.run.Phase = "failed"
			if result.Error == "" {
				result.Error = "The runner did not report a completed transfer."
			}
		}
		m.mu.Unlock()
	}
	m.mu.Lock()
	err = m.saveLocked()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if j.DeletionTimestamp != nil {
		return nil
	}
	// Only delete the Job whose result was collected. Its owner references
	// also remove the test endpoints on success, failure or timeout.
	uid := types.UID(j.UID)
	err = jobs.Delete(ctx, jobName, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &uid}, PropagationPolicy: ptr.To(meta.DeletePropagationForeground)})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}
