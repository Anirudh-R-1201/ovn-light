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
}
type Status struct {
	Enabled bool `json:"enabled"`
	Run     *Run `json:"run,omitempty"`
}
type Manager struct {
	client              kubernetes.Interface
	image, device, file string
	wake                chan struct{}
	operation           sync.Mutex
	mu                  sync.Mutex
	run                 *Run
}

func New(client kubernetes.Interface, image, device, dir string) (*Manager, error) {
	if device != "" && (len(validation.IsQualifiedName(device)) > 0 || !strings.Contains(device, "/") || strings.HasPrefix(device, "kubernetes.io/")) {
		return nil, fmt.Errorf("invalid traffic test device resource")
	}
	m := &Manager{wake: make(chan struct{}, 1), client: client, image: image, device: device, file: filepath.Join(dir, "traffic-test.json")}
	raw, err := os.ReadFile(m.file)
	if err == nil {
		err = json.Unmarshal(raw, &m.run)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
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
	labels := map[string]string{runLabel: id, "app.kubernetes.io/managed-by": "ovn-light"}
	runner := core.Container{
		Name: "runner", Image: image, ImagePullPolicy: core.PullIfNotPresent,
		Env: []core.EnvVar{
			{Name: "RUN_ID", Value: id},
			{Name: "TEST_IMAGE", Value: image},
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
	return &Run{ID: j.Labels[runLabel], JobUID: string(j.UID), Network: "default", Phase: "running", Source: Endpoint{Node: src}, Destination: Endpoint{Node: dst}, Started: j.CreationTimestamp.Time, Nodes: []NodeEvidence{{Node: src, State: "unknown"}, {Node: dst, State: "unknown"}}}
}
func (m *Manager) Start(ctx context.Context, q Request) (Status, error) {
	if m == nil {
		return Status{}, fmt.Errorf("traffic tests are disabled")
	}
	if q.Network != "default" || q.SourceNode == q.DestinationNode {
		return Status{}, fmt.Errorf("choose two distinct nodes on the default network")
	}
	m.operation.Lock()
	defer m.operation.Unlock()
	if s := m.Status(); s.Run != nil && s.Run.Finished == nil {
		return s, fmt.Errorf("a traffic test is already running")
	}
	for _, name := range []string{q.SourceNode, q.DestinationNode} {
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return Status{}, fmt.Errorf("invalid node name")
		}
		n, err := m.client.CoreV1().Nodes().Get(ctx, name, meta.GetOptions{})
		if err != nil {
			return Status{}, err
		}
		ready := false
		for _, c := range n.Status.Conditions {
			if c.Type == core.NodeReady && c.Status == core.ConditionTrue {
				ready = true
			}
		}
		if !ready || n.Labels["kubernetes.io/os"] != "linux" || n.Spec.Unschedulable {
			return Status{}, fmt.Errorf("%s must be a schedulable Ready Linux node", name)
		}
	}
	id := strings.ToLower(rand.Text())
	j, err := m.client.BatchV1().Jobs(namespace).Create(ctx, jobSpec(m.image, m.device, id, q), meta.CreateOptions{})
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
					if !complete || t.ExitCode != 0 || result.Bytes <= 0 {
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
