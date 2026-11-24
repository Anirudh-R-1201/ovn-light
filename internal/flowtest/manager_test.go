// SPDX-License-Identifier: Apache-2.0
package flowtest

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

func TestStartCrossNode(t *testing.T) {
	ctx := context.Background()
	node := func(name string) *core.Node {
		return &core.Node{
			ObjectMeta: meta.ObjectMeta{Name: name, Labels: map[string]string{"kubernetes.io/os": "linux"}},
			Status:     core.NodeStatus{Conditions: []core.NodeCondition{{Type: core.NodeReady, Status: core.ConditionTrue}}},
		}
	}
	client := fake.NewClientset(node("a"), node("b"))
	manager, err := New(client, "test-runner", "", "", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Request{{SourceNode: "a", DestinationNode: "a", Network: "default"}, {SourceNode: "a", DestinationNode: "b", Network: "blue"}, {SourceNode: "a", DestinationNode: "unknown", Network: "default"}} {
		if _, err := manager.Start(ctx, bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	req := Request{SourceNode: "a", DestinationNode: "b", Network: "default"}
	status, err := manager.Start(ctx, req)
	if err != nil || status.Run == nil || status.Run.Source.Node != "a" || status.Run.Destination.Node != "b" {
		t.Fatalf("start returned %+v, %v", status, err)
	}
	if _, err := manager.Start(ctx, req); err == nil {
		t.Fatal("started a second run")
	}
	j, err := client.BatchV1().Jobs(namespace).Get(ctx, jobName, meta.GetOptions{})
	if err != nil || j.Labels[runLabel] != status.Run.ID || j.Spec.ActiveDeadlineSeconds == nil || *j.Spec.BackoffLimit != 0 {
		t.Fatalf("unexpected Job: %+v, %v", j, err)
	}
}

func TestRecoverJobAndPersistResult(t *testing.T) {
	for _, state := range []batch.JobConditionType{batch.JobComplete, batch.JobFailed} {
		t.Run(string(state), func(t *testing.T) {
			ctx := context.Background()
			job := jobSpec("image", "", "test-run", Request{SourceNode: "a", DestinationNode: "b", Network: "default"})
			job.UID, job.Namespace, job.CreationTimestamp = "job-uid", namespace, meta.Now()
			job.Status.Conditions = []batch.JobCondition{{Type: state, Status: core.ConditionTrue}}
			runner := &core.Pod{
				ObjectMeta: meta.ObjectMeta{Name: "runner", Namespace: namespace,
					Labels:          map[string]string{"batch.kubernetes.io/controller-uid": "job-uid"},
					OwnerReferences: []meta.OwnerReference{{Kind: "Job", Name: job.Name, UID: job.UID, Controller: ptr.To(true)}},
				},
				Status: core.PodStatus{ContainerStatuses: []core.ContainerStatus{{Name: "runner", State: core.ContainerState{
					Terminated: &core.ContainerStateTerminated{Message: `{"delivered":true,"bytes":1024}`},
				}}}},
			}
			store := t.TempDir()
			client := fake.NewClientset(job, runner)
			manager, err := New(client, "image", "", "", store)
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.reconcile(ctx); err != nil {
				t.Fatal(err)
			}
			_, err = client.BatchV1().Jobs(namespace).Get(ctx, job.Name, meta.GetOptions{})
			if !apierrors.IsNotFound(err) {
				t.Fatalf("completed Job cleanup: %v", err)
			}
			restarted, err := New(client, "image", "", "", store)
			if err != nil {
				t.Fatal(err)
			}
			result := restarted.Status().Run
			if result == nil || result.ID != "test-run" || result.Finished == nil || result.Traffic == nil || result.Traffic.Delivered != (state == batch.JobComplete) {
				t.Fatalf("persisted result: %+v", result)
			}
		})
	}
}

func TestCatalogPlacementAndDeviceAvailability(t *testing.T) {
	node := func(name string, ready bool, devices string) *core.Node {
		n := &core.Node{ObjectMeta: meta.ObjectMeta{Name: name, Labels: map[string]string{core.LabelOSStable: "linux"}}}
		if ready {
			n.Status.Conditions = []core.NodeCondition{{Type: core.NodeReady, Status: core.ConditionTrue}}
		}
		n.Status.Allocatable = core.ResourceList{"test.example/rdma": resource.MustParse(devices)}
		return n
	}
	readyNodes := func() *fake.Clientset {
		return fake.NewClientset(node("worker-b", true, "1"), node("worker-a", true, "2"), node("offline", false, "0"))
	}
	ctx := context.Background()
	for _, tt := range []struct {
		name, test, scenario, src, dst, rdma string
		ok                                   bool
	}{
		{"same node service", "http", localService, "worker-b", "worker-b", "", true},
		{"different nodes selected", "iperf-udp", crossService, "worker-b", "worker-a", "", true},
		{"same node case mismatch", "http", localService, "worker-b", "worker-a", "", false},
		{"different node case mismatch", "simple", crossPod, "worker-b", "worker-b", "", false},
		{"unimplemented case", "http", "POD_TO_EXTERNAL", "worker-b", "worker-a", "", false},
		{"netperf service data port", "netperf-tcp-rr", crossService, "worker-b", "worker-a", "", true},
		{"unrecognized type", "invalid", localPod, "worker-b", "worker-b", "", false},
		{"RDMA unavailable", "ib-read-bw", crossPod, "worker-b", "worker-a", "", false},
		{"RDMA pair", "ib-read-bw", crossPod, "worker-b", "worker-a", "test.example/rdma", true},
		{"RDMA local devices exhausted", "ib-write-bw", localPod, "worker-b", "worker-b", "test.example/rdma", false},
		{"RDMA local pair", "ib-send-bw", localPod, "worker-a", "worker-a", "test.example/rdma", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := readyNodes()
			m, err := New(client, "runner", "", tt.rdma, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			opts, err := m.Options(ctx)
			if err != nil || len(opts.Nodes) != 2 || opts.Nodes[0].Name != "worker-a" || len(opts.Profiles) != 9 || len(opts.Cases) != 4 {
				t.Fatalf("catalog %+v, %v", opts, err)
			}
			out, err := m.Start(ctx, Request{Test: tt.test, Case: tt.scenario, SourceNode: tt.src, DestinationNode: tt.dst, Network: "default"})
			if (err == nil) != tt.ok {
				t.Fatalf("start: %v", err)
			}
			if !tt.ok {
				return
			}
			j, err := client.BatchV1().Jobs(namespace).Get(ctx, jobName, meta.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			env := map[string]string{}
			for _, v := range j.Spec.Template.Spec.Containers[0].Env {
				env[v.Name] = v.Value
			}
			if env["TEST_TYPE"] != tt.test || env["TEST_CASE"] != tt.scenario || env["SOURCE_NODE"] != tt.src || env["DESTINATION_NODE"] != tt.dst || env["DEVICE_RESOURCE"] != tt.rdma || out.Run.Test != tt.test || out.Run.Case != tt.scenario {
				t.Fatal(out.Run, env)
			}
			if (len(out.Run.Nodes) == 1) != (tt.src == tt.dst) {
				t.Fatal(out.Run.Nodes)
			}
		})
	}
}

func TestRestoreLegacyRun(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "traffic-test.json"), []byte(`{"id":"old","jobUID":"job-1","source":{"node":"one"},"destination":{"node":"two"},"phase":"running"}`), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := New(fake.NewClientset(), "runner", "", "", dir)
	if err != nil {
		t.Fatal(err)
	}
	r := m.Status().Run
	if r.Test != defaultTest || r.Case != crossPod || r.ID != "old" {
		t.Fatal(r)
	}
}

func TestTrafficHistoryRetentionAndRestart(t *testing.T) {
	dir := t.TempDir()
	m, err := New(fake.NewClientset(), "image", "", "", dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < historyLimit+3; i++ {
		now := time.Now().UTC()
		m.replaceLocked(&Run{ID: strconv.Itoa(i), Finished: &now, Phase: "completed", Nodes: []NodeEvidence{{Node: "node-a", Flows: []ObservedFlow{{Direction: "client → server"}}}}})
	}
	if err = m.saveLocked(); err != nil {
		t.Fatal(err)
	}
	restored, err := New(fake.NewClientset(), "image", "", "", dir)
	if err != nil {
		t.Fatal(err)
	}
	summaries := restored.List()
	if len(summaries) != historyLimit || summaries[0].ID != strconv.Itoa(historyLimit+2) || summaries[historyLimit-1].ID != "3" || summaries[0].Nodes != nil || restored.Lookup("2") != nil {
		t.Fatal(summaries)
	}
	detail := restored.Lookup("3")
	if len(detail.Nodes[0].Flows) != 1 {
		t.Fatal(detail)
	}
	detail.Nodes[0].Flows = nil
	if len(restored.Lookup("3").Nodes[0].Flows) != 1 {
		t.Fatal("result changed through caller")
	}
}

func TestEvaluatorSettings(t *testing.T) {
	m, err := New(fake.NewClientset(), "image", "", "", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []Request{
		{Test: "http", TestSettings: TestSettings{MinimumGbps: ptr.To(15.0)}},
		{Test: "iperf-tcp", TestSettings: TestSettings{MinimumGbps: ptr.To(-1.0)}},
		{Test: "iperf-tcp", TestSettings: TestSettings{SenderMbps: 15000}},
	} {
		if _, err := m.Start(context.Background(), q); err == nil || strings.Contains(err.Error(), "network") {
			t.Fatalf("invalid settings accepted: %v", err)
		}
	}
	q := Request{Test: "iperf-tcp", TestSettings: TestSettings{MinimumGbps: ptr.To(15.0), SenderMbps: 20000}}
	j := jobSpec("image", "", "check", q)
	run := runFromJob(j)
	if *run.MinimumGbps != 15 || run.SenderMbps != 20000 {
		t.Fatal(run)
	}
}
