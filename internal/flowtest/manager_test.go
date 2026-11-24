// SPDX-License-Identifier: Apache-2.0
package flowtest

import (
	"context"
	"testing"

	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	manager, err := New(client, "test-runner", "", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Request{{"a", "a", "default"}, {"a", "b", "blue"}, {"a", "unknown", "default"}} {
		if _, err := manager.Start(ctx, bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	req := Request{"a", "b", "default"}
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
			job := jobSpec("image", "", "test-run", Request{"a", "b", "default"})
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
			manager, err := New(client, "image", "", store)
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
			restarted, err := New(client, "image", "", store)
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
