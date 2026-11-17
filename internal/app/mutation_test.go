// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/trozet/ovn-light/internal/kube"
	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/policy"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clientfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestFirewallRollbackAfterRestart(t *testing.T) {
	a, i := liveFake(t)
	ctx := context.Background()
	i.Kind = "EgressFirewall"
	i.Destination = model.Endpoint{IP: "203.0.113.8"}
	r := a.Client.Dynamic.Resource(kube.Resources["egressfirewalls"]).Namespace(i.Source.Namespace)
	original := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "k8s.ovn.org/v1", "kind": "EgressFirewall", "metadata": map[string]any{"name": "default", "namespace": i.Source.Namespace}, "spec": map[string]any{"egress": []any{map[string]any{"type": "Deny", "to": map[string]any{"cidrSelector": "0.0.0.0/0"}}}}}}
	original, err := r.Create(ctx, original, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// The fake tracker ignores dry-run patch options. Return a copy here so
	// preparation retains the original object, as the API server would.
	a.Client.Dynamic.(*dynamicfake.FakeDynamicClient).PrependReactor("patch", "egressfirewalls", func(action ktesting.Action) (bool, runtime.Object, error) {
		if len(action.(ktesting.PatchActionImpl).GetPatchOptions().DryRun) > 0 {
			return true, original.DeepCopy(), nil
		}
		return false, nil, nil
	})
	snapshot := a.Snapshot()
	snapshot.Inventory.Resources["egressfirewalls"] = []unstructured.Unstructured{*original}
	snapshot.Nodes[0].Flows = strings.ReplaceAll(snapshot.Nodes[0].Flows, "dst=10.244.0.12", "dst=203.0.113.8")
	snapshot.Nodes[0].ACLs[0]["external_ids"] = map[string]any{"k8s.ovn.org/owner-type": "EgressFirewall", "k8s.ovn.org/name": i.Source.Namespace, "rule-index": "0"}
	a.Load(snapshot)
	for _, finding := range a.State().Findings {
		if finding.Destination.IP == i.Destination.IP {
			i.FindingID = finding.ID
		}
	}
	if i.FindingID == "" {
		t.Fatal("missing firewall evidence")
	}
	other := i
	other.Destination.IP = "203.0.113.9"
	if _, err := a.Prepare(ctx, other); err == nil {
		t.Fatal("changed observed destination accepted")
	}
	other = i
	other.Port = 8443
	if _, err := a.Prepare(ctx, other); err == nil {
		t.Fatal("changed observed port accepted")
	}
	p, err := a.Prepare(ctx, i)
	if err != nil {
		t.Fatal(err)
	}
	p, err = a.Apply(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := New("live", a.DataDir, a.Client, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	p, err = restarted.Rollback(ctx, p.ID)
	if err != nil || p.Status != "rolled-back" {
		t.Fatal(p, err)
	}
	restored, err := r.Get(ctx, "default", meta.GetOptions{})
	if err != nil || restored.GetUID() != original.GetUID() || !reflect.DeepEqual(restored.Object["spec"], original.Object["spec"]) {
		t.Fatal(restored, err)
	}
}

func liveFake(t *testing.T) (*App, policy.Intent) {
	t.Helper()
	s := Demo()
	var objects []runtime.Object
	for _, p := range s.Inventory.Pods {
		objects = append(objects, p.DeepCopy())
	}
	for _, n := range s.Inventory.Namespaces {
		objects = append(objects, n.DeepCopy())
	}
	for _, p := range s.Inventory.Policies {
		objects = append(objects, p.DeepCopy())
	}
	core := clientfake.NewClientset(objects...)
	listKinds := map[schema.GroupVersionResource]string{{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}: "NetworkPolicyList"}
	for k, gvr := range kube.Resources {
		listKinds[gvr] = k + "List"
	}
	for k, gvr := range kube.DiagnosticResources {
		listKinds[gvr] = k + "List"
	}
	dynamic := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds)
	dynamic.PrependReactor("create", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		a := action.(ktesting.CreateActionImpl)
		o := a.GetObject().(*unstructured.Unstructured)
		o.SetUID(types.UID("created-" + o.GetName()))
		o.SetResourceVersion("1")
		if len(a.GetCreateOptions().DryRun) > 0 {
			return true, o.DeepCopy(), nil
		}
		return false, nil, nil
	})
	c := &kube.Client{Core: core, Dynamic: dynamic}
	a, e := New("live", t.TempDir(), c, nil, true)
	if e != nil {
		t.Fatal(e)
	}
	a.Load(s)
	var intent policy.Intent
	for _, f := range a.State().Findings {
		if f.CanRecommend {
			intent = policy.Intent{Kind: "NetworkPolicy", Source: f.Source, Destination: f.Destination, Protocol: f.Protocol, Port: f.Destination.Port}
		}
	}
	return a, intent
}

func TestStalePlanCannotApply(t *testing.T) {
	a, i := liveFake(t)
	ctx := context.Background()
	p, e := a.Prepare(ctx, i)
	if e != nil {
		t.Fatal(e)
	}
	pod, e := a.Client.Core.CoreV1().Pods(i.Source.Namespace).Get(ctx, i.Source.Pod, meta.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	pod.Labels["new"] = "label"
	if _, e = a.Client.Core.CoreV1().Pods(pod.Namespace).Update(ctx, pod, meta.UpdateOptions{}); e != nil {
		t.Fatal(e)
	}
	if _, e = a.Apply(ctx, p.ID); e == nil || !strings.Contains(e.Error(), "changed") {
		t.Fatal("stale apply accepted", e)
	}
}
func TestExpiredPlanCannotApply(t *testing.T) {
	a, i := liveFake(t)
	ctx := context.Background()
	p, e := a.Prepare(ctx, i)
	if e != nil {
		t.Fatal(e)
	}
	a.plans[p.ID].ExpiresAt = time.Now().Add(-time.Minute)
	if _, e = a.Apply(ctx, p.ID); e == nil || !strings.Contains(e.Error(), "expired") {
		t.Fatal("expired apply accepted", e)
	}
}
func TestAppliedObjectCanBeRolledBackAfterRestart(t *testing.T) {
	a, i := liveFake(t)
	ctx := context.Background()
	p, e := a.Prepare(ctx, i)
	if e != nil {
		t.Fatal(e)
	}
	p, e = a.Apply(ctx, p.ID)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Applied) != 1 || p.Applied[0].UID == "" {
		t.Fatal("creation was not recorded", p)
	}
	if _, e = a.Apply(ctx, p.ID); e == nil {
		t.Fatal("duplicate apply accepted")
	}
	restarted, e := New("live", a.DataDir, a.Client, nil, true)
	if e != nil {
		t.Fatal(e)
	}
	p, e = restarted.Rollback(ctx, p.ID)
	if e != nil || p.Status != "rolled-back" || len(p.Applied) != 0 {
		t.Fatal(p, e)
	}
}
func TestRollbackPreservesEditedAndReplacedObjects(t *testing.T) {
	for _, change := range []string{"spec", "uid"} {
		t.Run(change, func(t *testing.T) {
			a, i := liveFake(t)
			ctx := context.Background()
			p, e := a.Prepare(ctx, i)
			if e != nil {
				t.Fatal(e)
			}
			p, e = a.Apply(ctx, p.ID)
			if e != nil {
				t.Fatal(e)
			}
			ref := p.Applied[0]
			r := a.Client.Dynamic.Resource(schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}).Namespace(ref.Namespace)
			o, e := r.Get(ctx, ref.Name, meta.GetOptions{})
			if e != nil {
				t.Fatal(e)
			}
			if change == "uid" {
				o.SetUID("replacement")
			} else {
				_ = unstructured.SetNestedField(o.Object, "changed", "spec", "podSelector", "matchLabels", "app")
			}
			if _, e = r.Update(ctx, o, meta.UpdateOptions{}); e != nil {
				t.Fatal(e)
			}
			if _, e = a.Rollback(ctx, p.ID); e == nil {
				t.Fatal("changed object was deleted")
			}
			if _, e = r.Get(ctx, ref.Name, meta.GetOptions{}); e != nil {
				t.Fatal("changed object did not survive", e)
			}
		})
	}
}
