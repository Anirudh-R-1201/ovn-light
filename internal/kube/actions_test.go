// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"context"
	"testing"

	"github.com/trozet/ovn-light/internal/policy"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestMultiPolicyRollbackGuardsNetworkAnnotation(t *testing.T) {
	o := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "k8s.cni.cncf.io/v1beta1", "kind": "MultiNetworkPolicy", "metadata": map[string]any{"name": "allow", "namespace": "ns", "uid": "id", "resourceVersion": "1", "annotations": map[string]any{"ovn-light.io/plan": "plan", policy.PolicyForAnnotation: "ns/blue"}}, "spec": map[string]any{"podSelector": map[string]any{}}}}
	c := &Client{Dynamic: dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())}
	ref := policy.ObjectRef{Kind: o.GetKind(), Name: o.GetName(), Namespace: o.GetNamespace(), UID: "id", SpecHash: SpecHash(o)}
	ctx := context.Background()
	if _, e := c.Create(ctx, *o, false); e != nil {
		t.Fatal(e)
	}
	r := c.Dynamic.Resource(Resources["multi-networkpolicies"]).Namespace("ns")
	o.SetAnnotations(map[string]string{"ovn-light.io/plan": "plan", policy.PolicyForAnnotation: "ns/red"})
	if _, e := r.Update(ctx, o, meta.UpdateOptions{}); e != nil {
		t.Fatal(e)
	}
	if e := c.Rollback(ctx, ref, "plan"); e == nil {
		t.Fatal("retargeted policy was deleted")
	}
	if _, e := r.Get(ctx, "allow", meta.GetOptions{}); e != nil {
		t.Fatal(e)
	}
}

func TestProbeRefusesUnspecifiedOrBroadPortBeforeExec(t *testing.T) {
	c := &Client{}
	for _, i := range []policy.Intent{{Protocol: "TCP", AllPorts: true}, {Protocol: "TCP", Port: 0}, {Protocol: "TCP", Port: 65536}, {Protocol: "TCP", Port: -1}} {
		if _, err := c.Probe(context.Background(), i); err == nil {
			t.Fatal("invalid probe accepted", i)
		}
	}
}
