// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"context"
	"reflect"
	"testing"

	"github.com/trozet/ovn-light/internal/policy"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestFirewallPatchAndRollbackPreserveExistingObject(t *testing.T) {
	for _, edit := range []string{"none", "before apply", "after apply", "replacement"} {
		t.Run(edit, func(t *testing.T) {
			ctx := context.Background()
			c := &Client{Dynamic: dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())}
			r := c.Dynamic.Resource(Resources["egressfirewalls"]).Namespace("ns")
			deny := map[string]any{"type": "Deny", "to": map[string]any{"cidrSelector": "0.0.0.0/0"}}
			original := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "k8s.ovn.org/v1", "kind": "EgressFirewall", "metadata": map[string]any{"name": "default", "namespace": "ns", "uid": "original", "resourceVersion": "1", "labels": map[string]any{"owner": "user"}}, "spec": map[string]any{"egress": []any{deny}}}}
			if _, err := r.Create(ctx, original, meta.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			before, _, _ := unstructured.NestedMap(original.Object, "spec")
			change := &policy.FirewallChange{Namespace: "ns", Name: "default", UID: "original", Index: 0, BeforeSpec: before}
			desired := *original.DeepCopy()
			_ = unstructured.SetNestedSlice(desired.Object, []any{map[string]any{"type": "Allow", "to": map[string]any{"cidrSelector": "203.0.113.8/32"}}, deny}, "spec", "egress")
			if edit == "before apply" {
				changed := original.DeepCopy()
				changed.Object["spec"] = map[string]any{"egress": []any{}}
				_, _ = r.Update(ctx, changed, meta.UpdateOptions{})
				if _, err := c.PatchFirewall(ctx, change, desired, false); err == nil {
					t.Fatal("atomic spec check ignored")
				}
				return
			}
			applied, err := c.PatchFirewall(ctx, change, desired, false)
			if err != nil {
				t.Fatal(err)
			}
			ref := policy.ObjectRef{Kind: "EgressFirewall", Namespace: "ns", Name: "default", UID: "original", SpecHash: SpecHash(applied)}
			if edit == "after apply" {
				applied.Object["spec"].(map[string]any)["egress"].([]any)[0].(map[string]any)["type"] = "Deny"
			}
			if edit == "replacement" {
				applied.SetUID("replacement")
			}
			if edit != "none" {
				if _, err = r.Update(ctx, applied, meta.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			err = c.RollbackFirewall(ctx, change, ref)
			if edit != "none" {
				if err == nil {
					t.Fatal("modified firewall was rolled back")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			restored, err := r.Get(ctx, "default", meta.GetOptions{})
			if err != nil || restored.GetUID() != original.GetUID() || !reflect.DeepEqual(restored.Object["spec"], original.Object["spec"]) || !reflect.DeepEqual(restored.GetLabels(), original.GetLabels()) {
				t.Fatal("firewall was not preserved", restored, err)
			}
		})
	}
}
