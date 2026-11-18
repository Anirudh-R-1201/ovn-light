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

func TestQoSPatchRollbackAndConcurrentChanges(t *testing.T) {
	for _, kind := range []string{"NetworkQoS", "EgressQoS"} {
		for _, edit := range []string{"none", "before", "after", "replacement"} {
			t.Run(kind+"/"+edit, func(t *testing.T) {
				ctx := context.Background()
				c := Client{Dynamic: dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())}
				gvr, _ := qosResource(kind)
				r := c.Dynamic.Resource(gvr).Namespace("app")
				original := &unstructured.Unstructured{Object: map[string]any{"apiVersion": gvr.Group + "/" + gvr.Version, "kind": kind, "metadata": map[string]any{"name": "q", "namespace": "app", "uid": "uid", "resourceVersion": "1", "labels": map[string]any{"owner": "user"}}, "spec": map[string]any{"egress": []any{map[string]any{"dscp": int64(10)}}}}}
				if _, err := r.Create(ctx, original, meta.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
				before, _, _ := unstructured.NestedMap(original.Object, "spec")
				change := &policy.QoSChange{Kind: kind, Namespace: "app", Name: "q", UID: "uid", BeforeSpec: before}
				desired := original.DeepCopy()
				desired.Object["spec"] = map[string]any{"egress": []any{map[string]any{"dscp": int64(20)}}}
				if edit == "before" {
					current := original.DeepCopy()
					current.Object["spec"] = map[string]any{"egress": []any{map[string]any{"dscp": int64(30)}}}
					if _, err := r.Update(ctx, current, meta.UpdateOptions{}); err != nil {
						t.Fatal(err)
					}
					if _, err := c.PatchQoS(ctx, change, *desired, false); err == nil {
						t.Fatal("concurrent spec update overwritten")
					}
					return
				}
				applied, err := c.PatchQoS(ctx, change, *desired, false)
				if err != nil {
					t.Fatal(err)
				}
				ref := policy.ObjectRef{Kind: kind, Namespace: "app", Name: "q", UID: "uid", SpecHash: SpecHash(applied)}
				if edit == "after" {
					applied.Object["spec"] = map[string]any{"egress": []any{map[string]any{"dscp": int64(30)}}}
				}
				if edit == "replacement" {
					applied.SetUID("replacement")
				}
				if edit != "none" {
					if _, err = r.Update(ctx, applied, meta.UpdateOptions{}); err != nil {
						t.Fatal(err)
					}
				}
				err = c.RollbackQoS(ctx, change, ref)
				if edit != "none" {
					if err == nil {
						t.Fatal("changed QoS overwritten by rollback")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				current, err := r.Get(ctx, "q", meta.GetOptions{})
				if err != nil || current.GetUID() != original.GetUID() || !reflect.DeepEqual(current.Object["spec"], original.Object["spec"]) || !reflect.DeepEqual(current.GetLabels(), original.GetLabels()) {
					t.Fatal("original resource not preserved", err, current)
				}
			})
		}
	}
}
