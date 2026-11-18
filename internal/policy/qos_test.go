// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"reflect"
	"testing"

	"github.com/trozet/ovn-light/internal/model"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestQoSReviewPreservesScope(t *testing.T) {
	original := unstructured.Unstructured{Object: map[string]any{"apiVersion": "k8s.ovn.org/v1alpha1", "kind": "NetworkQoS", "metadata": map[string]any{"name": "q", "namespace": "app", "uid": "uid"}, "spec": map[string]any{"podSelector": map[string]any{"matchLabels": map[string]any{"app": "a"}}, "priority": int64(20), "egress": []any{map[string]any{"dscp": int64(10)}, map[string]any{"dscp": int64(20)}}}}}
	inv := model.Inventory{Resources: map[string][]unstructured.Unstructured{"networkqoses": {original}}}
	before := original.DeepCopy()
	req := QoSRequest{Kind: "NetworkQoS", Namespace: "app", Name: "q", UID: "uid", Rule: 1, DSCP: 40}
	p, err := BuildQoS(inv, req, "test")
	if err != nil {
		t.Fatal(err)
	}
	rules, _, _ := unstructured.NestedSlice(p.Objects[0].Object, "spec", "egress")
	if rules[0].(map[string]any)["dscp"] != int64(10) || rules[1].(map[string]any)["dscp"] != int64(40) || !reflect.DeepEqual(original.Object, before.Object) {
		t.Fatal("scope or input was mutated")
	}
	if !reflect.DeepEqual(p.QoSChange.BeforeSpec, before.Object["spec"]) {
		t.Fatal("rollback spec incorrect")
	}
	req.UID = "replacement"
	if _, err = BuildQoS(inv, req, "test"); err == nil {
		t.Fatal("stale UID accepted")
	}
	req.UID = "uid"
	req.DSCP = 64
	if _, err = BuildQoS(inv, req, "test"); err == nil {
		t.Fatal("DSCP range accepted")
	}
	req.DSCP = 0
	v := int64(1)
	req.Burst = &v
	if _, err = BuildQoS(inv, req, "test"); err == nil {
		t.Fatal("burst without rate accepted")
	}
}
