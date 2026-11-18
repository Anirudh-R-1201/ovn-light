// SPDX-License-Identifier: Apache-2.0
package qos

import (
	"testing"
	"time"

	"github.com/trozet/ovn-light/internal/model"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestQoSNetworkScopeAndProgramming(t *testing.T) {
	s := model.Snapshot{CapturedAt: time.Now(), Inventory: model.Inventory{Resources: map[string][]unstructured.Unstructured{}, Pods: []core.Pod{{ObjectMeta: meta.ObjectMeta{Name: "client", Namespace: "app", UID: "client", Labels: map[string]string{"app": "client"}, Annotations: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":["10.0.0.2/24"],"role":"primary"},"app/blue":{"ip_addresses":["10.0.0.2/24"],"role":"secondary"}}`}}, Spec: core.PodSpec{NodeName: "node"}, Status: core.PodStatus{Phase: core.PodRunning}}}}}
	s.Inventory.Resources["networkqoses"] = []unstructured.Unstructured{{Object: map[string]any{"kind": "NetworkQoS", "metadata": map[string]any{"name": "q", "namespace": "app", "uid": "q"}, "spec": map[string]any{"egress": []any{map[string]any{"dscp": int64(10)}, map[string]any{"dscp": int64(20), "bandwidth": map[string]any{"rate": int64(500)}}}}}}}
	s.Nodes = []model.NodeSnapshot{{Name: "node", QoS: model.QoSEvidence{At: s.CapturedAt, Rules: []model.Row{{"_uuid": "row", "priority": int64(10001), "action": map[string]any{"dscp": int64(20)}, "bandwidth": map[string]any{"rate": int64(500)}, "external_ids": map[string]any{"k8s.ovn.org/owner-type": "NetworkQoS", "k8s.ovn.org/name": "app:q", "rule-index": "1"}}}, Switches: []model.Row{{"name": "node", "qos_rules": "row"}}}}}
	r := Analyze(s)
	if len(r.Policies) != 1 {
		t.Fatal(r)
	}
	p := r.Policies[0]
	if p.TargetCount != 1 || p.Targets[0].Network != "default" {
		t.Fatal("overlapping secondary IP selected", p.Targets)
	}
	if len(p.Programs) != 1 || p.Programs[0].Rule != 1 || p.Programs[0].State != "OVN row observed" {
		t.Fatal(p.Programs)
	}
	s.Nodes[0].QoS.Rules[0]["action"] = map[string]any{"dscp": int64(30)}
	r = Analyze(s)
	if r.Policies[0].Programs[0].State != "Desired / programmed values differ" {
		t.Fatal(r)
	}
	filtered := Filter(r, Options{Network: "blue"})
	if len(filtered.Policies) != 0 {
		t.Fatal(filtered)
	}
	if r.Capabilities["egressqoses"] != "API not discovered" {
		t.Fatal(r.Capabilities)
	}
}

func TestExplicitNADNetworkSelection(t *testing.T) {
	inv := model.Inventory{Namespaces: []core.Namespace{{ObjectMeta: meta.ObjectMeta{Name: "app", Labels: map[string]string{"team": "blue"}}}}, Resources: map[string][]unstructured.Unstructured{"network-attachment-definitions": {{Object: map[string]any{"metadata": map[string]any{"namespace": "app", "name": "blue", "labels": map[string]any{"network": "blue"}}, "spec": map[string]any{"config": `{"type":"ovn-k8s-cni-overlay","name":"blue","role":"secondary","topology":"layer3","netAttachDefName":"app/blue"}`}}}}}}
	selection := map[string]any{"networkSelectors": []any{map[string]any{"networkSelectionType": "NetworkAttachmentDefinitions", "networkAttachmentDefinitionSelector": map[string]any{"namespaceSelector": map[string]any{"matchLabels": map[string]any{"team": "blue"}}, "networkSelector": map[string]any{"matchLabels": map[string]any{"network": "blue"}}}}}}
	got := networks(inv, selection)
	if len(got) != 1 || got[0] != "network:blue" {
		t.Fatal("secondary network selection", got)
	}
	inv.Namespaces[0].Labels["team"] = "red"
	if got = networks(inv, selection); len(got) != 0 {
		t.Fatal("unresolved selector fell back to a network", got)
	}
}
