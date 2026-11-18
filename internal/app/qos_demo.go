// SPDX-License-Identifier: Apache-2.0
package app

import (
	"github.com/trozet/ovn-light/internal/model"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func demoQoS(s *model.Snapshot) {
	s.Inventory.Resources["networkqoses"] = []unstructured.Unstructured{{Object: map[string]any{"apiVersion": "k8s.ovn.org/v1alpha1", "kind": "NetworkQoS", "metadata": map[string]any{"namespace": "storefront", "name": "web-egress", "uid": "demo-qos"}, "spec": map[string]any{"priority": int64(50), "egress": []any{map[string]any{"dscp": int64(20), "bandwidth": map[string]any{"rate": int64(10000), "burst": int64(1000)}}}}, "status": map[string]any{"status": "DEMO"}}}}
	s.Inventory.Resources["egressqoses"] = []unstructured.Unstructured{}
	s.Nodes[0].QoS = model.QoSEvidence{At: s.CapturedAt, Rules: []model.Row{{"_uuid": "demo-qos-row", "priority": int64(10500), "direction": "to-lport", "match": "ip4 && ip4.src == $demo_web", "action": map[string]any{"dscp": int64(20)}, "bandwidth": map[string]any{"rate": int64(10000), "burst": int64(1000)}, "external_ids": map[string]any{"k8s.ovn.org/owner-type": "NetworkQoS", "k8s.ovn.org/name": "storefront:web-egress", "rule-index": "0"}}}, Switches: []model.Row{{"name": "kind-worker", "qos_rules": "demo-qos-row"}}}
}
