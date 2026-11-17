// SPDX-License-Identifier: Apache-2.0
package app

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/trozet/ovn-light/internal/model"
	core "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// Demo is deliberately synthetic and is always served with writes disabled.
func Demo() model.Snapshot {
	now := time.Now().UTC()
	s := model.Snapshot{Version: 1, CapturedAt: now}
	inv := model.Inventory{Resources: map[string][]unstructured.Unstructured{"clusternetworkconnects": {}}}
	for _, ns := range []string{"storefront", "payments", "analytics"} {
		inv.Namespaces = append(inv.Namespaces, core.Namespace{ObjectMeta: meta.ObjectMeta{Name: ns, UID: types.UID(ns), Labels: map[string]string{"kubernetes.io/metadata.name": ns}}})
	}
	for _, p := range []struct{ ns, name, ip, network string }{{"storefront", "web-7b49", "10.244.0.8", "default"}, {"payments", "api-6dc2", "10.244.0.12", "default"}, {"analytics", "worker-a82f", "10.40.0.8", "analytics/data"}, {"analytics", "warehouse-18ca", "10.40.0.12", "analytics/data"}} {
		annotation := fmt.Sprintf(`{"%s":{"ip_addresses":["%s/24"],"mac_address":"0a:58:0a:28:00:08","role":"primary"}}`, p.network, p.ip)
		inv.Pods = append(inv.Pods, core.Pod{ObjectMeta: meta.ObjectMeta{Namespace: p.ns, Name: p.name, UID: types.UID(p.name), Labels: map[string]string{"app": p.name}, Annotations: map[string]string{"k8s.ovn.org/pod-networks": annotation}}, Spec: core.PodSpec{NodeName: "kind-worker", Containers: []core.Container{{Name: "app", Image: "example"}}}, Status: core.PodStatus{Phase: core.PodRunning, PodIPs: []core.PodIP{{IP: p.ip}}}})
	}
	for _, ns := range []string{"payments", "analytics"} {
		inv.Policies = append(inv.Policies, netv1.NetworkPolicy{ObjectMeta: meta.ObjectMeta{Namespace: ns, Name: "default-deny-ingress", UID: types.UID(ns + "-deny")}, Spec: netv1.NetworkPolicySpec{PodSelector: meta.LabelSelector{}, PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress}}})
	}
	for _, n := range []struct{ ns, name, subnet string }{{"analytics", "data", "10.40.0.0/24"}, {"storefront", "frontend", "10.50.0.0/24"}} {
		inv.Resources["userdefinednetworks"] = append(inv.Resources["userdefinednetworks"], unstructured.Unstructured{Object: map[string]any{"apiVersion": "k8s.ovn.org/v1", "kind": "UserDefinedNetwork", "metadata": map[string]any{"name": n.name, "namespace": n.ns}, "spec": map[string]any{"topology": "Layer2", "layer2": map[string]any{"role": "Primary", "subnets": []any{n.subnet}}}}})
	}
	s.Inventory = inv
	n := model.NodeSnapshot{Name: "kind-worker", CapturedAt: now, Datapath: "system@ovs-system", Ports: "system@ovs-system:\n  port 4: web0\n  port 7: worker0\n", Interfaces: []model.Row{{"name": "web0", "external_ids": map[string]any{"iface-id": "storefront_web-7b49", "iface-id-ver": "web-7b49"}}, {"name": "worker0", "external_ids": map[string]any{"iface-id": "analytics.data_analytics_worker-a82f", "iface-id-ver": "worker-a82f"}}}, Detraces: map[string]string{}}
	n.Flows = `ufid:11111111-1111-4111-8111-111111111111, recirc_id(0),in_port(4),eth_type(0x0800),ipv4(src=10.244.0.8,dst=10.244.0.12,proto=6),tcp(src=41912,dst=8080), packets:41, bytes:2460, actions:ct(zone=64000),recirc(0x2a)
ufid:22222222-2222-4222-8222-222222222222, recirc_id(0x2a),in_port(4),eth_type(0x0800),ipv4(src=10.244.0.8,dst=10.244.0.12,proto=6),tcp(src=41912,dst=8080), packets:41, bytes:2460, actions:drop
ufid:33333333-3333-4333-8333-333333333333, recirc_id(0),in_port(7),eth_type(0x0800),ipv4(src=10.40.0.8,dst=10.40.0.12,proto=6),tcp(src=0/0,dst=0/0), packets:125, bytes:7500, actions:ct(zone=64001),recirc(0x3b)
ufid:44444444-4444-4444-8444-444444444444, recirc_id(0x3b),in_port(7),eth_type(0x0800),ipv4(src=10.40.0.8,dst=10.40.0.12,proto=6),tcp(src=0/0,dst=0/0), packets:125, bytes:7500, actions:drop`
	for j, namespace := range []string{"payments", "analytics"} {
		lf := fmt.Sprintf("%08x-0000-4000-8000-000000000000", 0xaabbcc01+j)
		acl := fmt.Sprintf("%08x-0000-4000-8000-000000000000", 0xdead0001+j)
		id := []string{"22222222-2222-4222-8222-222222222222", "44444444-4444-4444-8444-444444444444"}[j]
		n.Detraces[id] = fmt.Sprintf("table_id=45, cookie=0x%s, priority=100, actions=drop", lf[:8])
		n.LogicalFlows = append(n.LogicalFlows, model.Row{"_uuid": lf, "external_ids": map[string]any{"stage-hint": acl[:8]}})
		n.ACLs = append(n.ACLs, model.Row{"_uuid": acl, "action": "drop", "match": "outport == @" + namespace + "_default_deny && ip", "external_ids": map[string]any{"k8s.ovn.org/owner-type": "NetpolNamespace", "k8s.ovn.org/name": namespace, "direction": "Ingress"}})
	}
	s.Nodes = []model.NodeSnapshot{n}
	remote := inv.Pods[1].DeepCopy()
	remote.Labels = map[string]string{"app": "catalog"}
	remote.Name = "catalog-9dd4"
	remote.UID = "catalog-9dd4"
	remote.Spec.NodeName = "kind-worker2"
	remote.Annotations["k8s.ovn.org/pod-networks"] = `{"default":{"ip_addresses":["10.244.1.9/24"],"mac_address":"0a:58:0a:f4:01:09","role":"primary"}}`
	remote.Status.PodIPs = []core.PodIP{{IP: "10.244.1.9"}}
	s.Inventory.Pods = append(s.Inventory.Pods, *remote)
	s.Nodes[0].Flows += "\nufid:forward-a,recirc_id(0),in_port(4),ipv4(src=10.244.0.8,dst=10.244.1.9,proto=6),tcp(dst=8080),packets:1000,bytes:1250000,actions:9"
	s.Nodes[0].Collection.FlowComplete = true
	s.Nodes = append(s.Nodes, model.NodeSnapshot{Name: "kind-worker2", CapturedAt: now, Datapath: "system@ovs-system", Collection: model.CollectionStats{FlowComplete: true}, Ports: "system@ovs-system:\n  port 8: catalog0\n  port 9: geneve0\n", Interfaces: []model.Row{{"name": "catalog0", "external_ids": map[string]any{"iface-id": "payments_catalog-9dd4", "iface-id-ver": "catalog-9dd4"}}}, Flows: "ufid:forward-b,recirc_id(0),in_port(9),ipv4(src=10.244.0.8,dst=10.244.1.9,proto=6),tcp(dst=8080),packets:980,bytes:1225000,actions:8"})

	s.Nodes[0].Offload = model.OffloadEvidence{CapturedAt: now, ConfigKnown: true, Enabled: true, Provider: "doca", Version: "synthetic", Config: map[string]string{"hw-offload": "true", "doca-init": "true"}, CTSupported: true, CTComplete: true, Conntrack: "tcp,orig=(src=10.244.0.8,dst=10.244.0.12,sport=41912,dport=8080),reply=(src=10.244.0.12,dst=10.244.0.8,sport=8080,dport=41912),zone=64000,protoinfo=(state=ESTABLISHED),orig_offloaded:yes,reply_offloaded:yes", Stats: "Synthetic provider counters: 12 inserted offloads, 1 CT connection"}
	s.Nodes[1].Offload = model.OffloadEvidence{CapturedAt: now, ConfigKnown: true, Enabled: false, Version: "synthetic"}
	s.Nodes[0].Flows = strings.ReplaceAll(s.Nodes[0].Flows, "actions:", "offloaded:yes,dp:doca,actions:")
	s.Nodes[0].Flows = strings.Replace(s.Nodes[0].Flows, "packets:41, bytes:2460, offloaded:yes,dp:doca,actions:drop", "packets:41, bytes:2460, offloaded:no,dp:ovs,actions:drop, dp-offload-info:'Synthetic example: action is unsupported'", 1)
	s.Nodes[0].Flows = strings.Replace(s.Nodes[0].Flows, "packets:1000,bytes:1250000,", "packets:1000,bytes:1250000,partial_offload_packets:120,partial_offload_bytes:150000,", 1)
	demoRouting(&s)
	return s
}

// DemoBaseline supplies a second synthetic counter reading, so the demo can
// demonstrate rates without presenting cumulative counters as live traffic.
func DemoBaseline(s model.Snapshot) model.Snapshot {
	s.Nodes = append([]model.NodeSnapshot{}, s.Nodes...)
	s.CapturedAt = s.CapturedAt.Add(-30 * time.Second)
	counts := regexp.MustCompile(`(packets:|bytes:)([0-9]+)`)
	for i := range s.Nodes {
		s.Nodes[i].CapturedAt = s.CapturedAt
		s.Nodes[i].Offload.CapturedAt = s.CapturedAt
		s.Nodes[i].Flows = counts.ReplaceAllStringFunc(s.Nodes[i].Flows, func(v string) string {
			p := counts.FindStringSubmatch(v)
			n, _ := strconv.ParseUint(p[2], 10, 64)
			return p[1] + strconv.FormatUint(n/2, 10)
		})
	}
	return s
}
