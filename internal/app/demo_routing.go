// SPDX-License-Identifier: Apache-2.0
package app

import (
	"encoding/json"
	"github.com/trozet/ovn-light/internal/model"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func demoRouting(s *model.Snapshot) {
	add := func(kind, raw string) {
		var u unstructured.Unstructured
		_ = json.Unmarshal([]byte(raw), &u)
		s.Inventory.Resources[kind] = append(s.Inventory.Resources[kind], u)
	}
	for j, name := range []string{"kind-worker", "kind-worker2"} {
		n := core.Node{ObjectMeta: meta.ObjectMeta{Name: name, Labels: map[string]string{"kubernetes.io/hostname": name}, Annotations: map[string]string{"k8s.ovn.org/l3-gateway-config": `{"default":{"mode":"shared","ip-addresses":["192.0.2.10/24"],"next-hops":["192.0.2.1"]}}`, "k8s.ovn.org/node-subnets": `{"default":"10.244.0.0/24"}`}}, Status: core.NodeStatus{Conditions: []core.NodeCondition{{Type: core.NodeReady, Status: core.ConditionTrue}}}}
		s.Inventory.Nodes = append(s.Inventory.Nodes, n)
		s.Nodes[j].Routing = model.RoutingEvidence{CapturedAt: s.CapturedAt, HostComplete: true, OVNComplete: true, BridgeMappings: "physnet:br-ex", Links: []model.Row{{"ifname": "br-ex", "operstate": "UP"}}, Routes: []model.Row{{"dst": "192.0.2.0/24", "dev": "br-ex"}}, Bridges: []model.Row{{"name": "br-ex"}}, Peers: []model.BGPRuntime{{VRF: "default", Peer: "192.0.2.1", Family: "ipv4", State: "Established", Complete: true, Advertised: []string{"10.244.0.0/24"}}}}
	}
	add("routeadvertisements", `{"apiVersion":"k8s.ovn.org/v1","kind":"RouteAdvertisements","metadata":{"name":"external-default"},"spec":{"networkSelectors":[{"networkSelectionType":"DefaultNetwork"}],"nodeSelector":{},"advertisements":["PodNetwork","EgressIP"],"targetVRF":"default"},"status":{"status":"Accepted"}}`)
	add("frrconfigurations", `{"metadata":{"name":"generated-default","namespace":"frr-k8s-system","labels":{"k8s.ovn.org/route-advertisements":"external-default"}},"spec":{"nodeSelector":{},"bgp":{"routers":[{"asn":64512,"neighbors":[{"address":"192.0.2.1","asn":64513,"toAdvertise":{"allowed":{"mode":"all"}}}],"prefixes":["10.244.0.0/24"]}]}}}`)
	add("egressips", `{"apiVersion":"k8s.ovn.org/v1","kind":"EgressIP","metadata":{"name":"storefront-egress"},"spec":{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"storefront"}},"podSelector":{},"egressIPs":["198.51.100.25"]},"status":{"items":[{"egressIP":"198.51.100.25","node":"kind-worker2"}]}}`)
	s.Nodes[1].Routing.Routers = []model.Row{{"name": "GR_kind-worker2", "nat": []any{"demo-nat"}}}
	s.Nodes[1].Routing.NAT = []model.Row{{"_uuid": "demo-nat", "type": "snat", "logical_ip": "10.244.0.8", "external_ip": "198.51.100.25"}}
	add("clusteruserdefinednetworks", `{"metadata":{"name":"blue","labels":{"advertise":"true"}},"spec":{"uplinks":["blue-uplink"],"namespaceSelector":{"matchLabels":{"network":"blue"}},"network":{"topology":"Layer3","layer3":{"role":"Primary","subnets":[{"cidr":"10.80.0.0/16","hostSubnet":24}]}}},"status":{"vrfName":"blue"}}`)
	add("uplinks", `{"metadata":{"name":"blue-uplink"},"spec":{"nodeConfigs":[{"type":"OVSBridge","hostInterfaceName":"br-blue","nodeSelector":{"matchLabels":{"kubernetes.io/hostname":"kind-worker"}}}]}}`)
	add("uplinkstates", `{"metadata":{"name":"blue-uplink.kind-worker"},"spec":{"uplinkName":"blue-uplink","nodeName":"kind-worker"},"status":{"hostInterfaceName":"br-blue","ovsBridge":{"name":"br-blue"},"ipAddresses":["203.0.113.10/24"],"defaultGateways":["203.0.113.1"],"conditions":[{"type":"Resolved","status":"True"},{"type":"GatewayReady","status":"True"}]}}`)
	add("routeadvertisements", `{"metadata":{"name":"external-blue"},"spec":{"networkSelectors":[{"networkSelectionType":"ClusterUserDefinedNetworks","clusterUserDefinedNetworkSelector":{"networkSelector":{"matchLabels":{"advertise":"true"}}}}],"advertisements":["PodNetwork"],"targetVRF":"auto","nodeSelector":{}},"status":{"status":"Accepted"}}`)
	add("frrconfigurations", `{"metadata":{"name":"generated-blue","namespace":"frr-k8s-system","labels":{"k8s.ovn.org/route-advertisements":"external-blue"}},"spec":{"nodeSelector":{"matchLabels":{"kubernetes.io/hostname":"kind-worker"}},"bgp":{"routers":[{"asn":64520,"vrf":"blue","neighbors":[{"address":"203.0.113.1","asn":64521,"toAdvertise":{"allowed":{"mode":"all"}}}],"prefixes":["10.80.0.0/24"]}]}}}`)
	s.Inventory.Nodes[0].Annotations["k8s.ovn.org/node-subnets"] = `{"default":"10.244.0.0/24","cluster_udn_blue":"10.80.0.0/24"}`
	s.Nodes[0].Routing.Links = append(s.Nodes[0].Routing.Links, model.Row{"ifname": "blue", "linkinfo": map[string]any{"info_kind": "vrf", "info_data": map[string]any{"table": 1001}}}, model.Row{"ifname": "br-blue", "master": "blue", "operstate": "UP"})
	s.Nodes[0].Routing.Routes = append(s.Nodes[0].Routing.Routes, model.Row{"dst": "203.0.113.0/24", "dev": "br-blue", "table": 1001})
	s.Nodes[0].Routing.Peers = append(s.Nodes[0].Routing.Peers, model.BGPRuntime{VRF: "blue", Peer: "203.0.113.1", Family: "ipv4", State: "Active", Complete: true, Advertised: []string{}})
	for _, key := range []string{"bgpsessionstates", "frrnodestates"} {
		s.Inventory.Resources[key] = []unstructured.Unstructured{}
	}
}
