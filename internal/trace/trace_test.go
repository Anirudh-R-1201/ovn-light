// SPDX-License-Identifier: Apache-2.0
package trace

import (
	"os"
	"strings"
	"testing"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
	core "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

func inventory() model.Inventory {
	return model.Inventory{Pods: []core.Pod{{ObjectMeta: meta.ObjectMeta{Namespace: "demo", Name: "client", UID: "client-uid", Annotations: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":["10.0.0.2/24"],"mac_address":"0a:58:0a:00:00:02","gateway_ips":["10.0.0.1"],"role":"primary"}}`}}, Spec: core.PodSpec{NodeName: "node-a"}, Status: core.PodStatus{Phase: core.PodRunning}}, {ObjectMeta: meta.ObjectMeta{Namespace: "demo", Name: "server", UID: "server-uid", Annotations: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":["10.0.0.3/24"],"mac_address":"0a:58:0a:00:00:03","gateway_ips":["10.0.0.1"],"role":"primary"}}`}}, Spec: core.PodSpec{NodeName: "node-b"}, Status: core.PodStatus{Phase: core.PodRunning}}}}
}
func TestResolveIdentity(t *testing.T) {
	inv := inventory()
	e := ovn.Attachments(inv)[0].Endpoint
	if _, err := Resolve(inv, e); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*model.Endpoint){func(e *model.Endpoint) { e.UID = "old" }, func(e *model.Endpoint) { e.Network = "tenant" }, func(e *model.Endpoint) { e.NAD = "other/net" }, func(e *model.Endpoint) { e.IP = "10.0.0.3" }} {
		bad := e
		change(&bad)
		if _, err := Resolve(inv, bad); err == nil {
			t.Fatalf("accepted stale identity: %+v", bad)
		}
	}
	inv.Pods[0].DeletionTimestamp = &meta.Time{}
	if _, err := Resolve(inv, e); err == nil {
		t.Fatal("accepted deleting pod")
	}
}
func TestGatewayNetworkScope(t *testing.T) {
	inv := inventory()
	src := ovn.Attachments(inv)[0]
	rows := []model.Row{{"logical_port": src.LogicalPort, "datapath": "blue"}, {"logical_port": "blue-switch", "datapath": "blue", "options": map[string]any{"peer": "blue-router"}}, {"logical_port": "wrong-router", "mac": []any{"aa:bb:cc:dd:ee:ff 10.0.0.1/24"}}, {"logical_port": "blue-router", "mac": []any{"0a:58:0a:00:00:01 10.0.0.1/24"}}}
	got, err := NextHopMAC(inv, src, model.Endpoint{IP: "10.0.0.3"}, rows)
	if err != nil || got != "0a:58:0a:00:00:01" {
		t.Fatalf("gateway: %s %v", got, err)
	}
	rows = rows[:3]
	if _, err := NextHopMAC(inv, src, model.Endpoint{IP: "10.0.0.3"}, rows); err == nil {
		t.Fatal("used another network's router")
	}
}
func TestCommandsDoNotExecutePackets(t *testing.T) {
	r := Request{Source: model.Endpoint{IP: "2001:db8::2"}, Destination: model.Endpoint{IP: "2001:db8::3"}, Protocol: "TCP", Port: 443, State: "new"}
	if err := Validate(&r); err != nil {
		t.Fatal(err)
	}
	args := LogicalArgs("unix:/sb", LogicalFlow(r, `port"name`, "00:11:22:33:44:55", "00:11:22:33:44:66"), r.State, "[2001:db8::3]:8443")
	if strings.Count(strings.Join(args, " "), "--ct=trk,new") != MaxLookups || !strings.Contains(args[len(args)-1], "ip6.dst == 2001:db8::3") || !strings.Contains(args[len(args)-1], `inport == "port\"name"`) {
		t.Fatal(args)
	}
	for _, a := range append(args, OVSArgs(r, 3, "00:11:22:33:44:55", "00:11:22:33:44:66")...) {
		if a == "--generate" || a == "--execute" || a == "sh" {
			t.Fatal("unsafe command", a)
		}
	}
	for _, state := range []string{"new", "established", "reply"} {
		r.State = state
		if err := Validate(&r); err != nil {
			t.Fatal(err)
		}
	}
	r.State = "bogus"
	if Validate(&r) == nil {
		t.Fatal("invalid state accepted")
	}
}
func TestParseDeniedWithoutLiteralDrop(t *testing.T) {
	raw, err := os.ReadFile("testdata/denied.txt")
	if err != nil {
		t.Fatal(err)
	}
	n := model.NodeSnapshot{Name: "node", LogicalFlows: []model.Row{{"_uuid": "29d6c5cc-1111", "external_ids": map[string]any{"stage-hint": "4409227e"}}}, ACLs: []model.Row{{"_uuid": "4409227e-b1e0", "action": "drop", "external_ids": map[string]any{"k8s.ovn.org/owner-type": "NetpolNamespace", "k8s.ovn.org/name": "ovn-light-demo"}}}}
	s := Parse(string(raw), "ovn-light-demo_server-544658cd78-b8n9v", n, model.Inventory{})
	if s.Status != "predicted-drop" || len(s.Causes) != 1 || s.Causes[0].Namespace != "ovn-light-demo" {
		t.Fatalf("%+v", s)
	}
	if s.Stages[len(s.Stages)-1].Name != "ls_out_acl_action" {
		t.Fatal("missing terminal stage")
	}
	// A compiler UUID prefix collision must not attribute the wrong policy.
	n.LogicalFlows = append(n.LogicalFlows, model.Row{"_uuid": "29d6c5cc-2222", "external_ids": map[string]any{"stage-hint": "other"}})
	if causes := ovn.TraceCauses(n, model.Inventory{}, []string{"29d6c5cc"}); len(causes) != 0 {
		t.Fatal(causes)
	}
}
func TestParseOutcomes(t *testing.T) {
	base := "ingress(dp=\"switch\", inport=\"client\")\n 1. ls_in_l2_lkup (northd.c:1): 1, priority 50, uuid 12345678\n    output;\n"
	for _, tc := range []struct{ tail, want string }{{"    /* output to \"server\" */\n", "predicted-delivery"}, {"    /* output to \"remote\", type \"remote\" */\n", "handoff"}, {"    /* output to \"server\", type \"\" */\n", "predicted-delivery"}, {"", "unknown"}, {"*** error: incomplete trace\n", "unknown"}} {
		s := Parse(base+tc.tail, "server", model.NodeSnapshot{}, model.Inventory{})
		if s.Status != tc.want {
			t.Fatalf("%q: %s", tc.tail, s.Status)
		}
	}
	if s := Parse("garbage", "server", model.NodeSnapshot{}, model.Inventory{}); s.Status != "unknown" {
		t.Fatal(s)
	}
}
func TestServiceBackendPortAndIdentity(t *testing.T) {
	inv := inventory()
	src := ovn.Attachments(inv)[0].Endpoint
	svc := core.Service{ObjectMeta: meta.ObjectMeta{Namespace: "demo", Name: "web", UID: "service-uid"}, Spec: core.ServiceSpec{ClusterIP: "10.96.0.2", ClusterIPs: []string{"10.96.0.2"}, Ports: []core.ServicePort{{Name: "http", Protocol: core.ProtocolTCP, Port: 80}}}}
	slice := discovery.EndpointSlice{ObjectMeta: meta.ObjectMeta{Namespace: "demo", Labels: map[string]string{discovery.LabelServiceName: "web"}, OwnerReferences: []meta.OwnerReference{{Kind: "Service", UID: svc.UID}}}, Ports: []discovery.EndpointPort{{Name: ptr.To("http"), Protocol: ptr.To(core.ProtocolTCP), Port: ptr.To(int32(8080))}}, Endpoints: []discovery.Endpoint{{Addresses: []string{"10.0.0.3"}, Conditions: discovery.EndpointConditions{Ready: ptr.To(true)}, TargetRef: &core.ObjectReference{Kind: "Pod", Namespace: "demo", Name: "server", UID: types.UID("server-uid")}}}}
	r := Request{Source: src, Protocol: "TCP", Port: 80}
	got, err := ServiceBackends(inv, svc, []discovery.EndpointSlice{slice}, r)
	if err != nil || len(got.Backends) != 1 || got.Backends[0].Port != 8080 {
		t.Fatalf("%+v %v", got, err)
	}
	slice.Endpoints[0].TargetRef.UID = "stale"
	got, err = ServiceBackends(inv, svc, []discovery.EndpointSlice{slice}, r)
	if err != nil || len(got.Backends) != 0 {
		t.Fatal("stale target accepted")
	}
	r.Source.Network = "tenant"
	if _, err := ServiceBackends(inv, svc, nil, r); err == nil {
		t.Fatal("UDN VIP accepted")
	}
}

func TestInterconnectContinuation(t *testing.T) {
	inv := inventory()
	src := ovn.Attachments(inv)[0]
	r := Request{Source: src.Endpoint, Destination: ovn.Attachments(inv)[1].Endpoint, Protocol: "TCP", Port: 8080}
	_ = Validate(&r)
	raw := `ingress(dp="router", inport="pod-router")
 1. lr_in_ip_routing (northd.c:1): 1, priority 10, uuid 12345678
    ip.ttl--;
    eth.src = 00:11:22:33:44:55;
    eth.dst = 00:11:22:33:44:66;
    next;
egress(dp="transit", inport="from-a", outport="to-b")
 1. ls_out_delivery (northd.c:1): 1, priority 10, uuid 12345679
    output;
    /* output to "to-b", type "remote" */
`
	segment := Parse(raw, "server", model.NodeSnapshot{}, inv)
	remote := model.NodeSnapshot{Bindings: []model.Row{{"logical_port": "from-a", "type": "remote", "datapath": "transit"}, {"logical_port": "to-b", "type": "patch", "datapath": "transit"}}}
	flow, err := ContinueFlow(r, src, segment, remote)
	if err != nil || !strings.Contains(flow, `inport == "from-a"`) || !strings.Contains(flow, "ip.ttl == 63") || !strings.Contains(flow, "eth.src == 00:11:22:33:44:55") {
		t.Fatalf("%s %v", flow, err)
	}
	segment.Stages[0].Actions = append(segment.Stages[0].Actions, "ct_snat;")
	if _, err = ContinueFlow(r, src, segment, remote); err == nil {
		t.Fatal("continued transformed tuple")
	}
}

func TestParseDeliveredTrace(t *testing.T) {
	raw, err := os.ReadFile("testdata/delivered.txt")
	if err != nil {
		t.Fatal(err)
	}
	result := Parse(string(raw), "ovn-light-demo_server-544658cd78-b8n9v", model.NodeSnapshot{}, model.Inventory{})
	if result.Status != "predicted-delivery" {
		t.Fatalf("%s: %s", result.Status, result.Summary)
	}
}
