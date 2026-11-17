// SPDX-License-Identifier: Apache-2.0
package ovn_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/trozet/ovn-light/internal/app"
	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

func TestEgressFirewallRuleAttribution(t *testing.T) {
	s := app.Demo()
	s.Nodes[0].Flows = strings.ReplaceAll(s.Nodes[0].Flows, "dst=10.244.0.12", "dst=203.0.113.8")
	s.Nodes[0].ACLs[0]["external_ids"] = map[string]any{"k8s.ovn.org/owner-type": "EgressFirewall", "k8s.ovn.org/name": "storefront", "rule-idx": "3"}
	s.Inventory.Resources["egressfirewalls"] = []unstructured.Unstructured{{Object: map[string]any{"metadata": map[string]any{"namespace": "storefront", "name": "default"}}}}
	for _, f := range ovn.Analyze(s, nil).Findings {
		if f.Destination.IP != "203.0.113.8" {
			continue
		}
		c := f.Causes[0]
		if c.Type != "EgressFirewall" || c.Namespace != "storefront" || c.Name != "default" || c.Rule != "3" || c.Direction != "Egress" || !f.CanRecommend {
			t.Fatal(f)
		}
		return
	}
	t.Fatal("external firewall drop was lost")
}

func TestForwardTrafficCounterAndLocalOutputIdentity(t *testing.T) {
	s := app.Demo()
	s.Nodes = s.Nodes[:1]
	n := &s.Nodes[0]
	n.Ports += "  port 8: api0\n"
	n.Interfaces = append(n.Interfaces, model.Row{"name": "api0", "external_ids": map[string]any{"iface-id": "payments_api-6dc2", "iface-id-ver": "api-6dc2"}})
	n.Flows = `ufid:entry,recirc_id(0),in_port(web0),ipv4(src=10.244.0.8,dst=10.96.0.10,proto=6),tcp(dst=8080),packets:100,bytes:10000,actions:ct(zone=1,nat),recirc(8)
ufid:delivery,recirc_id(8),in_port(web0),ipv4(dst=0.0.0.0/0,proto=6),tcp(dst=0/0),packets:100,bytes:10000,actions:api0`
	old := s
	old.Nodes = append([]model.NodeSnapshot{}, s.Nodes...)
	s.CapturedAt = s.CapturedAt.Add(30 * time.Second)
	n.CapturedAt = s.CapturedAt
	n.Flows = strings.ReplaceAll(strings.ReplaceAll(n.Flows, "packets:100", "packets:110"), "bytes:10000", "bytes:11000")
	v := ovn.Analyze(s, &old)
	if len(v.Traffic) != 1 {
		t.Fatal(v.Traffic)
	}
	o := v.Traffic[0]
	if o.Source.Pod != "web-7b49" || o.Destination.Pod != "api-6dc2" || o.Destination.Port != 0 || o.Location != "local" || o.PacketDelta == nil || *o.PacketDelta != 10 || *o.ByteDelta != 1000 {
		t.Fatalf("NAT/output identity or terminal accounting: %+v", o)
	}
	n.Flows = strings.ReplaceAll(n.Flows, "packets:110", "packets:1")
	if ovn.Analyze(s, &old).Traffic[0].PacketDelta != nil {
		t.Fatal("reset became traffic")
	}
}

func TestSharedForwardCounterDoesNotInventPodPair(t *testing.T) {
	s := app.Demo()
	s.Nodes = s.Nodes[:1]
	n := &s.Nodes[0]
	n.Flows = `ufid:a,recirc_id(0),in_port(4),ipv4(src=10.244.0.8,dst=10.244.0.12,proto=6),packets:3,actions:recirc(1)
ufid:b,recirc_id(0),in_port(7),ipv4(src=10.40.0.8,dst=10.40.0.12,proto=6),packets:7,actions:recirc(1)
ufid:c,recirc_id(1),in_port(0/0),ipv4(src=0.0.0.0/0,dst=0.0.0.0/0,proto=6),packets:10,actions:9`
	v := ovn.Analyze(s, nil)
	if len(v.Traffic) != 1 || !v.Traffic[0].Shared || v.Traffic[0].Source.UID != "" || v.Traffic[0].Destination.UID != "" {
		t.Fatal(v.Traffic)
	}
}

func TestRealCrossNodeTopologyKeepsWildcardDestinationUnknown(t *testing.T) {
	b, err := os.ReadFile("../../testdata/kind-topology.json")
	if err != nil {
		t.Fatal(err)
	}
	var s model.Snapshot
	if err = json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	old := app.DemoBaseline(s)
	for i := range old.Nodes {
		old.Nodes[i].FlowCapturedAt = s.Nodes[i].FlowCapturedAt.Add(-30 * time.Second)
	}
	v := ovn.Analyze(s, &old)
	sent, received := false, false
	seen := map[string]bool{}
	for _, o := range v.Traffic {
		if seen[o.CounterID] {
			t.Fatal("duplicate counter", o.CounterID)
		}
		seen[o.CounterID] = true
		if o.Source.Pod == "client" && o.Location == "source" && o.Destination.Node == "ovn-light-topology-ci-worker" {
			if o.Destination.UID != "" {
				t.Fatal("masked /24 became a specific destination pod", o)
			}
			if o.CounterScope != "branch-input" || !o.Partial || o.PacketDelta == nil || *o.PacketDelta == 0 {
				t.Fatal(o)
			}
			sent = true
		}
		if o.Source.Pod == "client" && o.Destination.Pod == "server" && o.Location == "destination" && o.PacketDelta != nil && *o.PacketDelta > 0 {
			received = true
		}
	}
	if !sent || !received {
		t.Fatalf("sent=%t received=%t: %+v", sent, received, v.Traffic)
	}
}

func TestReceiverWildcardPreservesSourceNodeWithoutGuessingPod(t *testing.T) {
	b, err := os.ReadFile("../../testdata/kind-topology.json")
	if err != nil {
		t.Fatal(err)
	}
	var s model.Snapshot
	if err = json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	s.Nodes[1].Flows = strings.ReplaceAll(s.Nodes[1].Flows, "src=10.244.0.3,", "src=10.244.0.0/255.255.255.0,")
	old := app.DemoBaseline(s)
	for i := range old.Nodes {
		old.Nodes[i].FlowCapturedAt = s.Nodes[i].FlowCapturedAt.Add(-30 * time.Second)
	}
	found := false
	for _, o := range ovn.Analyze(s, &old).Traffic {
		if o.Location != "destination" || o.Destination.Pod != "server" {
			continue
		}
		if o.Source.UID != "" || o.Source.Node != "ovn-light-topology-ci-control-plane" {
			t.Fatal("wildcard source must retain only its tunnel node", o)
		}
		if o.PacketDelta != nil && *o.PacketDelta > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("receiver counter with a masked source was lost")
	}
}

func TestOverlappingUDNIPsDoNotCrossIdentity(t *testing.T) {
	s := app.Demo()
	other := s.Inventory.Pods[1].DeepCopy()
	other.Namespace = "analytics"
	other.Name = "overlap"
	other.UID = types.UID("overlap")
	other.Annotations["k8s.ovn.org/pod-networks"] = `{"analytics/data":{"ip_addresses":["10.244.0.12/24"],"role":"primary"}}`
	s.Inventory.Pods = append(s.Inventory.Pods, *other)
	for _, f := range ovn.Analyze(s, nil).Findings {
		if f.Destination.IP == "10.244.0.12" && f.Destination.Namespace != "payments" {
			t.Fatalf("IP lookup crossed networks: %+v", f)
		}
	}
}

func TestRealKINDDefaultDeny(t *testing.T) {
	b, e := os.ReadFile("../../testdata/kind-denied.json")
	if e != nil {
		t.Fatal(e)
	}
	var s model.Snapshot
	if e = json.Unmarshal(b, &s); e != nil {
		t.Fatal(e)
	}
	v := ovn.Analyze(s, nil)
	if len(v.Findings) != 1 {
		t.Fatalf("expected one drop path, got %+v", v.Findings)
	}
	f := v.Findings[0]
	if !strings.HasPrefix(f.Source.Pod, "client-") || !strings.HasPrefix(f.Destination.Pod, "server-") {
		t.Fatalf("lost workload identity: %+v", f)
	}
	if len(f.Steps) < 3 || len(f.Causes) != 1 || f.Causes[0].Type != "NetpolNamespace" {
		t.Fatalf("lost policy/path attribution: %+v", f)
	}
	if f.Destination.Port != 0 || f.CanRecommend {
		t.Fatal("wildcarded transport was incorrectly made precise")
	}
}

func TestEvidenceAndMaskedConnection(t *testing.T) {
	s := app.Demo()
	v := ovn.Analyze(s, nil)
	if len(v.Findings) != 2 {
		t.Fatal(v.Findings)
	}
	var precise, partial bool
	for _, f := range v.Findings {
		if f.Source.Pod == "" || f.Destination.Pod == "" || len(f.Causes) != 1 {
			t.Fatalf("attribution failed: %+v", f)
		}
		if f.Destination.Port == 8080 {
			precise = f.CanRecommend && f.Confidence == "connection"
		} else {
			partial = !f.CanRecommend && f.Confidence == "partial"
		}
	}
	if !precise || !partial {
		t.Fatal("masked traffic must not inherit an exact connection")
	}
}
func TestCounterResetAndDelta(t *testing.T) {
	old := app.Demo()
	now := old
	now.Nodes = append(now.Nodes[:0:0], old.Nodes...)
	now.Nodes[0].Flows = strings.ReplaceAll(old.Nodes[0].Flows, "packets:41", "packets:45")
	v := ovn.Analyze(now, &old)
	for _, f := range v.Findings {
		if f.Destination.Port == 8080 && (f.Delta == nil || *f.Delta != 4) {
			t.Fatal("missing delta", f)
		}
	}
	now.Nodes[0].Flows = strings.ReplaceAll(old.Nodes[0].Flows, "packets:41", "packets:1")
	v = ovn.Analyze(now, &old)
	for _, f := range v.Findings {
		if f.Destination.Port == 8080 && f.Delta != nil {
			t.Fatal("counter reset reported as valid delta")
		}
	}
}
func TestOVSDBTaggedValues(t *testing.T) {
	rows, e := ovn.DecodeTable(`{"headings":["_uuid","external_ids","datapath"],"data":[[["uuid","abc"],["map",[["iface-id","ns_pod"]]],["uuid","def"]]]}`)
	if e != nil || ovn.Str(rows[0]["_uuid"]) != "abc" || ovn.Map(rows[0]["external_ids"])["iface-id"] != "ns_pod" {
		t.Fatal(rows, e)
	}
}
