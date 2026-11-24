// SPDX-License-Identifier: Apache-2.0
package flowtest

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/trozet/ovn-light/internal/datapath"
	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/offload"
	"github.com/trozet/ovn-light/internal/ovn"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

func TestCorrelateTestStream(t *testing.T) {
	start := time.Now().UTC()
	r := Run{ID: "one", Network: "default", Started: start, Source: Endpoint{Node: "a", IP: "10.0.0.1", UID: "client"}, Destination: Endpoint{Node: "b", IP: "10.0.1.1", UID: "server"}, Nodes: []NodeEvidence{{Node: "a"}, {Node: "b"}}}
	tuple := &model.FlowTuple{Protocol: "tcp", SourceIP: "10.0.0.1", SourcePort: "35201", DestinationIP: "10.0.1.1", DestinationPort: "5201"}
	at := start.Add(time.Second)
	path := model.OffloadPath{ID: "p", Node: "a", Network: "default", Tuple: tuple, Status: "partial", ObservedAt: at, PartialDelta: ptr.To(uint64(4)), Stages: []model.OffloadStage{{ID: "ufid", Recirc: "2", Status: "software", PartialDelta: ptr.To(uint64(4))}}, Conntrack: []model.OffloadCT{{Zone: "3", Original: "hardware", Reply: "software", CapturedAt: at}}}
	report := model.OffloadReport{Nodes: []model.OffloadNode{{Name: "a", State: "enabled", CapturedAt: at, DiagnosticsAt: at}, {Name: "b", State: "disabled", CapturedAt: at, DiagnosticsAt: at}}, Paths: []model.OffloadPath{path}}
	r.observe(model.View{}, report, model.Inventory{})
	if len(r.Nodes[0].Paths) != 0 {
		t.Fatal("pre-run delta used")
	}
	at = at.Add(30 * time.Second)
	report.Nodes[0].CapturedAt = at
	report.Paths[0].ObservedAt = at
	r.observe(model.View{}, report, model.Inventory{})
	if len(r.Nodes[0].Paths) != 1 || r.Nodes[1].State != "disabled" {
		t.Fatal(r.Nodes)
	}
	got := r.Nodes[0].Paths[0]
	if got.Stages[0].Recirc != "2" || *got.Stages[0].PartialDelta != 4 || got.Conntrack[0].Original != "hardware" || got.Conntrack[0].Reply != "software" {
		t.Fatal(got)
	}
	for _, change := range []func(*model.OffloadPath){
		func(p *model.OffloadPath) { p.Network = "blue" },
		func(p *model.OffloadPath) { p.Tuple = nil },
		func(p *model.OffloadPath) { x := *p.Tuple; x.SourcePort = "60000"; p.Tuple = &x },
		func(p *model.OffloadPath) { p.Source.UID = "old-client" },
		func(p *model.OffloadPath) { p.ObservedAt = start.Add(-time.Second) },
	} {
		p := path
		change(&p)
		if r.matches(p) {
			t.Fatal("unrelated report matched", p)
		}
	}
	back := path
	back.Tuple = &model.FlowTuple{Protocol: "tcp", SourceIP: tuple.DestinationIP, SourcePort: tuple.DestinationPort, DestinationIP: tuple.SourceIP, DestinationPort: tuple.SourcePort}
	if !r.matches(back) {
		t.Fatal("missed reply direction")
	}
	report.Paths[0].Status = "hardware"
	report.Paths[0].ID = "other"
	report.Paths[0].Conntrack[0].CapturedAt = start.Add(-time.Minute)
	at = at.Add(30 * time.Second)
	report.Nodes[0].CapturedAt = at
	report.Paths[0].ObservedAt = at
	r.observe(model.View{}, report, model.Inventory{})
	p := r.Nodes[0].Paths[1]
	if p.Status != "unknown" || p.Conntrack[0].Original != "" {
		t.Fatal("stale CT used", p)
	}
}

func TestAgentSummaryIdentifiesSoftwareRecirculation(t *testing.T) {
	const clientIP, serverIP = "10.1.0.1", "10.2.0.1"
	start := time.Now().UTC()
	run := Run{ID: "run", JobUID: "job", Network: "default", Started: start, Source: Endpoint{Node: "a"}, Destination: Endpoint{Node: "b"}, Nodes: []NodeEvidence{{Node: "a"}, {Node: "b"}}}
	pod := func(role, node, ip string) core.Pod {
		return core.Pod{ObjectMeta: meta.ObjectMeta{
			Name: role, UID: types.UID(role), Namespace: namespace,
			Labels:          map[string]string{runLabel: run.ID, "ovn-light.io/role": role},
			Annotations:     map[string]string{"k8s.ovn.org/pod-networks": fmt.Sprintf(`{"default":{"role":"primary","ip_addresses":["%s/24"]}}`, ip)},
			OwnerReferences: []meta.OwnerReference{{Kind: "Job", Name: jobName, UID: types.UID(run.JobUID)}},
		}, Spec: core.PodSpec{NodeName: node}, Status: core.PodStatus{PodIP: ip, PodIPs: []core.PodIP{{IP: ip}}, Phase: core.PodRunning}}
	}
	inv := model.Inventory{Pods: []core.Pod{pod("client", "a", clientIP), pod("server", "b", serverIP)}}
	const match = "in_port(1),ipv4(src=10.1.0.1,dst=10.2.0.1,proto=6),tcp(src=35201,dst=5201)"
	const ct = "tcp,orig=(src=10.1.0.1,dst=10.2.0.1,sport=35201,dport=5201),reply=(src=10.2.0.1,dst=10.1.0.1,sport=5201,dport=35201),zone=7,protoinfo=(state=ESTABLISHED),orig_offloaded:yes"
	var store offload.Store
	for i := 0; i < 4; i++ {
		at := start.Add(time.Second + time.Duration(i)*30*time.Second)
		n := model.NodeSnapshot{Name: "a", Datapath: "netdev@ovs-netdev", CapturedAt: at,
			Collection: model.CollectionStats{FlowComplete: true}, Ports: "port 1: rep0",
			Interfaces: []model.Row{{"name": "rep0", "external_ids": map[string]any{"iface-id": namespace + "_client", "iface-id-ver": "client"}}},
			Offload:    model.OffloadEvidence{CapturedAt: at, ConfigKnown: true, Enabled: true, Provider: "doca", CTSupported: true, CTComplete: true, Conntrack: ct},
			Flows:      fmt.Sprintf("ufid:root,recirc_id(0),%s,packets:%d,bytes:%d,offloaded:yes,dp:doca,actions:ct(zone=7),recirc(42)\nufid:next,recirc_id(42),%s,packets:%d,bytes:%d,partial_offload_packets:%d,dp:ovs,actions:2", match, 20+i, 2000+100*i, match, 20+i, 2000+100*i, 3*i),
		}
		n = ovn.Summarize(n, nil, ovn.Project(inv), datapath.ReadSample(n.Flows, n.Ports))
		wire, err := json.Marshal(n)
		if err != nil {
			t.Fatal(err)
		}
		var received model.NodeSnapshot
		if err := json.Unmarshal(wire, &received); err != nil {
			t.Fatal(err)
		}
		view := ovn.Analyze(model.Snapshot{Inventory: inv, CapturedAt: at, Nodes: []model.NodeSnapshot{received}}, nil)
		store.Update(view.Offload)
		run.observe(view, store.Latest(), inv)
	}
	if len(run.Nodes[0].Paths) != 1 {
		t.Fatalf("test endpoints %v → %v, paths %+v", run.Source, run.Destination, run.Nodes[0].Paths)
	}
	p := run.Nodes[0].Paths[0]
	if !p.Issue || p.Status != "partial" || len(p.Stages) != 2 || p.Stages[1].Recirc != "42" || p.Stages[1].Status != "software" || p.Stages[1].PartialDelta == nil || *p.Stages[1].PartialDelta != 3 {
		t.Fatalf("unexpected recirculation evidence: %+v", p)
	}
	if len(p.Conntrack) != 1 || p.Conntrack[0].Original != "hardware" || p.Conntrack[0].Reply != "software" {
		t.Fatal(p.Conntrack)
	}
}

func TestSelectedProfileMatchesOnlyItsDataTraffic(t *testing.T) {
	src, dst := Endpoint{UID: "client", IP: "10.0.0.1"}, Endpoint{UID: "server", IP: "10.0.1.1"}
	run := Run{Source: src, Destination: dst, Network: "default"}
	for _, tt := range []struct {
		test, protocol, port string
		matches              bool
	}{
		{"iperf-udp", "udp", "35201", true}, {"iperf-udp", "tcp", "35201", false}, {"iperf-udp", "udp", "40312", false},
		{"http", "tcp", "40312", true}, {"simple", "tcp", "40312", true}, {"netperf-tcp-stream", "tcp", "40312", false}, {"ib-read-bw", "tcp", "35201", false},
	} {
		run.Test = tt.test
		for _, tuple := range []model.FlowTuple{
			{SourceIP: src.IP, DestinationIP: dst.IP, Protocol: tt.protocol, SourcePort: tt.port, DestinationPort: "5201"},
			{SourceIP: dst.IP, DestinationIP: src.IP, Protocol: tt.protocol, SourcePort: "5201", DestinationPort: tt.port},
		} {
			if run.matches(model.OffloadPath{Tuple: &tuple, Network: "default"}) != tt.matches {
				t.Fatalf("profile %s tuple %+v", tt.test, tuple)
			}
		}
	}
}

func TestNetperfSeparatesControlFromData(t *testing.T) {
	run := Run{Test: "netperf-tcp-rr", Source: Endpoint{UID: "a", IP: "10.0.0.1"}, Destination: Endpoint{UID: "b", IP: "10.0.0.2"}, Network: "default"}
	data := model.FlowTuple{Protocol: "tcp", SourceIP: run.Source.IP, DestinationIP: run.Destination.IP, SourcePort: "35202", DestinationPort: "5202"}
	path := model.OffloadPath{Network: run.Network, Tuple: &data}
	if !run.matches(path) {
		t.Fatal("missing negotiated data stream")
	}
	data.DestinationPort = "5201"
	if run.matches(path) {
		t.Fatal("control connection classified as data")
	}
}

func TestMaskedSoftwareFlowsAreScopedToTestPortAndDirection(t *testing.T) {
	now := time.Now().UTC()
	r := Run{Started: now, Source: Endpoint{UID: "client", IP: "10.0.1.1", Node: "a"}, Destination: Endpoint{UID: "server", IP: "10.0.2.1", Node: "b"}}
	n := NodeEvidence{Node: "b"}
	sample := model.TestPathSample{At: now, PodUID: "server", Node: "b", Match: map[string]string{"eth_type": "0x0800", "ipv4.proto": "6", "ipv4.src": "10.0.1.0/24", "ipv4.dst": "10.0.2.1", "tcp.dst": "5201"}, Stages: []model.OffloadStage{{ID: "one", Status: "software", Packets: 4, Raw: "actions:42"}}}
	r.recordTestFlows(&n, []model.TestPathSample{sample})
	if len(n.Flows) != 1 || n.Flows[0].Exact || n.Flows[0].Raw != "actions:42" || n.Flows[0].Direction != "client → server" {
		t.Fatal(n)
	}
	sample.Match["tcp.src"] = "35201"
	sample.Match["ipv4.src"] = "10.0.1.1"
	r.recordTestFlows(&n, []model.TestPathSample{sample})
	if len(n.Flows) != 1 || !n.Flows[0].Exact {
		t.Fatal(n)
	}
	for _, change := range []func(*model.TestPathSample){
		func(p *model.TestPathSample) { p.PodUID = "other" }, func(p *model.TestPathSample) { p.Outbound = true }, func(p *model.TestPathSample) { p.Node = "a" }, func(p *model.TestPathSample) { p.At = now.Add(-time.Second) }, func(p *model.TestPathSample) { p.Match["tcp.src"] = "41000" },
	} {
		test := sample
		change(&test)
		dst := NodeEvidence{Node: "b"}
		r.recordTestFlows(&dst, []model.TestPathSample{test})
		if len(dst.Flows) != 0 {
			t.Fatal(dst)
		}
	}
}

func TestServiceIPCanMatchBeforeOrAfterTranslation(t *testing.T) {
	now := time.Now().UTC()
	r := Run{Case: crossService, ServiceIP: "10.96.0.10", Started: now, Source: Endpoint{Node: "a", UID: "client", IP: "10.1.0.1"}, Destination: Endpoint{Node: "b", UID: "server", IP: "10.2.0.1"}}
	for _, tc := range []struct {
		address string
		want    bool
	}{{r.ServiceIP, true}, {r.Destination.IP, true}, {"10.96.0.11", false}} {
		sample := model.TestPathSample{
			PodUID: "client", Node: "a", Outbound: true, At: now,
			Match:  map[string]string{"eth_type": "0x0800", "ipv4.proto": "6", "ipv4.src": r.Source.IP, "ipv4.dst": tc.address, "tcp.src": "35201", "tcp.dst": "5201"},
			Stages: []model.OffloadStage{{ID: "f", Status: "hardware", Packets: 1, Raw: "actions:3"}},
		}
		n := NodeEvidence{Node: "a"}
		r.recordTestFlows(&n, []model.TestPathSample{sample})
		if (len(n.Flows) == 1 && n.Flows[0].Exact) != tc.want {
			t.Errorf("destination %s: %+v", tc.address, n.Flows)
		}
	}
}
