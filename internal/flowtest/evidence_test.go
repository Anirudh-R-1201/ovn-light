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
	r.observe(model.View{}, report, nil)
	if len(r.Nodes[0].Paths) != 0 {
		t.Fatal("pre-run delta used")
	}
	at = at.Add(30 * time.Second)
	report.Nodes[0].CapturedAt = at
	report.Paths[0].ObservedAt = at
	r.observe(model.View{}, report, nil)
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
	r.observe(model.View{}, report, nil)
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
		run.observe(view, store.Latest(), inv.Pods)
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
