// SPDX-License-Identifier: Apache-2.0
package offload

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/trozet/ovn-light/internal/datapath"
	"github.com/trozet/ovn-light/internal/model"
)

var start = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const ct = "tcp,orig=(src=10.0.0.1,dst=10.0.0.2,sport=1234,dport=80),reply=(src=10.0.0.2,dst=10.0.0.1,sport=80,dport=1234),zone=7,protoinfo=(state=ESTABLISHED),orig_offloaded:yes"

func node(at time.Time, packets, partial uint64, status, actions string) model.NodeSnapshot {
	return model.NodeSnapshot{Name: "node-a", Datapath: "netdev@ovs-netdev", CapturedAt: at, Collection: model.CollectionStats{FlowComplete: true}, Offload: model.OffloadEvidence{CapturedAt: at, ConfigKnown: true, Enabled: true, Provider: "doca", CTSupported: true, CTComplete: true, Conntrack: ct}, Flows: fmt.Sprintf("ufid:root,recirc_id(0),in_port(1),ipv4(src=10.0.0.1,dst=10.0.0.2,proto=6),tcp(src=1234,dst=80),packets:%d,bytes:%d,partial_offload_packets:%d,partial_offload_bytes:%d,offloaded:%s,dp:doca,actions:%s", packets, packets*64, partial, partial*64, status, actions)}
}
func analyze(t *testing.T, n model.NodeSnapshot) model.OffloadReport {
	t.Helper()
	flows, errs := datapath.Parse(n.Flows)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	no, ps := Analyze(n, flows, datapath.ReconstructTraffic(flows))
	return model.OffloadReport{CollectedAt: n.CapturedAt, Nodes: []model.OffloadNode{no}, Paths: ps}
}
func TestPartialActivityAndRecovery(t *testing.T) {
	var s Store
	for i := 0; i < 4; i++ {
		r := analyze(t, node(start.Add(time.Duration(i)*30*time.Second), uint64(100+i*10), uint64(i*10), "yes", "2"))
		issues := s.Update(r)
		if (len(issues) > 0) != (i == 3) {
			t.Fatalf("poll %d: %v", i, issues)
		}
	}
	r := s.Report(Options{Status: "issues"})
	if len(r.Paths) != 1 || len(r.Paths[0].Stages) != 0 {
		t.Fatal(r)
	}
	detail := s.Report(Options{ID: r.Paths[0].ID})
	if len(detail.Paths[0].Stages) != 1 || *detail.Paths[0].PartialDelta != 10 {
		t.Fatal(detail)
	}
	// A historical partial counter alone must not keep an issue alive.
	s.Update(analyze(t, node(start.Add(2*time.Minute), 160, 30, "yes", "2")))
	if s.Report(Options{}).Issues != 0 || s.Report(Options{}).Paths[0].Status != "hardware" {
		t.Fatal(s.Report(Options{}))
	}
}
func TestHistoryResets(t *testing.T) {
	for _, change := range []string{"reset", "modified", "missing", "incomplete", "long-gap", "provider"} {
		t.Run(change, func(t *testing.T) {
			var s Store
			for i := 0; i < 3; i++ {
				s.Update(analyze(t, node(start.Add(time.Duration(i)*30*time.Second), uint64(100+i*10), uint64(i*10), "yes", "2")))
			}
			n := node(start.Add(90*time.Second), 130, 30, "yes", "2")
			switch change {
			case "reset":
				n = node(n.CapturedAt, 1, 1, "yes", "2")
			case "modified":
				n.Flows = strings.Replace(n.Flows, "actions:2", "actions:3", 1)
			case "missing":
				s.Update(model.OffloadReport{})
			case "incomplete":
				n.Collection.FlowComplete = false
			case "long-gap":
				n.CapturedAt = start.Add(5 * time.Minute)
				n.Offload.CapturedAt = n.CapturedAt
			case "provider":
				n.Datapath = "different"
			}
			if issues := s.Update(analyze(t, n)); len(issues) != 0 {
				t.Fatal(issues)
			}
		})
	}
}
func TestCapabilityAndIncompletePath(t *testing.T) {
	n := node(start, 10, 0, "no", "2")
	n.Flows = strings.Replace(n.Flows, "dp:doca", "dp:ovs", 1)
	r := analyze(t, n)
	if r.Paths[0].Eligible || r.Paths[0].Status != "unknown" {
		t.Fatal(r)
	}
	n.Interfaces = []model.Row{{"name": "rep0", "status": map[string]any{"driver_name": "mlx5_core"}}}
	n.Ports = "port 1: rep0"
	r = analyze(t, n)
	if !r.Paths[0].Eligible || r.Paths[0].Status != "software" {
		t.Fatal(r)
	}
	n.Flows = strings.Replace(n.Flows, "actions:2", "actions:recirc(99)", 1)
	r = analyze(t, n)
	if len(r.Paths) != 1 || r.Paths[0].Complete {
		t.Fatal(r)
	}
	n.Offload.Enabled = false
	r = analyze(t, n)
	if len(r.Paths) != 0 || r.Nodes[0].State != "disabled" {
		t.Fatal(r)
	}
	n.Offload.CapturedAt = start.Add(-3 * time.Minute)
	r = analyze(t, n)
	if r.Nodes[0].State != "unknown" {
		t.Fatal(r)
	}
}
func TestCTDirectionsZonesAndNAT(t *testing.T) {
	n := node(start, 10, 0, "yes", "ct(zone=7),2")
	r := analyze(t, n)
	c := r.Paths[0].Conntrack[0]
	if c.Status != "hardware" || c.Reply != "software" || c.Direction != "original" || r.Paths[0].CTProblem {
		t.Fatal(c, r.Paths[0])
	}
	// Another network's identical tuple in a different zone cannot supply evidence.
	n.Offload.Conntrack = strings.Replace(ct, "zone=7", "zone=8", 1)
	if c = analyze(t, n).Paths[0].Conntrack[0]; c.Status != "unknown" {
		t.Fatal(c)
	}
	n.Offload.Conntrack = ct + "\n" + ct
	if c = analyze(t, n).Paths[0].Conntrack[0]; c.Status != "unknown" {
		t.Fatal(c)
	}
	n.Offload.Conntrack = "tcp,orig=(src=192.0.2.1,dst=10.0.0.2,sport=1234,dport=80),reply=(src=10.0.0.2,dst=10.0.0.1,sport=80,dport=1234),zone=7,protoinfo=(state=ESTABLISHED),orig_offloaded:yes"
	if c = analyze(t, n).Paths[0].Conntrack[0]; c.Status != "hardware" {
		t.Fatal("post-NAT tuple not correlated", c)
	}
	n.Offload.Conntrack = ct
	n.Flows = strings.ReplaceAll(n.Flows, "src=10.0.0.1,dst=10.0.0.2", "src=10.0.0.2,dst=10.0.0.1")
	n.Flows = strings.ReplaceAll(n.Flows, "src=1234,dst=80", "src=80,dst=1234")
	if c = analyze(t, n).Paths[0].Conntrack[0]; c.Status != "software" || c.Direction != "reply" {
		t.Fatal(c)
	}
	n.Offload.Conntrack = strings.Replace(ct, "ESTABLISHED", "SYN_SENT", 1)
	if c = analyze(t, n).Paths[0].Conntrack[0]; c.Status != "pending" {
		t.Fatal(c)
	}
}
func TestCTUnavailableMaskedAndMalformed(t *testing.T) {
	for _, mode := range []string{"unsupported", "failed", "stale", "masked", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			n := node(start, 10, 0, "yes", "ct(zone=7),2")
			switch mode {
			case "unsupported":
				n.Offload.CTSupported = false
			case "failed":
				n.Offload.CTComplete = false
			case "stale":
				n.Offload.CapturedAt = start.Add(-2 * time.Minute)
			case "masked":
				n.Flows = strings.Replace(n.Flows, "src=1234,dst=80", "src=0/0,dst=80", 1)
			case "malformed":
				n.Offload.Conntrack = ct + "\ntruncated"
			}
			r := analyze(t, n)
			if r.Paths[0].Status == "hardware" || r.Paths[0].Conntrack[0].Status != "unknown" {
				t.Fatal(r)
			}
		})
	}
}
func TestCTCachedEvidenceDoesNotConfirmRepeatedFailure(t *testing.T) {
	var s Store
	for i := 0; i < 4; i++ {
		n := node(start.Add(time.Duration(i)*25*time.Second), uint64(100+i*10), 0, "yes", "ct(zone=7),2")
		n.Offload.CapturedAt = start
		n.Offload.Conntrack = strings.Replace(ct, ",orig_offloaded:yes", "", 1)
		if issues := s.Update(analyze(t, n)); len(issues) > 0 {
			t.Fatal("cached CT counted repeatedly", issues)
		}
	}
}
func TestProviderFailureAndBoundedFiltering(t *testing.T) {
	var s Store
	for i := 0; i < 4; i++ {
		n := node(start.Add(time.Duration(i)*30*time.Second), uint64(100+i*10), 0, "no", "drop, dp-offload-info:'unsupported action'")
		s.Update(analyze(t, n))
	}
	r := s.Report(Options{Status: "issues", Node: "node-a", Limit: 1})
	if len(r.Paths) != 1 || r.Paths[0].Status != "failure" {
		t.Fatal(r)
	}
	if s.Report(Options{Node: "other"}).Total != 0 {
		t.Fatal("node filter leaked")
	}
	if s.Report(Options{Network: "other"}).Total != 0 {
		t.Fatal("network filter leaked")
	}
}
func TestIPv6CT(t *testing.T) {
	x := parseCT("tcp,orig=(src=fd00::1,dst=fd00::2,sport=42,dport=80),reply=(src=fd00::2,dst=fd00::1,sport=80,dport=42),zone=2,protoinfo=(state=ESTABLISHED),orig_offloaded:yes,reply_offloaded:yes")
	if !x.valid || len(x.entries) != 1 || !x.entries[0].replyHW {
		t.Fatal(x)
	}
}

func TestMixedRecirculationStages(t *testing.T) {
	n := node(start, 10, 0, "yes", "recirc(42)")
	n.Flows += "\nufid:next,recirc_id(42),in_port(1),ipv4(src=10.0.0.1,dst=10.0.0.2,proto=6),tcp(src=1234,dst=80),packets:10,bytes:640,dp:ovs,actions:2"
	r := analyze(t, n)
	if len(r.Paths) != 1 || len(r.Paths[0].Stages) != 2 || r.Paths[0].Status != "partial" {
		t.Fatal(r)
	}
}
func TestSetupTrafficNeverBecomesPersistentFallback(t *testing.T) {
	for _, field := range []string{"ct_state(+new+trk)", "ct_state(0x21/0x21)", "tcp_flags(0x2/0x2)"} {
		var s Store
		for i := 0; i < 5; i++ {
			n := node(start.Add(time.Duration(i)*30*time.Second), uint64(100+i*10), uint64(i*10), "partial", "2")
			n.Flows = strings.Replace(n.Flows, "in_port(1)", "in_port(1),"+field, 1)
			if issues := s.Update(analyze(t, n)); len(issues) != 0 {
				t.Fatal(field, issues)
			}
		}
		if s.Report(Options{}).Paths[0].Status != "pending" {
			t.Fatal(field, s.Report(Options{}))
		}
	}
}
func TestUnidirectionalUDPSetup(t *testing.T) {
	n := node(start, 10, 0, "yes", "ct(zone=7),2")
	n.Flows = strings.ReplaceAll(strings.ReplaceAll(n.Flows, "proto=6", "proto=17"), "tcp(", "udp(")
	n.Offload.Conntrack = strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(ct, "tcp,", "udp,"), ",protoinfo=(state=ESTABLISHED)", ""), ",orig_offloaded:yes", "")
	if p := analyze(t, n).Paths[0]; p.Status != "pending" || p.Eligible {
		t.Fatal(p)
	}
	n.Offload.Config = map[string]string{"hw-offload-ct-unidir-udp-enabled": "true"}
	if p := analyze(t, n).Paths[0]; !p.CTProblem {
		t.Fatal(p)
	}
}
func TestCTRepeatedFailureAndRecovery(t *testing.T) {
	var s Store
	for i := 0; i < 4; i++ {
		n := node(start.Add(time.Duration(i)*30*time.Second), uint64(100+i*10), 0, "yes", "ct(zone=7),2")
		n.Offload.Conntrack = strings.Replace(ct, ",orig_offloaded:yes", "", 1)
		issues := s.Update(analyze(t, n))
		if (len(issues) > 0) != (i == 3) {
			t.Fatal(i, issues)
		}
	}
	s.Update(analyze(t, node(start.Add(2*time.Minute), 150, 0, "yes", "ct(zone=7),2")))
	if s.Report(Options{}).Issues != 0 {
		t.Fatal("CT recovery did not clear issue")
	}
}

func TestReportRetentionAndQueryBounds(t *testing.T) {
	var s Store
	r := model.OffloadReport{}
	for i := 0; i < 4100; i++ {
		r.Paths = append(r.Paths, model.OffloadPath{ID: fmt.Sprint(i), Node: "node-a", Network: "blue"})
	}
	s.Update(r)
	result := s.Report(Options{Limit: 1000})
	if len(result.Paths) != 100 || result.Total != 4000 || result.Omitted != 4000 || len(s.history) != 4000 {
		t.Fatal(len(result.Paths), result.Total, result.Omitted, len(s.history))
	}
	r = model.OffloadReport{Paths: []model.OffloadPath{{ID: "large", Stages: []model.OffloadStage{{Raw: strings.Repeat("x", 17<<20)}}}}}
	s.Update(r)
	result = s.Report(Options{})
	if len(result.Paths) != 0 || result.Omitted != 1 || len(s.history) != 0 {
		t.Fatal(result, len(s.history))
	}
}
