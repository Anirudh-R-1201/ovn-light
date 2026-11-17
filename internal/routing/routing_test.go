// SPDX-License-Identifier: Apache-2.0
package routing_test

import (
	"strings"
	"testing"
	"time"

	"github.com/trozet/ovn-light/internal/app"
	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/routing"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestAdvertisementsRequireRuntimeEvidence(t *testing.T) {
	for _, tc := range []struct {
		name            string
		complete, stale bool
		advertised      []string
		want            string
	}{
		{"advertised", true, false, []string{"10.244.0.0/24"}, "Locally advertised"},
		{"missing", true, false, nil, "Not advertised"},
		{"incomplete", false, false, nil, "Configured"},
		{"stale", true, true, nil, "Configured"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := app.Demo()
			s.Nodes[0].Routing.Peers[0].Advertised = tc.advertised
			s.Nodes[0].Routing.Peers[0].Complete = tc.complete
			if tc.stale {
				s.Nodes[0].Routing.CapturedAt = s.CapturedAt.Add(-3 * time.Minute)
			}
			r := routing.Analyze(s, model.View{}, nil)
			for _, p := range r.Peers {
				if p.Node == "kind-worker" && p.VRF == "default" {
					if len(p.Prefixes) != 1 || p.Prefixes[0].State != tc.want || p.Prefixes[0].Kind != "PodNetwork" {
						t.Fatalf("%+v", p)
					}
					return
				}
			}
			t.Fatal("default peer missing")
		})
	}
}
func TestRoutingNetworkIsolationAndStaleResponse(t *testing.T) {
	s := app.Demo()
	r := routing.Analyze(s, model.View{}, nil)
	f := routing.Filter(r, routing.Options{Network: "cluster/blue"})
	if len(f.Peers) != 1 || f.Peers[0].Address != "203.0.113.1" || f.Peers[0].Prefixes[0].Kind != "PodNetwork" || len(f.Uplinks) != 1 || len(f.Advertisements) != 1 {
		t.Fatalf("%+v", f)
	}
	f.Peers[0].Prefixes[0].State = "corrupted"
	again := routing.Filter(r, routing.Options{Network: "cluster/blue", Stale: true})
	if again.Peers[0].Prefixes[0].State == "corrupted" || len(again.Issues) != 0 || !again.Stale {
		t.Fatal("response mutated stored evidence")
	}
	if len(routing.Filter(r, routing.Options{Node: "absent"}).Peers) != 0 {
		t.Fatal("node filter leaked")
	}
	s.Inventory.DiagnosticErrors = map[string]string{"frrconfigurations": "forbidden"}
	s.Inventory.Errors = []string{"read adminnetworkpolicies: forbidden"}
	r = routing.Analyze(s, model.View{}, nil)
	if r.Capabilities["frrconfigurations"] != "Collection failed" || r.Capabilities["adminnetworkpolicies"] != "Collection failed" {
		t.Fatal(r.Capabilities)
	}
}
func TestEgressSelectionAndSNATScope(t *testing.T) {
	s := app.Demo()
	r := routing.Analyze(s, model.View{}, nil)
	if len(r.Egress) != 1 || r.Egress[0].PodCount != 1 || len(r.Egress[0].Paths) != 1 {
		t.Fatalf("%+v", r.Egress)
	}
	p := r.Egress[0].Paths[0]
	if !p.Programmed || p.ObservedAtEgress || len(p.Traffic) != 0 {
		t.Fatalf("assignment was confused with traffic: %+v", p)
	}
	delta := uint64(3)
	o := model.TrafficObservation{Node: p.Source.Node, Network: p.Source.Network, Source: p.Source, Destination: model.Endpoint{Network: p.Source.Network, IP: "203.0.113.10"}, Verdict: "forward", PacketDelta: &delta}
	r = routing.Analyze(s, model.View{Traffic: []model.TrafficObservation{o}}, nil)
	if len(r.Egress[0].Paths[0].Traffic) != 1 || r.Egress[0].Paths[0].ObservedAtEgress {
		t.Fatal("source observation proved arrival")
	}
	o.Node = p.Assignment.Node
	o.Network = "other"
	r = routing.Analyze(s, model.View{Traffic: []model.TrafficObservation{o}}, nil)
	if len(r.Egress[0].Paths[0].Traffic) != 0 {
		t.Fatal("traffic crossed network scopes")
	}
	s.Nodes[1].Routing.Routers[0]["name"] = "GR_other_kind-worker2"
	r = routing.Analyze(s, model.View{}, nil)
	if r.Egress[0].Paths[0].Programmed {
		t.Fatal("NAT crossed gateway network scopes")
	}
	_ = unstructured.SetNestedMap(s.Inventory.Resources["egressips"][0].Object, map[string]any{"matchLabels": map[string]any{"app": "does-not-match"}}, "spec", "podSelector")
	r = routing.Analyze(s, model.View{}, nil)
	if r.Egress[0].PodCount != 0 {
		t.Fatal("pod and namespace selectors were not intersected")
	}
}
func TestEgressAssignmentsAndUnavailableNAT(t *testing.T) {
	s := app.Demo()
	before := routing.Analyze(s, model.View{}, nil)
	items := []any{map[string]any{"egressIP": "198.51.100.25", "node": "kind-worker"}, map[string]any{"egressIP": "2001:db8::25", "node": "kind-worker2"}}
	_ = unstructured.SetNestedSlice(s.Inventory.Resources["egressips"][0].Object, items, "status", "items")
	for i := range s.Nodes {
		s.Nodes[i].Routing = model.RoutingEvidence{}
	}
	r := routing.Analyze(s, model.View{}, &before)
	if r.Egress[0].Assignments[0].PreviousNode != "kind-worker2" || len(r.Egress[0].Assignments) != 2 || len(r.Egress[0].Paths) != 1 || r.Egress[0].Paths[0].Programmed {
		t.Fatalf("%+v", r.Egress[0])
	}
	if !strings.Contains(strings.Join(r.Egress[0].Warnings, " "), "Multiple") {
		t.Fatal("ambiguous assignments hidden")
	}
}

func TestEgressNetworkIsKnownBeforePodsExist(t *testing.T) {
	s := app.Demo()
	s.Inventory.Pods = nil
	r := routing.Analyze(s, model.View{}, nil)
	if len(r.Egress) != 1 || len(r.Egress[0].Networks) != 1 || r.Egress[0].Networks[0] != "default" || len(r.Egress[0].Paths) != 0 {
		t.Fatalf("%+v", r.Egress)
	}
}

func TestUplinkDiscoveryAndConditions(t *testing.T) {
	s := app.Demo()
	for _, tc := range []struct {
		name       string
		conditions []any
		want       string
	}{
		{"ready", []any{map[string]any{"type": "Resolved", "status": "True"}, map[string]any{"type": "GatewayReady", "status": "True"}}, "Ready"},
		{"unresolved", []any{map[string]any{"type": "Resolved", "status": "False", "reason": "HostInterfaceNotFound"}}, "Not ready"},
		{"missing", nil, "Unknown"},
		{"old", []any{map[string]any{"type": "Resolved", "status": "True", "observedGeneration": int64(1)}, map[string]any{"type": "GatewayReady", "status": "True", "observedGeneration": int64(1)}}, "Unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := &s.Inventory.Resources["uplinkstates"][0]
			u.SetGeneration(2)
			_ = unstructured.SetNestedSlice(u.Object, tc.conditions, "status", "conditions")
			r := routing.Filter(routing.Analyze(s, model.View{}, nil), routing.Options{Network: "cluster/blue"})
			if len(r.Uplinks) != 1 || r.Uplinks[0].Ready != tc.want || r.Uplinks[0].VRF != "blue" || r.Uplinks[0].Bridge != "br-blue" {
				t.Fatalf("%+v", r.Uplinks)
			}
		})
	}
}
