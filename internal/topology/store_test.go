// SPDX-License-Identifier: Apache-2.0
package topology

import (
	"fmt"
	"testing"
	"time"

	"github.com/trozet/ovn-light/internal/model"
)

func observation(node, location string, at time.Time) model.TrafficObservation {
	packets, bytes := uint64(10), uint64(1000)
	return model.TrafficObservation{CounterID: node + "/ufid", Node: node, Network: "blue", Source: model.Endpoint{UID: "a", Pod: "a", Node: "node-a", Network: "blue"}, Destination: model.Endpoint{UID: "b", Pod: "b", Node: "node-b", Network: "blue", Port: 443}, Protocol: "TCP", Verdict: "forward", Location: location, PacketDelta: &packets, ByteDelta: &bytes, Start: at.Add(-30 * time.Second), End: at}
}
func view(at time.Time, observations ...model.TrafficObservation) model.View {
	return model.View{CollectedAt: at, Traffic: observations, Nodes: []model.NodeStatus{{Name: "node-a", CapturedAt: at, Collection: model.CollectionStats{FlowComplete: true}}, {Name: "node-b", CapturedAt: at, Collection: model.CollectionStats{FlowComplete: true}}}}
}
func only(t *testing.T, s *Store, at time.Time) Connection {
	t.Helper()
	all, _ := s.connections(Options{Window: Retention}, at)
	if len(all) != 1 {
		t.Fatalf("connections: %+v", all)
	}
	for _, c := range all {
		return c
	}
	panic("unreachable")
}
func TestIndependentObservationPoints(t *testing.T) {
	var s Store
	at := time.Now()
	tx, rx := observation("node-a", "source", at), observation("node-b", "destination", at)
	s.Update(view(at, tx, tx, rx))
	c := only(t, &s, at)
	if c.Status != "both" || c.Sent.Packets != 10 || c.Received.Packets != 10 || *c.Sent.Rate != 1000.0/30 {
		t.Fatalf("double-counted duplicate or recirculation: %+v", c)
	}
	g := s.Graph(Options{}, at)
	if len(g.Edges) != 1 || *g.Edges[0].SourceRate != *c.Sent.Rate {
		t.Fatal(g)
	}
}
func TestSharedCounterHasNoConnectionRate(t *testing.T) {
	var s Store
	at := time.Now()
	o := observation("node-a", "source", at)
	o.Shared = true
	s.Update(view(at, o))
	c := only(t, &s, at)
	if c.Sent.Rate != nil || c.Sent.Packets != 0 || c.Status != "partial" {
		t.Fatal(c)
	}
}
func TestMissingReceiverAndCollectorCoverage(t *testing.T) {
	var s Store
	start := time.Now()
	var at time.Time
	for i := 0; i < 3; i++ {
		at = start.Add(time.Duration(i) * 30 * time.Second)
		s.Update(view(at, observation("node-a", "source", at)))
	}
	if c := only(t, &s, at); c.Status != "gap" {
		t.Fatal(c.Status)
	}
	s.nodes[1].Collection.FlowComplete = false
	if c := only(t, &s, at); c.Status != "partial" {
		t.Fatal("collector gap became packet loss", c.Status)
	}
	s.nodes[1].Collection.FlowComplete = true
	at = at.Add(30 * time.Second)
	o := observation("node-b", "destination", at)
	o.Destination.Port = 0
	s.Update(view(at, observation("node-a", "source", at), o))
	all, _ := s.connections(Options{Window: Retention}, at)
	for _, c := range all {
		if c.Status == "gap" {
			t.Fatal("wildcard receiver evidence was ignored")
		}
	}
}
func TestDropsRequireDeltasAndExpire(t *testing.T) {
	var s Store
	at := time.Now()
	o := observation("node-b", "destination", at)
	o.Verdict = "drop"
	o.PacketDelta = nil
	o.ByteDelta = nil
	s.Update(view(at, o))
	if c := only(t, &s, at); c.Status != "cached-drop" || c.Dropped.Packets != 0 {
		t.Fatal(c)
	}
	at = at.Add(30 * time.Second)
	o = observation("node-b", "destination", at)
	o.Verdict = "drop"
	s.Update(view(at, o))
	if c := only(t, &s, at); c.Status != "drop" || c.Dropped.Packets != 10 {
		t.Fatal(c)
	}
	s.Update(view(at.Add(Retention + time.Second)))
	if len(s.Graph(Options{}, at.Add(Retention+time.Second)).Edges) != 0 {
		t.Fatal("expired traffic remained live")
	}
}
func TestNetworksAndUIDsRemainSeparate(t *testing.T) {
	var s Store
	at := time.Now()
	a, b := observation("node-a", "source", at), observation("node-b", "destination", at)
	b.Network = "red"
	s.Update(view(at, a, b))
	g := s.Graph(Options{Network: "blue"}, at)
	if len(g.Edges) != 1 || g.Edges[0].ReceiverRate != nil {
		t.Fatal(g)
	}
}
func TestHistoryAndGraphLimits(t *testing.T) {
	var s Store
	at := time.Now()
	v := view(at)
	for i := 0; i < MaxConnections+50; i++ {
		o := observation("node-a", "source", at)
		o.CounterID = fmt.Sprint(i)
		o.Source.UID = fmt.Sprint(i)
		o.Source.Node = fmt.Sprint(i)
		v.Traffic = append(v.Traffic, o)
	}
	s.Update(v)
	g := s.Graph(Options{Limit: 8}, at)
	if !g.Truncated || g.RetainedConnections != MaxConnections || len(g.Edges) != 8 || g.HiddenEdges != MaxConnections-8 {
		t.Fatal(g.Truncated, g.RetainedConnections, len(g.Edges), g.HiddenEdges)
	}
	for i := 1; i < MaxFrames+5; i++ {
		s.Update(view(at.Add(time.Duration(i) * time.Second)))
	}
	if len(s.frames) != MaxFrames {
		t.Fatal(len(s.frames))
	}
}
func BenchmarkTopology2000Connections(b *testing.B) {
	var s Store
	at := time.Now()
	v := view(at)
	for i := 0; i < MaxConnections; i++ {
		o := observation("node-a", "source", at)
		o.CounterID = fmt.Sprint(i)
		o.Source.UID = fmt.Sprint(i)
		v.Traffic = append(v.Traffic, o)
	}
	for i := 0; i < 20; i++ {
		v.CollectedAt = at.Add(time.Duration(i) * 30 * time.Second)
		s.Update(v)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Graph(Options{Window: Retention}, v.CollectedAt)
	}
}
