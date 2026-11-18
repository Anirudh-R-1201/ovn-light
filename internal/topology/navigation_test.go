// SPDX-License-Identifier: Apache-2.0
package topology

import (
	"fmt"
	"testing"
	"time"

	"github.com/trozet/ovn-light/internal/model"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func largeTopology() (Store, time.Time) {
	at := time.Now()
	v := model.View{CollectedAt: at}
	inv := model.Inventory{}
	for i := 0; i < 2000; i++ {
		name := fmt.Sprintf("node-%04d", i)
		ns := "busy"
		if i == 1999 {
			ns = "quiet"
		}
		o := observation(name, "source", at)
		o.CounterID = name
		o.Source = model.Endpoint{UID: name, Pod: "client", Namespace: ns, Node: name, Network: "blue"}
		o.Destination = model.Endpoint{UID: "server", Pod: "server", Namespace: "service", Node: "node-0000", Network: "blue", Port: 443}
		if i == 1999 {
			o.Verdict = "drop"
		}
		v.Traffic = append(v.Traffic, o)
		v.Pods = append(v.Pods, o.Source)
		v.Nodes = append(v.Nodes, model.NodeStatus{Name: name, CapturedAt: at, Collection: model.CollectionStats{FlowComplete: true}})
		inv.Nodes = append(inv.Nodes, core.Node{ObjectMeta: meta.ObjectMeta{Name: name, Labels: map[string]string{"topology.kubernetes.io/zone": fmt.Sprintf("zone-%d", i%4)}}})
	}
	var s Store
	s.Inventory(inv)
	s.Update(v)
	return s, at
}
func TestLargeTopologyScopeAndBudget(t *testing.T) {
	s, at := largeTopology()
	g := s.Graph(Options{Limit: 12}, at)
	if len(g.Edges) != 12 || g.TotalEdges != 2000 || g.HiddenEdges != 1988 || g.Edges[0].Status != "drop" {
		t.Fatalf("budget or issue priority: edges=%d total=%d hidden=%d first=%s", len(g.Edges), g.TotalEdges, g.HiddenEdges, g.Edges[0].Status)
	}
	g = s.Graph(Options{Limit: 1, Namespace: "quiet"}, at)
	if len(g.Edges) != 1 || g.Edges[0].Status != "drop" || g.HiddenEdges != 0 {
		t.Fatal("namespace filter must precede limit", g)
	}
	g = s.Graph(Options{Level: "zones", Limit: 12}, at)
	if len(g.Nodes) != 4 || len(g.Edges) != 4 {
		t.Fatal("zone grouping", len(g.Nodes), len(g.Edges))
	}
	g = s.Graph(Options{Nodes: "node-1999,node-0000", Paths: "between"}, at)
	if len(g.Edges) != 2 {
		t.Fatal("between selected nodes", len(g.Edges))
	}
	g = s.Graph(Options{NodeSelector: "topology.kubernetes.io/zone=zone-3", Paths: "between"}, at)
	if len(g.Edges) != 0 {
		t.Fatal("node labels must apply to both endpoints")
	}
	g = s.Graph(Options{Paths: "none", Namespace: "quiet", Limit: 8}, at)
	if len(g.Edges) != 0 || len(g.Nodes) == 0 || g.HiddenEdges != 1 {
		t.Fatal("hide paths lost scope", g)
	}
}
func BenchmarkTopology2000Nodes(b *testing.B) {
	s, at := largeTopology()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		s.Graph(Options{Level: "zones", Limit: 12}, at)
	}
}
