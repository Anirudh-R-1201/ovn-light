// SPDX-License-Identifier: Apache-2.0
package topology

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/trozet/ovn-light/internal/model"
)

const MaxConnections = 2000
const MaxFrames = 60
const Retention = 10 * time.Minute

type Options struct {
	Network, Node, Level, Filter, Sort, Edge string
	Window                                   time.Duration
	Limit                                    int
}
type Counters struct {
	Packets   uint64    `json:"packets"`
	Bytes     uint64    `json:"bytes"`
	Rate      *float64  `json:"bytesPerSecond,omitempty"`
	Start     time.Time `json:"start,omitempty"`
	End       time.Time `json:"end,omitempty"`
	Observed  bool      `json:"observed"`
	Offloaded bool      `json:"offloaded"`
	Software  bool      `json:"software"`
}
type Point struct {
	At       time.Time `json:"at"`
	Source   *float64  `json:"sourceBytesPerSecond,omitempty"`
	Receiver *float64  `json:"receiverBytesPerSecond,omitempty"`
	Drops    uint64    `json:"drops"`
}
type Connection struct {
	ID              string                     `json:"id"`
	Network         string                     `json:"network"`
	Source          model.Endpoint             `json:"source"`
	Destination     model.Endpoint             `json:"destination"`
	Protocol        string                     `json:"protocol"`
	Sent            Counters                   `json:"sent"`
	Received        Counters                   `json:"received"`
	Local           Counters                   `json:"local"`
	Dropped         Counters                   `json:"dropped"`
	Status          string                     `json:"status"`
	Partial         bool                       `json:"partial"`
	Shared          bool                       `json:"shared"`
	CachedDrop      bool                       `json:"cachedDrop"`
	Observations    []model.TrafficObservation `json:"observations,omitempty"`
	History         []Point                    `json:"history,omitempty"`
	FindingIDs      []string                   `json:"findingIDs,omitempty"`
	LastSeen        time.Time                  `json:"lastSeen"`
	missing         int
	receiverHealthy bool
}
type Node struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Node     string          `json:"node"`
	Network  string          `json:"network"`
	Pods     int             `json:"pods"`
	Endpoint *model.Endpoint `json:"endpoint,omitempty"`
}
type Edge struct {
	ID             string       `json:"id"`
	Source         string       `json:"source"`
	Destination    string       `json:"destination"`
	Network        string       `json:"network"`
	Status         string       `json:"status"`
	Connections    int          `json:"connections"`
	SourceRate     *float64     `json:"sourceBytesPerSecond,omitempty"`
	ReceiverRate   *float64     `json:"receiverBytesPerSecond,omitempty"`
	LocalRate      *float64     `json:"localBytesPerSecond,omitempty"`
	DroppedPackets uint64       `json:"droppedPackets"`
	Partial        bool         `json:"partial"`
	DropNodes      []string     `json:"dropNodes,omitempty"`
	Members        []Connection `json:"members,omitempty"`
}
type Graph struct {
	CollectedAt         time.Time `json:"collectedAt"`
	WindowSeconds       int       `json:"windowSeconds"`
	Nodes               []Node    `json:"nodes"`
	Edges               []Edge    `json:"edges"`
	TotalEdges          int       `json:"totalEdges"`
	HiddenEdges         int       `json:"hiddenEdges"`
	Truncated           bool      `json:"truncated"`
	Warnings            []string  `json:"warnings"`
	RetainedConnections int       `json:"retainedConnections"`
	Samples             int       `json:"samples"`
}
type frame struct {
	at          time.Time
	connections map[string]Connection
	truncated   bool
}

// Store keeps bounded aggregates, not raw dumps or packet logs. Its owner
// serializes updates and snapshots; a slow browser never queues collection work.
type Store struct {
	frames []frame
	nodes  []model.NodeStatus
	pods   []model.Endpoint
}

// Frames and inventory are immutable after Update publishes them. Copying the
// frame slice lets API queries run without holding the app's state lock.
func (s *Store) Snapshot() Store {
	return Store{frames: append([]frame{}, s.frames...), nodes: s.nodes, pods: s.pods}
}

func id(parts ...string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(parts, "\x00"))))[:24]
}
func endpointKey(e model.Endpoint) string { return strings.Join([]string{e.Node, e.UID, e.IP}, "|") }
func connectionID(o model.TrafficObservation) string {
	return id(o.Network, endpointKey(o.Source), endpointKey(o.Destination), o.Protocol, fmt.Sprint(o.Destination.Port))
}

func add(c *Counters, o model.TrafficObservation) {
	c.Observed = true
	c.Offloaded = c.Offloaded || o.Offloaded
	c.Software = c.Software || !o.Offloaded
	if o.Shared || o.PacketDelta == nil || o.ByteDelta == nil || !o.Start.Before(o.End) {
		return
	}
	c.Packets += *o.PacketDelta
	c.Bytes += *o.ByteDelta
	if c.Start.IsZero() || o.Start.Before(c.Start) {
		c.Start = o.Start
	}
	if o.End.After(c.End) {
		c.End = o.End
	}
	r := float64(c.Bytes) / c.End.Sub(c.Start).Seconds()
	c.Rate = &r
}
func merge(c *Counters, b Counters) {
	c.Observed = c.Observed || b.Observed
	c.Offloaded = c.Offloaded || b.Offloaded
	c.Software = c.Software || b.Software
	if b.Rate == nil {
		return
	}
	c.Packets += b.Packets
	c.Bytes += b.Bytes
	if c.Start.IsZero() || b.Start.Before(c.Start) {
		c.Start = b.Start
	}
	if b.End.After(c.End) {
		c.End = b.End
	}
	r := float64(c.Bytes) / c.End.Sub(c.Start).Seconds()
	c.Rate = &r
}
func union(a, b []string, limit int) []string {
	for _, s := range b {
		found := false
		for _, v := range a {
			if s == v {
				found = true
				break
			}
		}
		if !found && len(a) < limit {
			a = append(a, s)
		}
	}
	return a
}

func (s *Store) Update(v model.View) {
	s.nodes, s.pods = v.Nodes, v.Pods
	cutoff := v.CollectedAt.Add(-Retention)
	for len(s.frames) > 0 && (!s.frames[0].at.After(cutoff) || len(s.frames) >= MaxFrames) {
		s.frames = s.frames[1:]
	}
	if len(s.frames) > 0 && !v.CollectedAt.After(s.frames[len(s.frames)-1].at) {
		return
	}
	known := map[string]bool{}
	for _, f := range s.frames {
		for k := range f.connections {
			known[k] = true
		}
	}
	f := frame{at: v.CollectedAt, connections: map[string]Connection{}}
	observations := append([]model.TrafficObservation{}, v.Traffic...)
	sort.SliceStable(observations, func(i, j int) bool {
		a, b := observations[i], observations[j]
		if (a.Verdict == "drop") != (b.Verdict == "drop") {
			return a.Verdict == "drop"
		}
		return a.CounterID < b.CounterID
	})
	seen := map[string]bool{}
	for _, o := range observations {
		if seen[o.CounterID] {
			continue
		}
		seen[o.CounterID] = true
		k := connectionID(o)
		if !known[k] && len(known) >= MaxConnections {
			f.truncated = true
			continue
		}
		known[k] = true
		c, ok := f.connections[k]
		if !ok {
			o.Source.Labels, o.Destination.Labels = nil, nil
			c = Connection{ID: k, Network: o.Network, Source: o.Source, Destination: o.Destination, Protocol: o.Protocol}
		}
		c.Shared = c.Shared || o.Shared
		c.Partial = c.Partial || o.Partial || o.Shared
		c.FindingIDs = union(c.FindingIDs, o.FindingIDs, 16)
		if o.End.After(c.LastSeen) {
			c.LastSeen = o.End
		}
		if len(c.Observations) < 8 {
			o.Source.Labels, o.Destination.Labels = nil, nil
			if len(o.Warnings) > 4 {
				o.Warnings = o.Warnings[:4]
			}
			c.Observations = append(c.Observations, o)
		}
		if o.Verdict == "drop" {
			add(&c.Dropped, o)
			c.CachedDrop = true
		} else {
			switch o.Location {
			case "source":
				add(&c.Sent, o)
			case "destination":
				add(&c.Received, o)
			case "local":
				add(&c.Local, o)
			default:
				c.Partial = true
			}
		}
		c.receiverHealthy = s.healthy(c.Destination.Node, v.CollectedAt)
		f.connections[k] = c
	}
	s.frames = append(s.frames, f)
}

func (s *Store) healthy(node string, now time.Time) bool {
	for _, n := range s.nodes {
		if n.Name == node {
			return n.Collection.FlowComplete && now.Sub(n.CapturedAt) <= 90*time.Second
		}
	}
	return false
}
func overlap(a, b Counters) bool {
	return a.Rate != nil && b.Rate != nil && a.Start.Before(b.End) && b.Start.Before(a.End)
}
func status(c Connection, healthy bool) string {
	if c.Dropped.Packets > 0 {
		return "drop"
	}
	if c.CachedDrop {
		return "cached-drop"
	}
	if c.Partial || !healthy {
		return "partial"
	}
	if c.Local.Packets > 0 {
		return "local"
	}
	if c.Sent.Packets > 0 && c.Received.Packets > 0 && overlap(c.Sent, c.Received) {
		return "both"
	}
	if c.Source.UID == "" || c.Destination.UID == "" {
		return "partial"
	}
	if c.missing >= 3 && c.Sent.End.Sub(c.Sent.Start) >= 60*time.Second && c.Sent.Packets > 0 && c.Received.Packets == 0 && c.Protocol != "" && c.Destination.Port > 0 {
		return "gap"
	}
	if c.Sent.Packets > 0 {
		return "source-only"
	}
	if c.Received.Packets > 0 {
		return "receiver-only"
	}
	return "cached"
}
func (s *Store) connections(o Options, now time.Time) (map[string]Connection, bool) {
	all := map[string]Connection{}
	truncated := false
	for _, f := range s.frames {
		if f.at.Before(now.Add(-o.Window)) {
			continue
		}
		truncated = truncated || f.truncated
		for k, c := range all {
			if _, ok := f.connections[k]; !ok {
				c.missing = 0
				all[k] = c
			}
		}
		for k, b := range f.connections {
			if o.Network != "" && b.Network != o.Network || o.Node != "" && b.Source.Node != o.Node && b.Destination.Node != o.Node {
				continue
			}
			c, ok := all[k]
			if !ok {
				c = Connection{ID: k, Network: b.Network, Source: b.Source, Destination: b.Destination, Protocol: b.Protocol}
			}
			merge(&c.Sent, b.Sent)
			merge(&c.Received, b.Received)
			merge(&c.Local, b.Local)
			merge(&c.Dropped, b.Dropped)
			c.Shared = c.Shared || b.Shared
			c.Partial = c.Partial || b.Partial
			c.CachedDrop = c.CachedDrop || b.CachedDrop
			c.FindingIDs = union(c.FindingIDs, b.FindingIDs, 16)
			c.LastSeen = b.LastSeen
			c.Observations = b.Observations
			if o.Edge != "" {
				c.History = append(c.History, Point{At: f.at, Source: b.Sent.Rate, Receiver: b.Received.Rate, Drops: b.Dropped.Packets})
			}
			if b.Sent.Packets > 0 && b.Received.Packets == 0 && b.Dropped.Packets == 0 && !b.Partial && b.receiverHealthy {
				c.missing++
			} else {
				c.missing = 0
			}
			all[k] = c
		}
	}
	for k, c := range all {
		c.Status = status(c, s.healthy(c.Destination.Node, now) && s.healthy(c.Source.Node, now))
		// A receiver's wildcarded port can cover this traffic. It cannot prove
		// delivery for this exact port, but it must suppress a missing-RX alarm.
		if c.Status == "gap" {
			for _, peer := range all {
				if peer.Received.Packets > 0 && c.Source.UID == peer.Source.UID && c.Destination.UID == peer.Destination.UID && c.Network == peer.Network && (peer.Protocol == "" || peer.Protocol == c.Protocol) && (peer.Destination.Port == 0 || peer.Destination.Port == c.Destination.Port) {
					c.Status = "partial"
					break
				}
			}
		}
		all[k] = c
	}
	return all, truncated
}
func node(e model.Endpoint, network, level string) Node {
	name := e.Node
	if name == "" {
		name = "Unresolved / external"
	}
	n := Node{ID: id(network, name), Name: name, Node: e.Node, Network: network}
	if level == "pods" {
		key := endpointKey(e)
		if e.UID != "" {
			key = e.Node + "|" + e.UID
		}
		n.ID = id(network, key)
		n.Endpoint = &e
		n.Name = e.Namespace + "/" + e.Pod
		if e.Pod == "" {
			n.Name = e.IP
			if n.Name == "" {
				n.Name = "Unresolved on " + name
			}
		}
	}
	return n
}
func priority(status string) int {
	switch status {
	case "drop":
		return 9
	case "gap":
		return 8
	case "cached-drop":
		return 7
	case "partial":
		return 6
	case "source-only", "receiver-only":
		return 5
	case "both", "local":
		return 4
	default:
		return 1
	}
}
func sumRate(a **float64, b *float64) {
	if b == nil {
		return
	}
	v := *b
	if *a != nil {
		v += **a
	}
	*a = &v
}
func rate(e Edge) float64 {
	var largest float64
	for _, r := range []*float64{e.SourceRate, e.ReceiverRate, e.LocalRate} {
		if r != nil && *r > largest {
			largest = *r
		}
	}
	return largest
}

func (s *Store) Graph(o Options, now time.Time) Graph {
	if o.Window <= 0 || o.Window > Retention {
		o.Window = 2 * time.Minute
	}
	if o.Limit <= 0 || o.Limit > 100 {
		o.Limit = 40
	}
	if o.Level != "pods" {
		o.Level = "nodes"
	}
	g := Graph{Nodes: []Node{}, Edges: []Edge{}, WindowSeconds: int(o.Window.Seconds()), Warnings: []string{}, Samples: len(s.frames)}
	if len(s.frames) > 0 {
		g.CollectedAt = s.frames[len(s.frames)-1].at
	}
	all, truncated := s.connections(o, now)
	g.Truncated = truncated
	g.RetainedConnections = len(all)
	nodes, edges := map[string]Node{}, map[string]Edge{}
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c := all[k]
		if o.Filter == "drop" && c.Status != "drop" && c.Status != "cached-drop" || o.Filter == "gap" && c.Status != "gap" && c.Status != "source-only" {
			continue
		}
		a, b := node(c.Source, c.Network, o.Level), node(c.Destination, c.Network, o.Level)
		nodes[a.ID], nodes[b.ID] = a, b
		key := id(c.Network, a.ID, b.ID)
		e, ok := edges[key]
		if !ok {
			e = Edge{ID: key, Source: a.ID, Destination: b.ID, Network: c.Network, Status: c.Status}
		}
		if priority(c.Status) > priority(e.Status) {
			e.Status = c.Status
		}
		e.Connections++
		e.Partial = e.Partial || c.Partial
		e.DroppedPackets += c.Dropped.Packets
		for _, o := range c.Observations {
			if o.Verdict == "drop" {
				e.DropNodes = union(e.DropNodes, []string{o.Node}, 8)
			}
		}
		sumRate(&e.SourceRate, c.Sent.Rate)
		sumRate(&e.ReceiverRate, c.Received.Rate)
		sumRate(&e.LocalRate, c.Local.Rate)
		if key == o.Edge && len(e.Members) < 50 {
			e.Members = append(e.Members, c)
		}
		edges[key] = e
	}
	for _, e := range edges {
		if o.Edge == "" || e.ID == o.Edge {
			g.Edges = append(g.Edges, e)
		}
	}
	sort.Slice(g.Edges, func(i, j int) bool {
		a, b := g.Edges[i], g.Edges[j]
		if o.Sort == "drops" && a.DroppedPackets != b.DroppedPackets {
			return a.DroppedPackets > b.DroppedPackets
		}
		if rate(a) != rate(b) {
			return rate(a) > rate(b)
		}
		return a.ID < b.ID
	})
	g.TotalEdges = len(g.Edges)
	if len(g.Edges) > o.Limit {
		g.HiddenEdges = len(g.Edges) - o.Limit
		g.Edges = g.Edges[:o.Limit]
	}
	used := map[string]bool{}
	for _, e := range g.Edges {
		used[e.Source] = true
		used[e.Destination] = true
	}
	pods := map[string]map[string]bool{}
	for _, p := range s.pods {
		if o.Network != "" && p.Network != o.Network {
			continue
		}
		n := node(p, p.Network, o.Level)
		if pods[n.ID] == nil {
			pods[n.ID] = map[string]bool{}
		}
		pods[n.ID][p.UID] = true
		if len(g.Edges) == 0 && len(used) < 24 && (o.Node == "" || p.Node == o.Node) {
			nodes[n.ID] = n
			used[n.ID] = true
		}
	}
	for k := range used {
		n := nodes[k]
		n.Pods = len(pods[k])
		g.Nodes = append(g.Nodes, n)
	}
	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].ID < g.Nodes[j].ID })
	if truncated {
		g.Warnings = append(g.Warnings, "Traffic history reached its 2,000-connection limit; some observations were omitted.")
	}
	missing := 0
	for _, n := range s.nodes {
		if !s.healthy(n.Name, now) {
			missing++
		}
	}
	if missing > 0 {
		g.Warnings = append(g.Warnings, fmt.Sprintf("%d collectors have incomplete or stale flow evidence; inspect Collectors for coverage.", missing))
	}
	if now.Sub(g.CollectedAt) > 90*time.Second {
		g.Warnings = append(g.Warnings, "Collection is stale; cached observations do not establish current reachability.")
	}
	g.Warnings = append(g.Warnings, "Rates cover observed counter intervals. Source and receiver counters are separate; no packet-loss percentage is inferred. Short-lived or masked flows may be absent.")
	return g
}
