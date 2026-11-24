// SPDX-License-Identifier: Apache-2.0
package history

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/policy"
)

// Record describes one counter at one observation point. A nil delta means
// the counter was already populated when its baseline was first observed.
type Record struct {
	At           time.Time      `json:"at"`
	Start        *time.Time     `json:"start,omitempty"`
	Node         string         `json:"node"`
	Network      string         `json:"network"`
	Verdict      string         `json:"verdict"`
	Source       model.Endpoint `json:"source"`
	Destination  model.Endpoint `json:"destination"`
	Protocol     string         `json:"protocol,omitempty"`
	Location     string         `json:"location,omitempty"`
	CounterID    string         `json:"counterID"`
	Packets      uint64         `json:"cachedPackets"`
	Delta        *uint64        `json:"packetDelta,omitempty"`
	ByteDelta    *uint64        `json:"byteDelta,omitempty"`
	Shared       bool           `json:"shared,omitempty"`
	Partial      bool           `json:"partial,omitempty"`
	CounterScope string         `json:"counterScope,omitempty"`
	Causes       []Cause        `json:"causes,omitempty"`
}

// Cause keeps the denying ACL alongside policy metadata from the same collection.
type Cause struct {
	Kind                string   `json:"kind"`
	Namespace           string   `json:"namespace,omitempty"`
	Name                string   `json:"name,omitempty"`
	Direction           string   `json:"direction,omitempty"`
	Rule                string   `json:"rule,omitempty"`
	RuleName            string   `json:"ruleName,omitempty"`
	ACL                 string   `json:"acl"`
	Action              string   `json:"action"`
	Match               string   `json:"match,omitempty"`
	Selecting           []string `json:"selecting,omitempty"`
	SelectionIncomplete bool     `json:"selectionIncomplete,omitempty"`
}

type batch struct {
	entries        map[string][][2]string
	bytes, omitted int
}

const batchLimit = 1 << 20
const lineLimit = 16 << 10

func records(v model.View, inv model.Inventory) batch {
	b := batch{entries: make(map[string][][2]string)}
	seen := map[string]bool{}
	add := func(r Record) {
		if r.Delta != nil && *r.Delta == 0 || r.Delta == nil && r.Packets == 0 {
			return
		}
		if b.bytes >= batchLimit {
			b.omitted++
			return
		}
		r.Source.Labels, r.Destination.Labels = nil, nil
		line, err := json.Marshal(r)
		if err != nil || len(line) > lineLimit {
			b.omitted++
			return
		}
		key := string(line)
		if seen[key] {
			return
		}
		if b.bytes+len(key) > batchLimit {
			b.omitted++
			return
		}
		seen[key] = true
		b.bytes += len(key)
		b.entries[r.Verdict] = append(b.entries[r.Verdict], [2]string{nanos(r.At), key})
	}
	observations := make(map[string]model.TrafficObservation, len(v.Traffic))
	for _, o := range v.Traffic {
		observations[o.CounterID] = o
	}
	type attachment struct{ uid, network string }
	endpoints := map[attachment]model.Endpoint{}
	for _, e := range v.Pods {
		endpoints[attachment{e.UID, e.Network}] = e
	}
	type selection struct {
		names      []string
		incomplete bool
	}
	type lookup struct {
		attachment
		direction string
	}
	cache := map[lookup]selection{}
	linked := map[string]bool{}
	for _, f := range v.Findings {
		if b.bytes >= batchLimit {
			b.omitted++
			continue
		}
		o, found := observations[f.CounterID]
		r := fromObservation(o)
		if !found {
			r = Record{At: f.ObservedAt, Node: f.Node, Packets: f.Packets, Delta: f.Delta, CounterID: f.CounterID}
		}
		linked[f.CounterID] = true
		r.Verdict, r.Protocol, r.Source, r.Destination = "drop", f.Protocol, f.Source, f.Destination
		if f.Source.Network != "" {
			r.Network = f.Source.Network
		} else if f.Destination.Network != "" {
			r.Network = f.Destination.Network
		}
		r.Shared = r.Shared || f.SharedCounter
		r.Partial = r.Partial || f.Confidence != "connection"
		for _, c := range f.Causes {
			item := Cause{Kind: c.Type, Namespace: c.Namespace, Name: c.Name, Direction: c.Direction, Rule: c.Rule, ACL: c.ACL, Action: c.Action, Match: c.Match}
			if c.Admin != nil {
				item.RuleName = c.Admin.RuleName
			}
			if c.Type == "NetpolNamespace" {
				target := f.Destination
				if strings.EqualFold(c.Direction, "egress") {
					target = f.Source
				}
				k := lookup{attachment{target.UID, target.Network}, c.Direction}
				e, ok := endpoints[k.attachment]
				if ok && e.Namespace == c.Namespace && target.UID != "" {
					selected, ok := cache[k]
					if !ok {
						names, err := policy.SelectingPolicies(inv, e, c.Direction)
						selected = selection{names[:min(24, len(names))], err != nil || len(names) > 24}
						cache[k] = selected
					}
					item.Selecting, item.SelectionIncomplete = selected.names, selected.incomplete
				} else {
					item.SelectionIncomplete = true
				}
			}
			r.Causes = append(r.Causes, item)
		}
		add(r)
	}
	for _, o := range v.Traffic {
		if !linked[o.CounterID] {
			add(fromObservation(o))
		}
	}
	return b
}

func fromObservation(o model.TrafficObservation) Record {
	r := Record{At: o.End, Node: o.Node, Network: o.Network, Verdict: o.Verdict, Source: o.Source, Destination: o.Destination, Protocol: o.Protocol, Location: o.Location, CounterID: o.CounterID, Packets: o.Packets, Delta: o.PacketDelta, ByteDelta: o.ByteDelta, Shared: o.Shared, Partial: o.Partial, CounterScope: o.CounterScope}
	if !o.Start.IsZero() {
		r.Start = &o.Start
	}
	return r
}
