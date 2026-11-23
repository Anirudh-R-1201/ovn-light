// SPDX-License-Identifier: Apache-2.0
package ovn

import (
	"fmt"
	"strings"
	"time"

	"github.com/trozet/ovn-light/internal/datapath"
	"github.com/trozet/ovn-light/internal/model"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// AnalysisContext is shared across nodes and reused until endpoint or policy
// identity changes. It excludes Kubernetes pod specs and container environment.
type AnalysisContext struct {
	Attachments []Attachment
	Hosts       map[string]string
	Inventory   model.Inventory
}

func Project(inv model.Inventory) AnalysisContext {
	x := AnalysisContext{Attachments: Attachments(inv), Hosts: map[string]string{}}
	x.Inventory.Resources = make(map[string][]unstructured.Unstructured)
	for _, k := range []string{"egressfirewalls", "adminnetworkpolicies", "baselineadminnetworkpolicies"} {
		x.Inventory.Resources[k] = inv.Resources[k]
	}
	for _, p := range inv.Pods {
		if p.Status.HostIP != "" {
			x.Hosts[p.Status.HostIP] = p.Spec.NodeName
		}
	}
	return x
}

func Summarize(n model.NodeSnapshot, previous *model.Snapshot, x AnalysisContext, sample datapath.Sample) model.NodeSnapshot {
	s := model.Snapshot{Inventory: x.Inventory, Nodes: []model.NodeSnapshot{n}, CapturedAt: n.CapturedAt}
	v := analyze(s, previous, x.Attachments, x.Hosts, &sample)
	m := &model.NodeSummary{Flows: v.Nodes[0].Flows, Offloaded: v.Nodes[0].Offloaded, Findings: v.Findings, Traffic: groupTraffic(v.Traffic), OffloadNode: v.Offload.Nodes[0]}
	for _, p := range v.Offload.Paths {
		m.Paths = append(m.Paths, model.CollectorOffloadPath{Path: p, Signature: p.Signature, Datapath: p.Datapath, Complete: p.SampleComplete, Eligible: p.Eligible, CTProblem: p.CTProblem, DiagnosticsAt: p.DiagnosticsAt})
	}
	n.Summary = m
	n.Collection.Agent = true
	n.Collection.TrafficGroups = len(m.Traffic)
	n.Flows, n.Ports, n.Detraces, n.Bindings, n.Datapaths, n.LogicalFlows, n.ACLs, n.Offload = "", "", nil, nil, nil, nil, nil, model.OffloadEvidence{}
	return n
}

// Combine independent terminal counters only when their observation point,
// interval and evidence quality agree. Keep shared counters individually
// identifiable for drop inspection and exclude them from per-pod rates.
func groupTraffic(obs []model.TrafficObservation) []model.TrafficObservation {
	type key struct {
		identity, scope, warnings  string
		offload, partial, measured bool
		start, end                 time.Time
	}
	seen := map[key]int{}
	var groups []model.TrafficObservation
	for _, o := range obs {
		o.Source.Labels, o.Destination.Labels = nil, nil
		k := key{trafficIdentity(o), o.CounterScope, strings.Join(o.Warnings, "\x00"), o.Offloaded, o.Partial, o.PacketDelta != nil && o.ByteDelta != nil, o.Start, o.End}
		i, exists := seen[k]
		if o.Shared || len(o.FindingIDs) > 0 {
			groups = append(groups, o)
			continue
		}
		if !exists {
			seen[k] = len(groups)
			groups = append(groups, o)
			continue
		}
		g := &groups[i]
		g.Packets += o.Packets
		g.Bytes += o.Bytes
		if k.measured {
			packets, bytes := *g.PacketDelta+*o.PacketDelta, *g.ByteDelta+*o.ByteDelta
			g.PacketDelta, g.ByteDelta = &packets, &bytes
		}
		g.Members = max(1, g.Members) + 1
		g.CounterID = fmt.Sprintf("%s/group/%d", o.Node, i)
	}
	return groups
}
