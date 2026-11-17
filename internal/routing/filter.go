// SPDX-License-Identifier: Apache-2.0
package routing

import (
	"encoding/json"
	"github.com/trozet/ovn-light/internal/model"
	"strings"
)

// Filter returns independent response objects so stale-state labels cannot mutate
// the report retained for other readers or the next assignment comparison.
func Filter(report Report, o Options) Report {
	r := report
	r.Warnings = append([]string{}, report.Warnings...)
	if o.Limit <= 0 {
		o.Limit = 40
	}
	o.Offset = max(0, o.Offset)
	r.Limit = o.Limit
	r.Offset = o.Offset
	r.Stale = o.Stale
	r.Peers = nil
	for _, p := range report.Peers {
		if matches(p.Networks, p.Node, p, o) {
			if o.Network != "" {
				prefixes := []Prefix{}
				for _, prefix := range p.Prefixes {
					if has(prefix.Networks, o.Network) {
						prefixes = append(prefixes, prefix)
					}
				}
				p.Prefixes = prefixes
				p.PrefixCount = len(prefixes)
			}
			r.Peers = append(r.Peers, p)
		}
	}
	r.Uplinks = nil
	for _, u := range report.Uplinks {
		if matches(u.Networks, u.Node, u, o) {
			r.Uplinks = append(r.Uplinks, u)
		}
	}
	r.Advertisements = nil
	for _, a := range report.Advertisements {
		if o.Node != "" && !has(a.Nodes, o.Node) {
			continue
		}
		if matches(a.Networks, o.Node, a, o) {
			r.Advertisements = append(r.Advertisements, a)
		}
	}
	r.Egress = nil
	for _, e := range report.Egress {
		if o.Node != "" {
			found := false
			for _, p := range e.Pods {
				found = found || p.Node == o.Node
			}
			for _, a := range e.Assignments {
				found = found || a.Node == o.Node
			}
			if !found {
				continue
			}
		}
		if matches(e.Networks, o.Node, e, o) {
			pathOptions := o
			if strings.Contains(strings.ToLower(e.Name), strings.ToLower(o.Search)) {
				pathOptions.Search = ""
			}
			e.Paths = filterPaths(e.Paths, pathOptions)
			e.Pods = filterPods(e.Pods, o)
			r.Egress = append(r.Egress, e)
		}
	}
	r.Issues = nil
	for _, i := range report.Issues {
		if matches(i.Networks, i.Node, i, o) {
			r.Issues = append(r.Issues, i)
		}
	}
	r.Totals = map[string]int{"peers": len(r.Peers), "uplinks": len(r.Uplinks), "advertisements": len(r.Advertisements), "egress": len(r.Egress), "issues": len(r.Issues)}
	r.Peers = page(r.Peers, o)
	r.Uplinks = page(r.Uplinks, o)
	r.Advertisements = page(r.Advertisements, o)
	r.Egress = page(r.Egress, o)
	r.Issues = page(r.Issues, o)
	if o.Stale {
		r.Issues = []Issue{}
		r.Warnings = append(r.Warnings, "Collection is stale. Last-known configuration is shown; current health is unknown.")
	}
	raw, _ := json.Marshal(r)
	var result Report
	_ = json.Unmarshal(raw, &result)
	return result
}
func matches(networks []string, node string, value any, o Options) bool {
	if o.Network != "" && !has(networks, o.Network) || o.Node != "" && node != o.Node {
		return false
	}
	if o.Search != "" {
		raw, _ := json.Marshal(value)
		return strings.Contains(strings.ToLower(string(raw)), strings.ToLower(o.Search))
	}
	return true
}
func page[T any](items []T, o Options) []T {
	start := min(o.Offset, len(items))
	end := min(start+o.Limit, len(items))
	return append([]T{}, items[start:end]...)
}
func filterPaths(paths []EgressPath, o Options) []EgressPath {
	out := []EgressPath{}
	for _, p := range paths {
		if o.Network != "" && p.Source.Network != o.Network || o.Node != "" && p.Source.Node != o.Node && p.Assignment.Node != o.Node {
			continue
		}
		if o.Search != "" {
			raw, _ := json.Marshal(p)
			if !strings.Contains(strings.ToLower(string(raw)), strings.ToLower(o.Search)) {
				continue
			}
		}
		out = append(out, p)
	}
	return out
}
func filterPods(pods []model.Endpoint, o Options) []model.Endpoint {
	out := []model.Endpoint{}
	for _, p := range pods {
		if o.Network != "" && p.Network != o.Network {
			continue
		}
		out = append(out, p)
	}
	return out
}
