// SPDX-License-Identifier: Apache-2.0
package datapath

import (
	"fmt"
	"strings"
)

type Path struct {
	Flows    []Flow
	Identity map[string]string
	Original map[string]string
	Warnings []string
	Complete bool
}

// Reconstruct follows compatible packet constraints rather than treating a
// recirculation ID as a connection ID. Limits bound adversarial/large dumps.
func Reconstruct(flows []Flow) []Path {
	byStage := map[string][]Flow{}
	for _, f := range flows {
		byStage[f.Recirc] = append(byStage[f.Recirc], f)
	}
	var paths []Path
	covered := map[string]bool{}
	const maxPaths = 4000
	visits := 0
	var walk func(Flow, Path, map[string]bool)
	walk = func(f Flow, p Path, seen map[string]bool) {
		visits++
		if len(paths) >= maxPaths || visits > 50000 {
			return
		}
		if seen[f.ID] || len(p.Flows) >= 24 {
			return
		}
		m, ok := Merge(p.Identity, f.Match)
		if !ok {
			return
		}
		p.Identity = m
		p.Flows = append(append([]Flow{}, p.Flows...), f)
		p.Warnings = append([]string{}, p.Warnings...)
		if len(p.Flows) == 1 {
			p.Original = clone(m)
		}
		if Terminal(f.Actions) == "drop" {
			paths = append(paths, p)
			covered[f.ID] = true
			return
		}
		seen2 := map[string]bool{}
		for k, v := range seen {
			seen2[k] = v
		}
		seen2[f.ID] = true
		state, warnings := Transform(m, f.Actions)
		p.Warnings = append(p.Warnings, warnings...)
		p.Identity = state
		for _, id := range Recircs(f.Actions) {
			for _, next := range byStage[id] {
				walk(next, p, seen2)
			}
		}
	}
	for _, f := range flows {
		if f.Recirc == "0" {
			walk(f, Path{Identity: map[string]string{}, Complete: true}, map[string]bool{})
		}
	}
	for _, f := range flows {
		if Terminal(f.Actions) == "drop" && !covered[f.ID] {
			paths = append(paths, Path{Flows: []Flow{f}, Identity: clone(f.Match), Original: clone(f.Match), Warnings: []string{"Ingress path is missing or incompatible; identity is incomplete."}})
		}
	}
	if len(paths) >= maxPaths || visits > 50000 {
		for i := range paths {
			paths[i].Complete = false
			paths[i].Warnings = append(paths[i].Warnings, "Path limit reached; this snapshot is incomplete.")
		}
	}
	return paths
}

func Transform(match map[string]string, actions string) (map[string]string, []string) {
	m := clone(match)
	var warnings []string
	for _, a := range Split(actions) {
		switch {
		case strings.HasPrefix(a, "recirc("):
		case strings.HasPrefix(a, "set(") && strings.HasSuffix(a, ")"):
			set := map[string]string{}
			flatten("", a[4:len(a)-1], set)
			for k, v := range set {
				if strings.Contains(v, "/") {
					delete(m, k)
					warnings = append(warnings, "Masked rewrite requires additional evidence: "+k)
				} else {
					m[k] = v
				}
			}
		case strings.HasPrefix(a, "ct("):
			delete(m, "ct_state")
			delete(m, "ct_mark")
			delete(m, "ct_label")
			delete(m, "ct_zone")
			if strings.Contains(a, "nat") {
				for _, k := range []string{"ipv4.src", "ipv4.dst", "ipv6.src", "ipv6.dst", "tcp.src", "tcp.dst", "udp.src", "udp.dst", "sctp.src", "sctp.dst"} {
					delete(m, k)
				}
				warnings = append(warnings, "Conntrack NAT may translate addresses or ports; only explicit matches after NAT identify the translated tuple.")
			}
		case a == "ct_clear":
			for _, k := range []string{"ct_state", "ct_mark", "ct_label", "ct_zone"} {
				delete(m, k)
			}
		case strings.HasPrefix(a, "clone(") || strings.HasPrefix(a, "sample(") || strings.HasPrefix(a, "check_pkt_len("):
			warnings = append(warnings, "Conditional or cloned actions need packet evidence: "+a)
		default:
			warnings = append(warnings, fmt.Sprintf("Action is not modeled during identity reconstruction: %s", a))
		}
	}
	return m, warnings
}
