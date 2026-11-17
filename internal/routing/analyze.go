// SPDX-License-Identifier: Apache-2.0
package routing

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
)

const raKey = "k8s.ovn.org/route-advertisements"

func str(v any) string { return ovn.Str(v) }
func obj(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	if m, ok := v.(model.Row); ok {
		return m
	}
	return map[string]any{}
}
func arr(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	return nil
}
func stringsOf(v any) []string {
	out := []string{}
	switch x := v.(type) {
	case string:
		out = append(out, x)
	case []string:
		out = append(out, x...)
	case []any:
		for _, item := range x {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
func has(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}
func union(a []string, b ...string) []string {
	for _, s := range b {
		if s != "" && !has(a, s) {
			a = append(a, s)
		}
	}
	sort.Strings(a)
	return a
}
func selector(raw any, values map[string]string) bool {
	if raw == nil {
		return true
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return false
	}
	var s meta.LabelSelector
	if json.Unmarshal(b, &s) != nil {
		return false
	}
	sel, err := meta.LabelSelectorAsSelector(&s)
	return err == nil && sel.Matches(labels.Set(values))
}
func fresh(at, now time.Time) bool {
	return !at.IsZero() && now.Sub(at) < 2*time.Minute && now.Sub(at) > -time.Minute
}
func normalizedVRF(s string) string {
	if s == "" {
		return "default"
	}
	return s
}
func cidr(s string) string {
	if p, e := netip.ParsePrefix(s); e == nil {
		return p.Masked().String()
	}
	if ip, e := netip.ParseAddr(s); e == nil {
		return netip.PrefixFrom(ip, ip.BitLen()).String()
	}
	return ""
}
func resourceStatus(r unstructured.Unstructured) string {
	status := obj(r.Object["status"])
	for _, raw := range arr(status["conditions"]) {
		c := obj(raw)
		if str(c["status"]) == "False" {
			return str(c["type"]) + ": " + str(c["reason"]) + " " + str(c["message"])
		}
	}
	if s := str(status["status"]); s != "" {
		return s
	}
	return "Reported configuration; inspect conditions"
}
func Analyze(s model.Snapshot, v model.View, previous *Report) Report {
	r := Report{CollectedAt: s.CapturedAt, Capabilities: map[string]string{}, Peers: []Peer{}, Uplinks: []Uplink{}, Advertisements: []Advertisement{}, Egress: []Egress{}, Issues: []Issue{}, Warnings: []string{}, Totals: map[string]int{}}
	inv := s.Inventory
	for _, kind := range []string{"routeadvertisements", "frrconfigurations", "bgpsessionstates", "frrnodestates", "uplinks", "uplinkstates", "egressips", "adminnetworkpolicies", "baselineadminnetworkpolicies"} {
		r.Capabilities[kind] = "API not available"
		if _, ok := inv.Resources[kind]; ok {
			r.Capabilities[kind] = "Available"
		}
		for _, err := range inv.Errors {
			if strings.HasPrefix(err, "read "+kind+":") {
				r.Capabilities[kind] = "Collection failed"
				r.Warnings = append(r.Warnings, err)
			}
		}
		if err := inv.DiagnosticErrors[kind]; err != "" {
			r.Capabilities[kind] = "Collection failed"
			r.Warnings = append(r.Warnings, kind+": "+err)
		}
	}
	if err := inv.DiagnosticErrors["nodes"]; err != "" {
		r.Warnings = append(r.Warnings, "nodes: "+err)
	}
	nodes := map[string]core.Node{}
	runtime := map[string]model.NodeSnapshot{}
	for _, n := range inv.Nodes {
		nodes[n.Name] = n
	}
	for _, n := range s.Nodes {
		runtime[n.Name] = n
		for _, err := range n.Routing.Errors {
			r.Warnings = append(r.Warnings, n.Name+": "+err)
		}
	}
	r.Uplinks = buildUplinks(inv, runtime)
	r.Egress = buildEgress(s, v, previous)
	expected := map[string]map[string][]Prefix{}
	for _, resource := range inv.Resources["routeadvertisements"] {
		spec := obj(resource.Object["spec"])
		a := Advertisement{Name: resource.GetName(), Networks: advertisedNetworks(inv, spec), Types: stringsOf(spec["advertisements"]), VRF: normalizedVRF(str(spec["targetVRF"])), Conditions: arr(obj(resource.Object["status"])["conditions"]), Status: resourceStatus(resource), Nodes: []string{}, Configurations: []string{}}
		expected[a.Name] = map[string][]Prefix{}
		for name, n := range nodes {
			if !selector(spec["nodeSelector"], n.Labels) {
				continue
			}
			a.Nodes = append(a.Nodes, name)
			if has(a.Types, "PodNetwork") {
				for _, network := range a.Networks {
					for _, prefix := range podPrefixes(inv, n, network) {
						expected[a.Name][name] = append(expected[a.Name][name], Prefix{CIDR: prefix, Kind: "PodNetwork", Networks: []string{network}, Advertisement: a.Name})
					}
				}
			}
			if has(a.Types, "EgressIP") {
				for _, e := range r.Egress {
					for _, assignment := range e.Assignments {
						if assignment.Node != name {
							continue
						}
						for _, network := range e.Networks {
							if has(a.Networks, network) {
								expected[a.Name][name] = append(expected[a.Name][name], Prefix{CIDR: cidr(assignment.IP), Kind: "EgressIP", Networks: []string{network}, Advertisement: a.Name})
							}
						}
					}
				}
			}
		}
		sort.Strings(a.Nodes)
		for _, c := range inv.Resources["frrconfigurations"] {
			if c.GetLabels()[raKey] == a.Name {
				a.Configurations = append(a.Configurations, c.GetNamespace()+"/"+c.GetName())
			}
		}
		sort.Strings(a.Configurations)
		r.Advertisements = append(r.Advertisements, a)
		for _, raw := range a.Conditions {
			c := obj(raw)
			if str(c["status"]) == "False" {
				r.Issues = append(r.Issues, Issue{Kind: "RouteAdvertisements", Name: a.Name, Networks: a.Networks, Message: a.Status})
				break
			}
		}
	}
	peers := map[string]*Peer{}
	for _, config := range inv.Resources["frrconfigurations"] {
		spec := obj(config.Object["spec"])
		ra := config.GetLabels()[raKey]
		for node, n := range nodes {
			if !selector(spec["nodeSelector"], n.Labels) {
				continue
			}
			for _, raw := range arr(obj(spec["bgp"])["routers"]) {
				router := obj(raw)
				vrf := normalizedVRF(str(router["vrf"]))
				for _, value := range arr(router["neighbors"]) {
					neighbor := obj(value)
					address := str(neighbor["address"])
					if address == "" {
						address = str(neighbor["interface"])
					}
					if address == "" {
						continue
					}
					key := node + "/" + vrf + "/" + address
					p := peers[key]
					if p == nil {
						p = &Peer{ID: key, Node: node, VRF: vrf, Address: address, LocalASN: str(router["asn"]), RemoteASN: str(neighbor["asn"]), Source: str(neighbor["sourceaddress"]), Interface: str(neighbor["interface"]), BGP: "Unknown", BFD: "Unknown", StateSource: "Configuration only", Configurations: []string{}, Networks: []string{}, Uplinks: []string{}, Prefixes: []Prefix{}, Warnings: []string{}}
						if p.RemoteASN == "" {
							p.RemoteASN = str(neighbor["dynamicASN"])
						}
						peers[key] = p
					}
					p.Configurations = union(p.Configurations, config.GetNamespace()+"/"+config.GetName())
					for _, a := range r.Advertisements {
						if a.Name == ra {
							p.Networks = union(p.Networks, a.Networks...)
						}
					}
					allowed := obj(obj(neighbor["toAdvertise"])["allowed"])
					for _, rawPrefix := range stringsOf(router["prefixes"]) {
						prefix := cidr(rawPrefix)
						if prefix == "" {
							continue
						}
						if str(allowed["mode"]) != "all" && !has(stringsOf(allowed["prefixes"]), rawPrefix) {
							continue
						}
						matching := []Prefix{}
						for _, expect := range expected[ra][node] {
							if expect.CIDR == prefix {
								matching = append(matching, expect)
							}
						}
						if len(matching) == 0 {
							matching = append(matching, Prefix{CIDR: prefix, Kind: "Other", Networks: []string{}, Advertisement: ra})
						}
						for _, route := range matching {
							route.State = "Configured"
							duplicate := false
							for _, known := range p.Prefixes {
								if known.CIDR == route.CIDR && known.Advertisement == route.Advertisement && strings.Join(known.Networks, ",") == strings.Join(route.Networks, ",") {
									duplicate = true
								}
							}
							if !duplicate {
								p.Prefixes = append(p.Prefixes, route)
							}
						}
					}
				}
			}
		}
	}
	for _, session := range inv.Resources["bgpsessionstates"] {
		status := obj(session.Object["status"])
		key := str(status["node"]) + "/" + normalizedVRF(str(status["vrf"])) + "/" + str(status["peer"])
		if p := peers[key]; p != nil {
			p.BGP = str(status["bgpStatus"])
			p.BFD = str(status["bfdStatus"])
			p.StateSource = "FRR-k8s reported status"
		}
	}
	for _, p := range peers {
		n := runtime[p.Node]
		e := n.Routing
		if fresh(e.CapturedAt, s.CapturedAt) {
			p.CapturedAt = e.CapturedAt
			for _, live := range e.Peers {
				if live.VRF != p.VRF || live.Peer != p.Address {
					continue
				}
				p.BGP = live.State
				p.StateSource = "FRR runtime"
				p.Warnings = append(p.Warnings, live.Errors...)
				for i := range p.Prefixes {
					prefix, _ := netip.ParsePrefix(p.Prefixes[i].CIDR)
					if prefix.Addr().Is4() != (live.Family == "ipv4") {
						continue
					}
					if has(live.Advertised, p.Prefixes[i].CIDR) {
						p.Prefixes[i].State = "Locally advertised"
					} else if live.Complete && strings.EqualFold(live.State, "Established") {
						p.Prefixes[i].State = "Not advertised"
					}
				}
				for _, prefix := range live.Advertised {
					known := false
					for _, route := range p.Prefixes {
						if route.CIDR == prefix {
							known = true
							break
						}
					}
					if !known {
						p.Prefixes = append(p.Prefixes, Prefix{CIDR: prefix, Kind: "Other", Networks: []string{}, State: "Locally advertised"})
					}
				}
			}
		}
		p.Uplinks, p.Mapping = peerUplinks(*p, r.Uplinks, n, s.CapturedAt)
		p.PrefixCount = len(p.Prefixes)
		sort.Slice(p.Prefixes, func(i, j int) bool { return p.Prefixes[i].CIDR < p.Prefixes[j].CIDR })
		if len(p.Prefixes) > 500 {
			p.Prefixes = p.Prefixes[:500]
			p.Warnings = append(p.Warnings, "Showing the first 500 prefixes for this peer.")
		}
		if p.BGP != "" && p.BGP != "Unknown" && !strings.EqualFold(p.BGP, "Established") {
			r.Issues = append(r.Issues, Issue{Kind: "BGP", Name: p.Address, Node: p.Node, Networks: p.Networks, Message: "BGP session reported " + p.BGP + " (" + p.StateSource + ")."})
		}
		missing := 0
		for _, route := range p.Prefixes {
			if route.State == "Not advertised" {
				missing++
			}
		}
		if missing > 0 {
			r.Issues = append(r.Issues, Issue{Kind: "Advertisement", Name: p.Address, Node: p.Node, Networks: p.Networks, Message: fmt.Sprintf("%d configured prefixes were absent from the complete local advertised-route table; configuration may still be converging.", missing)})
		}
		r.Peers = append(r.Peers, *p)
	}
	for _, u := range r.Uplinks {
		if u.Ready == "Not ready" {
			r.Issues = append(r.Issues, Issue{Kind: "Uplink", Name: u.Name, Node: u.Node, Networks: u.Networks, Message: "Uplink reports unresolved discovery or incomplete gateway programming."})
		}
	}
	for _, e := range r.Egress {
		for _, ip := range e.Requested {
			assigned := false
			for _, a := range e.Assignments {
				if a.IP == ip {
					assigned = true
				}
			}
			if !assigned {
				r.Issues = append(r.Issues, Issue{Kind: "EgressIP", Name: e.Name, Networks: e.Networks, Message: ip + " has no reported node assignment."})
			}
		}
	}
	for _, f := range inv.Resources["frrnodestates"] {
		status := obj(f.Object["status"])
		for _, field := range []string{"lastConversionResult", "lastReloadResult"} {
			value := str(status[field])
			if value != "" && !strings.EqualFold(value, "success") {
				r.Issues = append(r.Issues, Issue{Kind: "FRR", Name: f.GetName(), Node: f.GetName(), Networks: []string{}, Message: field + ": " + value})
			}
		}
	}
	sort.Slice(r.Peers, func(i, j int) bool { return r.Peers[i].ID < r.Peers[j].ID })
	sort.Slice(r.Uplinks, func(i, j int) bool { return r.Uplinks[i].ID < r.Uplinks[j].ID })
	sort.Slice(r.Advertisements, func(i, j int) bool { return r.Advertisements[i].Name < r.Advertisements[j].Name })
	sort.Slice(r.Egress, func(i, j int) bool { return r.Egress[i].Name < r.Egress[j].Name })
	return r
}
func advertisedNetworks(inv model.Inventory, spec map[string]any) []string {
	out := []string{}
	for _, raw := range arr(spec["networkSelectors"]) {
		selection := obj(raw)
		switch str(selection["networkSelectionType"]) {
		case "DefaultNetwork":
			out = union(out, "default")
		case "ClusterUserDefinedNetworks":
			sel := obj(selection["clusterUserDefinedNetworkSelector"])["networkSelector"]
			for _, c := range inv.Resources["clusteruserdefinednetworks"] {
				if selector(sel, c.GetLabels()) {
					out = union(out, "cluster/"+c.GetName())
				}
			}
		}
	}
	return out
}
func podPrefixes(inv model.Inventory, node core.Node, network string) []string {
	name := network
	if strings.HasPrefix(network, "cluster/") {
		name = "cluster_udn_" + strings.TrimPrefix(network, "cluster/")
	}
	values := map[string]any{}
	_ = json.Unmarshal([]byte(node.Annotations["k8s.ovn.org/node-subnets"]), &values)
	out := []string{}
	for _, raw := range stringsOf(values[name]) {
		if value := cidr(raw); value != "" {
			out = union(out, value)
		}
	}
	if len(out) == 0 && strings.HasPrefix(network, "cluster/") {
		for _, c := range inv.Resources["clusteruserdefinednetworks"] {
			if "cluster/"+c.GetName() != network {
				continue
			}
			for _, raw := range stringsOf(obj(obj(obj(c.Object["spec"])["network"])["layer2"])["subnets"]) {
				if value := cidr(raw); value != "" {
					out = union(out, value)
				}
			}
		}
	}
	return out
}
