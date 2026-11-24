// SPDX-License-Identifier: Apache-2.0
package ovn

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/trozet/ovn-light/internal/datapath"
	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/offload"
)

var portRE = regexp.MustCompile(`(?m)^\s*port\s+(\d+):\s+([^\s(]+)`)
var cookieRE = regexp.MustCompile(`cookie[= ]+(?:0x)?([0-9a-fA-F]+)`)

func Analyze(s model.Snapshot, previous *model.Snapshot) model.View {
	return analyze(s, previous, Attachments(s.Inventory), nil, nil)
}

func analyze(s model.Snapshot, previous *model.Snapshot, attachments []Attachment, hosts map[string]string, prepared *datapath.Sample) model.View {
	v := model.View{TestPathsLimited: map[string]bool{}, CollectedAt: s.CapturedAt, Findings: []model.Finding{}, Nodes: []model.NodeStatus{}, Pods: []model.Endpoint{}, Errors: append([]string{}, s.Inventory.Errors...), Connections: s.Inventory.Resources["clusternetworkconnects"]}
	traffic := newTrafficIndex(s.Inventory, attachments)
	if hosts != nil {
		traffic.hosts = hosts
	}
	if prepared == nil {
		v.Networks = Networks(s.Inventory)
		for _, a := range attachments {
			v.Pods = append(v.Pods, a.Endpoint)
		}
	}
	old := map[string]datapath.Flow{}
	oldNodes := map[string]model.NodeSnapshot{}
	if previous != nil {
		for _, n := range previous.Nodes {
			oldNodes[n.Name] = n
			fs, _ := datapath.Parse(n.Flows)
			for _, f := range fs {
				old[n.Name+"/"+f.ID] = f
			}
		}
	}
	for _, n := range s.Nodes {
		if m := n.Summary; m != nil {
			v.TestPaths = append(v.TestPaths, m.TestPaths...)
			v.TestPathsLimited[n.Name] = m.TestPathsLimited
			v.Nodes = append(v.Nodes, model.NodeStatus{Name: n.Name, CapturedAt: flowTime(n), Collection: n.Collection, Errors: n.Errors, Flows: m.Flows, Offloaded: m.Offloaded})
			v.Findings = append(v.Findings, m.Findings...)
			v.Traffic = append(v.Traffic, m.Traffic...)
			v.Offload.Omitted += m.OmittedPaths
			v.Offload.Nodes = append(v.Offload.Nodes, m.OffloadNode)
			for _, wire := range m.Paths {
				p := wire.Path
				p.Signature, p.Datapath, p.SampleComplete, p.Eligible, p.CTProblem, p.DiagnosticsAt = wire.Signature, wire.Datapath, wire.Complete, wire.Eligible, wire.CTProblem, wire.DiagnosticsAt
				v.Offload.Paths = append(v.Offload.Paths, p)
			}
			continue
		}
		sample := prepared
		if sample == nil {
			raw := datapath.ReadSample(n.Flows, n.Ports)
			sample = &raw
		}
		flows, errs := sample.Flows, sample.Errors
		status := model.NodeStatus{Name: n.Name, Flows: len(flows), CapturedAt: flowTime(n), Collection: n.Collection, Errors: append(append([]string{}, n.Errors...), errs...)}
		for _, f := range flows {
			if f.Offloaded {
				status.Offloaded++
			}
		}
		v.Nodes = append(v.Nodes, status)
		allPaths := sample.Paths
		paths := make([]datapath.Path, 0)
		for _, p := range allPaths {
			if p.Verdict == "drop" {
				paths = append(paths, p)
			}
		}
		sharing := map[string]int{}
		for _, p := range paths {
			sharing[p.Flows[len(p.Flows)-1].ID]++
		}
		for _, p := range paths {
			last := p.Flows[len(p.Flows)-1]
			if last.Packets == 0 {
				continue
			}
			src := resolveSource(n, p, attachments)
			dstIP := exactIP(p.Identity, "dst")
			dst := model.Endpoint{IP: dstIP, Network: src.Network}
			var candidates []model.Endpoint
			for _, a := range attachments {
				mac := datapath.Exact("eth.dst", p.Identity["eth.dst"])
				ipMatches := dstIP != "" && a.Endpoint.IP == dstIP
				macMatches := dstIP == "" && mac != "" && a.MAC == mac && sameFamily(p.Identity, a.Endpoint.IP)
				if (ipMatches || macMatches) && src.Network != "" && a.Endpoint.Network == src.Network {
					candidates = append(candidates, a.Endpoint)
				}
			}
			if len(candidates) == 0 {
				candidates = logicalDestinations(n, p, attachments, src.Network)
			}
			if len(candidates) == 1 {
				dst = candidates[0]
			}
			if src.UID == "" && dst.Network != "" {
				resolved := traffic.endpoint(dst.Network, p.Identity, "src")
				if resolved.UID != "" {
					src = resolved
				}
			}
			proto, port := transport(p.Identity)
			dst.Port = port
			causes := causesFor(n, p)
			enrichAdminCauses(causes, s.Inventory, n.MetadataAt)
			externalFirewall := false
			for j := range causes {
				if causes[j].Type == "EgressFirewall" {
					externalFirewall = externalFirewall || causes[j].Namespace == src.Namespace && dst.Pod == "" && dst.IP != ""
					for _, ef := range s.Inventory.Resources["egressfirewalls"] {
						if ef.GetNamespace() == causes[j].Namespace {
							causes[j].Name = ef.GetName()
						}
					}
				}
			}
			var ids []string
			steps := []model.Step{}
			for _, f := range p.Flows {
				ids = append(ids, f.ID)
				steps = append(steps, model.Step{ID: f.ID, Recirc: f.Recirc, InPort: f.InPort, Match: f.Match, Actions: f.Actions, Packets: f.Packets, Offloaded: f.Offloaded, OpenFlow: n.Detraces[f.ID]})
			}
			f := model.Finding{ID: fmt.Sprintf("%x", sha256.Sum256([]byte(n.Name+strings.Join(ids, "/"))))[:20], Node: n.Name, Source: src, Destination: dst, Protocol: proto, Verdict: "drop", Confidence: "partial", Packets: last.Packets, CounterID: n.Name + "/" + last.ID, SharedCounter: sharing[last.ID] > 1, ObservedAt: n.CapturedAt, Causes: causes, Steps: steps, Warnings: append([]string{}, p.Warnings...)}
			if before, ok := old[f.CounterID]; ok && before.Actions == last.Actions && before.Packets <= last.Packets {
				d := last.Packets - before.Packets
				f.Delta = &d
			}
			if !p.Complete {
				f.Warnings = append(f.Warnings, "The full path to ingress was not recovered.")
			}
			if f.SharedCounter {
				f.Warnings = append(f.Warnings, "Drop counter is shared by multiple compatible paths; counts are not per connection.")
			}
			if src.Pod == "" {
				f.Warnings = append(f.Warnings, "Source workload is unresolved (tunnel, host port, or missing attachment).")
			}
			if dst.Pod == "" && !externalFirewall {
				f.Warnings = append(f.Warnings, "Destination workload is unresolved or shared across networks.")
			}
			if port == 0 {
				f.Warnings = append(f.Warnings, "Destination port is wildcarded; choose the intended connection before proposing an allow rule.")
			}
			if len(causes) == 0 {
				f.Warnings = append(f.Warnings, "No denying ACL was recovered from the translation cache.")
			}
			if src.Pod != "" && dst.Pod != "" && port > 0 && p.Complete && !f.SharedCounter {
				f.Confidence = "connection"
			}
			for _, cause := range causes {
				if cause.Type == "NetpolNamespace" && f.Confidence == "connection" {
					f.CanRecommend = true
				}
				if cause.Type == "EgressFirewall" && cause.Namespace == src.Namespace && src.Network == "default" && src.Role == "primary" && dst.IP != "" && dst.Pod == "" && port > 0 && p.Complete && !f.SharedCounter {
					f.Confidence = "connection"
					f.CanRecommend = true
				}
			}
			for _, cause := range causes {
				if cause.Admin != nil {
					f.CanRecommend = false
				}
			}
			for _, warning := range p.Warnings {
				if strings.Contains(warning, "not modeled") || strings.Contains(warning, "requires additional") || strings.Contains(warning, "Conditional") {
					f.CanRecommend = false
					f.Confidence = "partial"
				}
			}
			f.Title = label(src) + " → " + label(dst)
			if proto != "" {
				f.Title += " · " + proto
			}
			if port > 0 {
				f.Title += fmt.Sprintf("/%d", port)
			}
			v.Findings = append(v.Findings, f)
		}

		observations := traffic.traffic(n, allPaths, old, oldNodes[n.Name], v.Findings)
		v.Traffic = append(v.Traffic, observations...)
		offNode, offPaths := offload.Analyze(n, flows, allPaths)
		byCounter := map[string][]model.TrafficObservation{}
		for _, o := range observations {
			byCounter[o.CounterID] = append(byCounter[o.CounterID], o)
		}
		flowByID := map[string]datapath.Flow{}
		for _, f := range flows {
			flowByID[f.ID] = f
		}
		for i := range offPaths {
			p := &offPaths[i]
			var path datapath.Path
			if i < len(allPaths) {
				path = allPaths[i]
			} else if len(p.Stages) > 0 {
				if f, ok := flowByID[p.Stages[0].ID]; ok {
					path = datapath.Path{Flows: []datapath.Flow{f}, Identity: f.Match, Original: f.Match}
				}
			}
			if len(path.Flows) > 0 {
				p.Source = resolveSource(n, path, attachments)
				p.Destination = traffic.endpoint(p.Source.Network, path.Identity, "dst")
				p.Network = p.Source.Network
				p.Protocol, p.Destination.Port = transport(path.Identity)
				// Use receiver-side attribution only when this terminal counter has one
				// observed identity. Shared counters must not select an arbitrary pod.
				matches := byCounter[n.Name+"/"+path.Flows[len(path.Flows)-1].ID]
				if len(matches) == 1 {
					p.Source, p.Destination, p.Network, p.Protocol = matches[0].Source, matches[0].Destination, matches[0].Network, matches[0].Protocol
				}
			}
			p.Signature += "/" + p.Network + "/" + p.Source.UID + "/" + p.Destination.UID
		}
		testPaths, limited := sampleTestPaths(n, traffic.testPorts[n.Name], allPaths, offNode.State)
		v.TestPaths = append(v.TestPaths, testPaths...)
		v.TestPathsLimited[n.Name] = limited
		v.Offload.Nodes = append(v.Offload.Nodes, offNode)
		v.Offload.Paths = append(v.Offload.Paths, offPaths...)

	}
	sort.Slice(v.Findings, func(i, j int) bool {
		a, b := v.Findings[i], v.Findings[j]
		if a.Delta != nil && b.Delta != nil && *a.Delta != *b.Delta {
			return *a.Delta > *b.Delta
		}
		if a.Packets != b.Packets {
			return a.Packets > b.Packets
		}
		return a.ID < b.ID
	})
	if prepared == nil {
		sourceContexts(&v, traffic)
	}
	v.Offload.CollectedAt = s.CapturedAt
	return v
}

func label(e model.Endpoint) string {
	if e.Pod != "" {
		return e.Namespace + "/" + e.Pod
	}
	if e.IP != "" {
		return e.IP
	}
	return "Unresolved endpoint"
}
func exactIP(m map[string]string, side string) string {
	for _, prefix := range []string{"ipv4.", "ipv6."} {
		key := prefix + side
		if v := datapath.Exact(key, m[key]); v != "" {
			return v
		}
	}
	return ""
}
func transport(m map[string]string) (string, int) {
	for _, proto := range []string{"tcp", "udp", "sctp"} {
		if value, ok := m[proto+".dst"]; ok {
			p, _ := strconv.Atoi(datapath.Exact(proto+".dst", value))
			return strings.ToUpper(proto), p
		}
	}
	for _, key := range []string{"ipv4.proto", "ipv6.proto"} {
		switch datapath.Exact(key, m[key]) {
		case "6":
			return "TCP", 0
		case "17":
			return "UDP", 0
		case "132":
			return "SCTP", 0
		}
	}
	return "", 0
}

func sameFamily(m map[string]string, ip string) bool {
	v6 := strings.Contains(ip, ":")
	if _, ok := m["ipv4.src"]; ok {
		return !v6
	}
	if _, ok := m["ipv6.src"]; ok {
		return v6
	}
	return true
}

var metadataRE = regexp.MustCompile(`(?:^|[, ])metadata=(0x[0-9a-fA-F]+)(?:/([^, ]+))?`)
var outportRE = regexp.MustCompile(`(?:^|[, ])reg15=(0x[0-9a-fA-F]+)(?:/([^, ]+))?`)

// An exact logical outport in the terminal translation can identify a pod even
// when the datapath's destination address was wildcarded by the ACL compiler.
func logicalDestinations(n model.NodeSnapshot, p datapath.Path, attachments []Attachment, network string) []model.Endpoint {
	ports := map[string]bool{}
	last := p.Flows[len(p.Flows)-1]
	for _, line := range strings.Split(n.Detraces[last.ID], "\n") {
		match, _, _ := strings.Cut(line, "actions=")
		dp := metadataRE.FindStringSubmatch(match)
		out := outportRE.FindStringSubmatch(match)
		if len(dp) == 0 || len(out) == 0 {
			continue
		}
		if dp[2] != "" && dp[2] != "0xffffffffffffffff" || out[2] != "" && out[2] != "0xffffffff" {
			continue
		}
		dpKey, _ := strconv.ParseUint(dp[1], 0, 64)
		outKey, _ := strconv.ParseUint(out[1], 0, 32)
		for _, d := range n.Datapaths {
			key, _ := strconv.ParseUint(Str(d["tunnel_key"]), 10, 64)
			if key != dpKey {
				continue
			}
			for _, b := range n.Bindings {
				portKey, _ := strconv.ParseUint(Str(b["tunnel_key"]), 10, 32)
				if Str(b["datapath"]) == Str(d["_uuid"]) && portKey == outKey {
					ports[Str(b["logical_port"])] = true
				}
			}
		}
	}
	var found []model.Endpoint
	for _, a := range attachments {
		if ports[a.LogicalPort] && (network == "" || a.Endpoint.Network == network) && sameFamily(p.Identity, a.Endpoint.IP) {
			found = append(found, a.Endpoint)
		}
	}
	return found
}

func resolveSource(n model.NodeSnapshot, p datapath.Path, attachments []Attachment) model.Endpoint {
	f := p.Flows[0]
	port := f.InPort
	for _, match := range portRE.FindAllStringSubmatch(n.Ports, -1) {
		if match[1] == port {
			port = match[2]
			break
		}
	}
	ip := exactIP(p.Original, "src")
	for _, row := range n.Interfaces {
		if Str(row["name"]) != port {
			continue
		}
		ext := Map(row["external_ids"])
		logical := Str(ext["iface-id"])
		uid := Str(ext["iface-id-ver"])
		for _, a := range attachments {
			if a.Node == n.Name && a.LogicalPort == logical && (uid == "" || uid == a.Endpoint.UID) && (ip == "" || ip == a.Endpoint.IP) && sameFamily(p.Original, a.Endpoint.IP) {
				return a.Endpoint
			}
		}
	}
	// A tunnel ingress has no local pod interface. Resolve the logical datapath
	// from the Geneve tunnel ID, then restrict IP lookup to bound logical ports.
	// Never resolve an IP globally: different UDNs can reuse the same addresses.
	tunnelID := datapath.Exact("tunnel.tun_id", p.Original["tunnel.tun_id"])
	if tunnelID != "" && ip != "" {
		key, err := strconv.ParseUint(tunnelID, 0, 64)
		if err == nil {
			dps := map[string]bool{}
			for _, dp := range n.Datapaths {
				v, _ := strconv.ParseUint(Str(dp["tunnel_key"]), 10, 64)
				if v == key {
					dps[Str(dp["_uuid"])] = true
				}
			}
			ports := map[string]bool{}
			for _, binding := range n.Bindings {
				if dps[Str(binding["datapath"])] {
					ports[Str(binding["logical_port"])] = true
				}
			}
			var candidates []model.Endpoint
			for _, a := range attachments {
				if a.Endpoint.IP == ip && ports[a.LogicalPort] {
					candidates = append(candidates, a.Endpoint)
				}
			}
			if len(candidates) == 1 {
				return candidates[0]
			}
		}
	}
	return model.Endpoint{IP: ip}
}

func causesFor(n model.NodeSnapshot, p datapath.Path) []model.PolicyCause {
	cookies := map[uint64]bool{}
	for _, f := range p.Flows {
		for _, m := range cookieRE.FindAllStringSubmatch(n.Detraces[f.ID], -1) {
			v, _ := strconv.ParseUint(m[1], 16, 64)
			cookies[v] = true
		}
	}
	aclHints := map[string]bool{}
	for _, lf := range n.LogicalFlows {
		id := Str(lf["_uuid"])
		if len(id) < 8 {
			continue
		}
		cookie, _ := strconv.ParseUint(id[:8], 16, 64)
		if cookies[cookie] {
			hint := Str(Map(lf["external_ids"])["stage-hint"])
			if hint != "" {
				aclHints[hint] = true
			}
		}
	}
	return causesForHints(n, aclHints)
}

// TraceCauses resolves only unambiguous logical-flow UUIDs from ovn-trace.
// A matching deny ACL explains a simulated decision, not an observed drop.
func TraceCauses(n model.NodeSnapshot, inv model.Inventory, ids []string) []model.PolicyCause {
	hints := map[string]bool{}
	for _, id := range ids {
		var matches []model.Row
		if len(id) < 8 {
			continue
		}
		for _, lf := range n.LogicalFlows {
			if strings.HasPrefix(Str(lf["_uuid"]), id) {
				matches = append(matches, lf)
			}
		}
		if len(matches) == 1 {
			hint := Str(Map(matches[0]["external_ids"])["stage-hint"])
			if hint != "" {
				hints[hint] = true
			}
		}
	}
	for hint := range hints {
		matches := 0
		for _, acl := range n.ACLs {
			if strings.HasPrefix(Str(acl["_uuid"]), hint) {
				matches++
			}
		}
		if matches != 1 {
			delete(hints, hint)
		}
	}
	out := causesForHints(n, hints)
	enrichAdminCauses(out, inv, n.CapturedAt)
	for j := range out {
		if out[j].Admin != nil {
			out[j].Admin.Explanation = strings.ReplaceAll(out[j].Admin.Explanation, "observed path", "simulated path")
			out[j].Admin.Warnings = []string{"This attribution describes the requested simulation and current API resource; it does not prove a real packet was dropped."}
		}
	}
	return out
}

func causesForHints(n model.NodeSnapshot, aclHints map[string]bool) []model.PolicyCause {
	var out []model.PolicyCause
	for _, a := range n.ACLs {
		id := Str(a["_uuid"])
		found := false
		for hint := range aclHints {
			if strings.HasPrefix(id, hint) {
				found = true
			}
		}
		if !found {
			continue
		}
		action := Str(a["action"])
		if action != "drop" && action != "reject" {
			continue
		}
		ext := Map(a["external_ids"])
		c := model.PolicyCause{ACL: id, Action: action, Type: Str(ext["k8s.ovn.org/owner-type"]), Name: Str(ext["k8s.ovn.org/name"]), Direction: Str(ext["direction"]), Rule: Str(ext["gress-index"]), Match: Str(a["match"])}
		if c.Type == "NetpolNamespace" || c.Type == "EgressFirewall" {
			c.Namespace = c.Name
			c.Name = ""
		} else if c.Type == "NetworkPolicy" {
			c.Namespace, c.Name, _ = strings.Cut(c.Name, ":")
		}
		if c.Type == "EgressFirewall" {
			c.Rule = Str(ext["rule-index"])
			if c.Rule == "" {
				c.Rule = Str(ext["rule-idx"])
			}
			c.Direction = "Egress"
		}
		out = append(out, c)
	}
	return out
}
