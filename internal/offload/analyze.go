// SPDX-License-Identifier: Apache-2.0
package offload

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/trozet/ovn-light/internal/datapath"
	"github.com/trozet/ovn-light/internal/model"
)

func flowTime(n model.NodeSnapshot) time.Time {
	if !n.FlowCapturedAt.IsZero() {
		return n.FlowCapturedAt
	}
	return n.CapturedAt
}

// Analyze reuses OVN's reconstructed paths. Uncovered flows are retained as
// incomplete stages so a missing recirculation cannot hide an offload failure.
func Analyze(n model.NodeSnapshot, flows []datapath.Flow, paths []datapath.Path) (model.OffloadNode, []model.OffloadPath) {
	e := n.Offload
	node := model.OffloadNode{Name: n.Name, State: "unknown", Provider: e.Provider, Version: e.Version, CapturedAt: flowTime(n), DiagnosticsAt: e.CapturedAt, Config: e.Config, Stats: e.Stats, PMDStats: e.PMDStats, Counts: map[string]int{}, Errors: append([]string{}, e.Errors...)}
	fresh := !e.CapturedAt.IsZero() && absDuration(flowTime(n).Sub(e.CapturedAt)) <= 90*time.Second
	if e.ConfigKnown && fresh {
		if e.Enabled {
			node.State = "enabled"
		} else {
			node.State = "disabled"
		}
	}
	if !fresh {
		node.Errors = append(node.Errors, "Offload configuration and diagnostics are unavailable or stale.")
	}
	for _, f := range flows {
		node.Counts[f.OffloadStatus]++
	}
	if node.State == "disabled" {
		return node, nil
	}
	x := parseCT(e.Conntrack)
	if e.CTComplete && !x.valid {
		node.Errors = append(node.Errors, "Conntrack dump could not be fully decoded; CT classification is unavailable.")
	}
	hardwarePorts := map[string]bool{}
	for _, f := range flows {
		if f.Offloaded || f.OffloadStatus == "partial" {
			hardwarePorts[f.InPort] = true
		}
	}
	portIDs := map[string]string{}
	for _, line := range strings.Split(n.Ports, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "port" {
			portIDs[f[2]] = strings.TrimSuffix(f[1], ":")
		}
	}
	// An observed hardware flow establishes capability for that ingress port.
	// Representor metadata also allows diagnosis when every insertion has failed.
	for _, row := range n.Interfaces {
		options, _ := row["options"].(map[string]any)
		status, _ := row["status"].(map[string]any)
		driver, _ := status["driver_name"].(string)
		args, _ := options["dpdk-devargs"].(string)
		if strings.Contains(driver, "mlx5") || strings.Contains(args, "representor=") {
			name, _ := row["name"].(string)
			hardwarePorts[name] = true
			if port := portIDs[name]; port != "" {
				hardwarePorts[port] = true
			}
		}
	}
	covered := map[string]bool{}
	for _, p := range paths {
		for _, f := range p.Flows {
			covered[f.ID] = true
		}
	}
	paths = append([]datapath.Path{}, paths...)
	for _, f := range flows {
		if !covered[f.ID] && len(paths) < 4000 {
			paths = append(paths, datapath.Path{Flows: []datapath.Flow{f}, Original: f.Match, Identity: f.Match, Warnings: []string{"No complete terminal path was reconstructed."}})
		}
	}
	if len(paths) >= 4000 {
		node.Errors = append(node.Errors, "Offload path limit reached; additional stages may be omitted.")
	}
	var out []model.OffloadPath
	for _, p := range paths {
		if len(out) >= 4000 {
			break
		}
		if len(p.Flows) == 0 {
			continue
		}
		o := model.OffloadPath{Node: n.Name, Datapath: n.Datapath, SampleComplete: n.Collection.FlowComplete, Complete: p.Complete && n.Collection.FlowComplete && len(p.Warnings) == 0, ObservedAt: flowTime(n), Warnings: append([]string{}, p.Warnings...), DiagnosticsAt: e.CapturedAt}
		if t, ok := matchTuple(p.Identity); ok {
			o.Tuple = &model.FlowTuple{Protocol: t.protocol, SourceIP: t.src, DestinationIP: t.dst, SourcePort: t.sport, DestinationPort: t.dport}
		}
		sig, ids := "", ""
		hw, sw, partial, unknown, failure := false, false, false, false, false
		for _, f := range p.Flows {
			ids += "/" + f.ID
			sig += fmt.Sprintf("%s/%v/%s/%s;", f.ID, f.Match, f.Actions, f.Provider)
			o.Stages = append(o.Stages, model.OffloadStage{ID: f.ID, Recirc: f.Recirc, InPort: f.InPort, Status: f.OffloadStatus, Provider: f.Provider, Reason: f.OffloadInfo, Packets: f.Packets, Bytes: f.Bytes, PartialPackets: f.PartialPackets, PartialBytes: f.PartialBytes, Raw: f.Raw})
			switch f.OffloadStatus {
			case "hardware":
				hw = true
			case "software":
				sw = true
			case "partial":
				partial = true
			default:
				unknown = true
			}
			if f.OffloadInfo != "" && f.OffloadStatus != "hardware" {
				failure = true
			}
		}
		sig += e.Provider + "/" + e.Version
		o.ID = fmt.Sprintf("%x", sha256.Sum256([]byte(n.Name+"/"+n.Datapath+ids+"/"+p.Output)))[:24]
		o.Signature = fmt.Sprintf("%x", sha256.Sum256([]byte(sig)))
		o.Conntrack = pathCT(n, p, x, fresh)
		for _, ct := range o.Conntrack {
			o.Signature += "/" + ct.Zone + "/" + ct.Direction + "/" + ct.Status
		}
		ctPending := false
		for _, f := range p.Flows {
			if setupFlow(f) {
				ctPending = true
			}
		}
		for _, ct := range o.Conntrack {
			switch ct.Status {
			case "unknown", "not-expected":
				unknown = true
			case "pending":
				ctPending = true
			case "software":
				sw = true
				o.CTProblem = true
			case "hardware":
				hw = true
			}
		}
		o.Eligible = node.State == "enabled" && (hardwarePorts[p.Flows[0].InPort] || hw || partial || failure)
		ip := false
		for _, f := range p.Flows {
			if _, ok := f.Match["ipv4.proto"]; ok {
				ip = true
			}
			if _, ok := f.Match["ipv6.proto"]; ok {
				ip = true
			}
		}
		switch {
		case node.State != "enabled":
			o.Status = "unknown"
			o.Summary = "Offload configuration is unconfirmed."
		case !ip:
			o.Status = "not-expected"
			o.Summary = "Control or non-IP traffic; transport offload is not evaluated."
			o.Eligible = false
		case failure:
			o.Status = "failure"
			o.Summary = "The provider reported an offload failure."
		case partial || hw && sw:
			o.Status = "partial"
			o.Summary = "Some observed stages require software processing."
		case sw:
			o.Status = "software"
			o.Summary = "Observed stages report software processing."
		case ctPending:
			o.Status = "pending"
			o.Summary = "Conntrack setup is still pending."
		case unknown || !o.Complete:
			o.Status = "unknown"
			o.Summary = "Evidence does not cover the complete offload path."
		default:
			o.Status = "hardware"
			o.Summary = "Offload is reported for the observed path and direction."
		}
		if ctPending && !failure {
			o.Status = "pending"
			o.Summary = "Connection setup may require software processing."
			o.Eligible = false
		}
		if !o.Eligible && !ctPending && (sw || partial) && node.State == "enabled" {
			o.Status = "unknown"
			o.Summary = "Software processing observed; ingress offload capability is unconfirmed."
		}
		if !o.Complete {
			o.Warnings = append(o.Warnings, "Path coverage is incomplete; unobserved stages may have different offload status.")
		}
		if unknown && len(o.Conntrack) > 0 {
			o.Warnings = append(o.Warnings, "Conntrack offload could not be established for every required zone.")
		}
		o.Guidance = "Inspect the stage evidence and the node's provider diagnostics. Rule counters are shared and do not establish a per-connection offload percentage."
		if failure {
			o.Guidance = "Review the provider's per-stage failure reason, ingress representor, and supported matches/actions. Recheck after correcting the reported cause."
		}
		if o.CTProblem {
			o.Guidance = "Inspect the matched conntrack zone and observed direction. Check CT offload configuration and provider counters; unobserved reply traffic alone is not a failure."
		}
		out = append(out, o)
	}
	return node, out
}
func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// Setup rules can remain busy as new connections arrive even when established
// traffic is fully offloaded. Their counters must not become fallback alerts.
func setupFlow(f datapath.Flow) bool {
	for key, bit := range map[string]uint64{"ct_state": 1, "tcp_flags": 2} {
		v := f.Match[key]
		if key == "ct_state" && strings.Contains(v, "+new") || key == "tcp_flags" && strings.Contains(v, "+syn") {
			return true
		}
		value, mask, masked := strings.Cut(v, "/")
		n, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			continue
		}
		m := uint64(0xffffffff)
		if masked {
			m, err = strconv.ParseUint(mask, 0, 32)
			if err != nil {
				continue
			}
		}
		if n&m&bit != 0 {
			return true
		}
	}
	return false
}
