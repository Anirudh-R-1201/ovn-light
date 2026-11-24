// SPDX-License-Identifier: Apache-2.0
package ovn

import (
	"strings"

	"github.com/trozet/ovn-light/internal/datapath"
	"github.com/trozet/ovn-light/internal/model"
)

// Only nodes hosting a test endpoint export these samples. A UID check keeps
// cached port names from attributing traffic to a replacement pod.
func sampleTestPaths(n model.NodeSnapshot, logical map[string]string, paths []datapath.Path, state string) ([]model.TestPathSample, bool) {
	if len(logical) == 0 {
		return nil, false
	}
	ports := map[string]string{}
	for _, row := range n.Interfaces {
		ext := Map(row["external_ids"])
		uid := logical[Str(ext["iface-id"])]
		if uid != "" && Str(ext["iface-id-ver"]) == uid {
			ports[Str(row["name"])] = uid
		}
	}
	for _, pair := range portRE.FindAllStringSubmatch(n.Ports, -1) {
		if uid := ports[pair[2]]; uid != "" {
			ports[pair[1]] = uid
		}
	}
	var out []model.TestPathSample
	size := 0
	for _, p := range paths {
		if len(p.Flows) == 0 {
			continue
		}
		uid := ports[p.Flows[0].InPort]
		outbound := uid != ""
		if !outbound {
			uid = ports[p.Output]
		}
		if uid == "" {
			continue
		}
		if p.Identity["ipv4.proto"] == "" && p.Identity["ipv6.proto"] == "" {
			continue
		}
		item := model.TestPathSample{PodUID: uid, Node: n.Name, At: flowTime(n), Outbound: outbound, Match: map[string]string{}}
		for _, key := range []string{"eth_type", "ipv4.src", "ipv4.dst", "ipv4.proto", "ipv6.src", "ipv6.dst", "ipv6.proto", "tcp.src", "tcp.dst", "udp.src", "udp.dst"} {
			if value := p.Identity[key]; value != "" {
				item.Match[key] = value
			}
		}
		for _, f := range p.Flows {
			status := f.OffloadStatus
			if status == "unknown" && state == "disabled" {
				status = "software"
			}
			raw := strings.TrimSpace(f.Raw)
			if len(raw) > 4096 {
				raw = raw[:4096] + "…"
			}
			size += len(raw) + 256
			if size > 128<<10 || len(out) >= 64 {
				return out, true
			}
			item.Stages = append(item.Stages, model.OffloadStage{
				ID: f.ID, Recirc: f.Recirc, InPort: f.InPort, Status: status, Provider: f.Provider,
				Packets: f.Packets, Bytes: f.Bytes, PartialPackets: f.PartialPackets, PartialBytes: f.PartialBytes, Raw: raw,
			})
		}
		out = append(out, item)
	}
	return out, false
}
