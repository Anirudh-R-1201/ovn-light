// SPDX-License-Identifier: Apache-2.0
package ovn

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/trozet/ovn-light/internal/datapath"
	"github.com/trozet/ovn-light/internal/model"
)

// Candidate senders are inventory matches, optionally supported by a separate
// outgoing observation. They never replace the unresolved source identity or
// supply a destination port to a policy proposal.
func sourceContexts(v *model.View, x trafficIndex) {
	outgoing := map[string][]model.TrafficObservation{}
	for _, o := range v.Traffic {
		if o.Verdict == "forward" && o.Source.UID != "" && (o.Location == "source" || o.Location == "local") {
			outgoing[o.Network+"/"+o.Source.UID] = append(outgoing[o.Network+"/"+o.Source.UID], o)
		}
	}
	for j := range v.Findings {
		f := &v.Findings[j]
		if f.Source.UID != "" || len(f.Steps) == 0 {
			continue
		}
		match := f.Steps[0].Match
		if f.Source.Node == "" {
			f.Source.Node = x.hosts[datapath.Exact("tunnel.src", match["tunnel.src"])]
		}
		context := &model.SourceContext{Network: f.Source.Network, Candidates: []model.SourceCandidate{}}
		if context.Network == "" {
			context.Network = f.Destination.Network
		}
		key, raw := "", ""
		for _, family := range []string{"ipv4", "ipv6"} {
			if value, ok := match[family+".src"]; ok {
				key, raw = family+".src", value
				break
			}
		}
		context.Address = sourceAddress(raw)
		f.SourceContext = context
		if context.Network == "" || context.Address == "" {
			continue
		}
		candidates := map[string]model.SourceCandidate{}
		for _, a := range x.attachments {
			e := a.Endpoint
			if e.Network != context.Network || f.Source.Node != "" && e.Node != f.Source.Node || !sameFamily(match, e.IP) {
				continue
			}
			if _, ok := datapath.Intersect(key, raw, e.IP); !ok {
				continue
			}
			c := model.SourceCandidate{Endpoint: e, Evidence: "Pod address matches the source constraint on this network. This does not establish that the pod sent the dropped traffic."}
			for _, o := range outgoing[e.Network+"/"+e.UID] {
				age := f.ObservedAt.Sub(o.End)
				if age < 0 {
					age = -age
				}
				if age > 90*time.Second || o.Destination.Node == "" || o.Destination.Node != f.Node || f.Protocol != "" && o.Protocol != "" && f.Protocol != o.Protocol || f.Destination.IP != "" && o.Destination.IP != "" && f.Destination.IP != o.Destination.IP || f.Destination.Port > 0 && o.Destination.Port > 0 && f.Destination.Port != o.Destination.Port {
					continue
				}
				if o.PacketDelta == nil || *o.PacketDelta == 0 {
					continue
				}
				c.Observed = true
				transport := o.Protocol
				if transport == "" {
					transport = "Protocol unidentified"
				}
				if o.Destination.Port > 0 {
					transport += fmt.Sprintf("/%d", o.Destination.Port)
				} else {
					transport += "; destination port unidentified"
				}
				c.Evidence = "Separate outgoing activity toward " + o.Destination.Node + " was observed (" + transport + "). Matching this activity to the drop is unconfirmed."
				break
			}
			candidates[e.UID+"/"+e.Network+"/"+e.IP] = c
		}
		for _, c := range candidates {
			context.Candidates = append(context.Candidates, c)
		}
		sort.Slice(context.Candidates, func(i, j int) bool {
			a, b := context.Candidates[i], context.Candidates[j]
			if a.Observed != b.Observed {
				return a.Observed
			}
			return label(a.Endpoint)+a.Endpoint.IP < label(b.Endpoint)+b.Endpoint.IP
		})
		context.TotalCandidates = len(context.Candidates)
		if len(context.Candidates) > 8 {
			context.Candidates = context.Candidates[:8]
		}
	}
}

func sourceAddress(raw string) string {
	if raw == "" {
		return ""
	}
	value, mask, masked := strings.Cut(raw, "/")
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return ""
	}
	if !masked {
		return addr.String()
	}
	bits, err := strconv.Atoi(mask)
	if err != nil {
		m, e := netip.ParseAddr(mask)
		if e != nil || m.BitLen() != addr.BitLen() {
			return ""
		}
		ones, width := net.IPMask(m.AsSlice()).Size()
		if width == 0 {
			return raw
		}
		bits = ones
	}
	if bits == 0 {
		return ""
	}
	if bits < 0 || bits > addr.BitLen() {
		return ""
	}
	if bits == addr.BitLen() {
		return addr.String()
	}
	return netip.PrefixFrom(addr, bits).Masked().String()
}
