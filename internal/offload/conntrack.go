// SPDX-License-Identifier: Apache-2.0
package offload

import (
	"bufio"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/trozet/ovn-light/internal/datapath"
	"github.com/trozet/ovn-light/internal/model"
)

type tuple struct{ protocol, src, dst, sport, dport string }

func (t tuple) reverse() tuple { return tuple{t.protocol, t.dst, t.src, t.dport, t.sport} }
func (t tuple) key(zone string) string {
	return strings.Join([]string{zone, t.protocol, t.src, t.dst, t.sport, t.dport}, "/")
}

type ctEntry struct {
	original, reply              tuple
	zone, raw, reason            string
	origHW, replyHW, established bool
}
type ctRef struct {
	entry     int
	direction string
}
type ctIndex struct {
	entries []ctEntry
	byTuple map[string][]ctRef
	valid   bool
}

func parseTuple(s, protocol string) (tuple, bool) {
	t := tuple{protocol: protocol}
	fields := map[string]string{}
	for _, f := range datapath.Split(strings.TrimSuffix(strings.TrimPrefix(s, "("), ")")) {
		k, v, ok := strings.Cut(f, "=")
		if ok {
			fields[k] = v
		}
	}
	src, err1 := netip.ParseAddr(fields["src"])
	dst, err2 := netip.ParseAddr(fields["dst"])
	a, err3 := strconv.ParseUint(fields["sport"], 10, 16)
	b, err4 := strconv.ParseUint(fields["dport"], 10, 16)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return t, false
	}
	t.src, t.dst, t.sport, t.dport = src.String(), dst.String(), strconv.FormatUint(a, 10), strconv.FormatUint(b, 10)
	return t, true
}
func parseCT(raw string) ctIndex {
	x := ctIndex{byTuple: map[string][]ctRef{}, valid: true}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := datapath.Split(line)
		if len(fields) == 0 {
			continue
		}
		proto := strings.ToLower(fields[0])
		if proto != "tcp" && proto != "udp" && proto != "sctp" {
			// Other protocols are not candidates for the transport offload analysis.
			if !strings.Contains(line, "orig=(") {
				x.valid = false
			}
			continue
		}
		e := ctEntry{zone: "0", raw: line, established: false}
		origOK, replyOK := false, false
		for _, f := range fields[1:] {
			k, v, ok := strings.Cut(f, "=")
			if ok {
				switch k {
				case "orig":
					e.original, origOK = parseTuple(v, proto)
				case "reply":
					e.reply, replyOK = parseTuple(v, proto)
				case "zone":
					z, err := strconv.ParseUint(v, 10, 16)
					if err != nil {
						x.valid = false
					}
					e.zone = strconv.FormatUint(z, 10)
				case "status":
					if proto == "udp" {
						e.established = strings.Contains(v, "SEEN_REPLY") || strings.Contains(v, "ASSURED")
					}
				case "protoinfo":
					e.established = e.established || strings.Contains(v, "state=ESTABLISHED")
				case "reply_offload_deferred":
					e.reason = v
				}
			}
			if f == "orig_offloaded:yes" {
				e.origHW = true
			}
			if f == "reply_offloaded:yes" {
				e.replyHW = true
			}
		}
		if !origOK || !replyOK {
			x.valid = false
			continue
		}
		idx := len(x.entries)
		x.entries = append(x.entries, e)
		// The reverse reply tuple identifies the original direction after NAT.
		// Keep the zone in every key; two UDNs can use identical addresses.
		for _, r := range []struct {
			t   tuple
			dir string
		}{{e.original, "original"}, {e.reply.reverse(), "original"}, {e.reply, "reply"}, {e.original.reverse(), "reply"}} {
			key := r.t.key(e.zone)
			ref := ctRef{idx, r.dir}
			duplicate := false
			for _, old := range x.byTuple[key] {
				if old == ref {
					duplicate = true
				}
			}
			if !duplicate {
				x.byTuple[key] = append(x.byTuple[key], ref)
			}
		}
	}
	if scanner.Err() != nil {
		x.valid = false
	}
	return x
}
func matchTuple(m map[string]string) (tuple, bool) {
	fields := map[string]string{}
	proto := ""
	for _, family := range []string{"ipv4", "ipv6"} {
		switch datapath.Exact(family+".proto", m[family+".proto"]) {
		case "6":
			proto = "tcp"
		case "17":
			proto = "udp"
		case "132":
			proto = "sctp"
		}
		if src := datapath.Exact(family+".src", m[family+".src"]); src != "" {
			fields["src"] = src
			fields["dst"] = datapath.Exact(family+".dst", m[family+".dst"])
		}
	}
	if proto == "" {
		return tuple{}, false
	}
	fields["sport"] = datapath.Exact(proto+".src", m[proto+".src"])
	fields["dport"] = datapath.Exact(proto+".dst", m[proto+".dst"])
	return parseTuple(fmt.Sprintf("(src=%s,dst=%s,sport=%s,dport=%s)", fields["src"], fields["dst"], fields["sport"], fields["dport"]), proto)
}
func ctZones(actions string) []string {
	var zones []string
	for _, a := range datapath.Split(actions) {
		if strings.HasPrefix(a, "clone(") {
			zones = append(zones, ctZones(strings.TrimSuffix(a[6:], ")"))...)
		}
		if !strings.HasPrefix(a, "ct(") {
			continue
		}
		zone := "0"
		for _, f := range datapath.Split(strings.TrimSuffix(a[3:], ")")) {
			if z, ok := strings.CutPrefix(f, "zone="); ok {
				v, err := strconv.ParseUint(z, 0, 16)
				if err != nil {
					zone = "unknown"
				} else {
					zone = strconv.FormatUint(v, 10)
				}
			}
		}
		zones = append(zones, zone)
	}
	return zones
}
func pathCT(n model.NodeSnapshot, p datapath.Path, x ctIndex, fresh bool) []model.OffloadCT {
	var result []model.OffloadCT
	seen := map[string]bool{}
	for _, f := range p.Flows {
		zones := ctZones(f.Actions)
		if len(zones) == 0 && strings.Contains(f.Match["ct_state"], "+trk") {
			z := datapath.Exact("ct_zone", f.Match["ct_zone"])
			if z == "" {
				z = "unknown"
			}
			zones = append(zones, z)
		}
		for _, zone := range zones {
			t, exact := matchTuple(f.Match)
			key := t.key(zone)
			if !exact {
				key = zone + "/unknown"
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			c := model.OffloadCT{Zone: zone, Status: "unknown", Original: "unknown", Reply: "unknown", CapturedAt: n.Offload.CapturedAt}
			switch {
			case !fresh || !n.Offload.CTComplete || !n.Offload.CTSupported:
				c.Reason = "Conntrack offload evidence is unavailable or stale."
			case !x.valid:
				c.Reason = "Conntrack dump was incomplete or could not be decoded."
			case !exact || zone == "unknown":
				c.Reason = "An exact tuple and conntrack zone are required."
			case len(x.byTuple[key]) != 1:
				c.Reason = "No unique matching conntrack entry was observed."
			default:
				ref := x.byTuple[key][0]
				e := x.entries[ref.entry]
				c.Raw, c.Direction = e.raw, ref.direction
				c.Original, c.Reply = "software", "software"
				if e.origHW {
					c.Original = "hardware"
				}
				if e.replyHW {
					c.Reply = "hardware"
				}
				c.Status = c.Original
				if ref.direction == "reply" {
					c.Status = c.Reply
				}
				c.Reason = e.reason
				if c.Status == "software" && e.original.protocol == "udp" && !e.established && n.Offload.Config["hw-offload-ct-unidir-udp-enabled"] != "true" {
					c.Status = "pending"
					c.Reason = "No return traffic recorded; unidirectional UDP offload is not enabled."
				} else if c.Status == "software" && !e.established && e.original.protocol != "udp" {
					c.Status = "pending"
					c.Reason = "Connection is not established; software setup may be expected."
				}
			}
			if c.Status == "software" && n.Offload.Config["hw-offload-ct-size"] == "0" {
				c.Status = "unknown"
				c.Reason = "Global CT offload capacity is zero; per-device CT configuration needs review."
			}
			if c.Status == "software" && strings.Contains(t.src, ":") && n.Offload.Config["hw-offload-ct-ipv6-enabled"] != "true" {
				c.Status = "not-expected"
				c.Reason = "IPv6 conntrack offload is not enabled in the collected configuration."
			}
			result = append(result, c)
		}
	}
	return result
}
