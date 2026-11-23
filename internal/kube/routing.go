// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
)

type routingCache struct {
	Targets  nodeTargets
	Evidence model.RoutingEvidence
	Bytes    int
}

var routingName = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,63}$`)

func (c *Collector) captureRouting(name string, t nodeTargets, execute func(Target, ...string) (string, error)) model.RoutingEvidence {
	c.cacheMu.Lock()
	cached := c.routingCache[name]
	c.cacheMu.Unlock()
	if cached.Targets == t && time.Since(cached.Evidence.CapturedAt) < time.Minute {
		return cached.Evidence
	}
	e := model.RoutingEvidence{CapturedAt: time.Now().UTC(), Peers: []model.BGPRuntime{}, Errors: []string{}}
	started := time.Now()
	bytesRead := 0
	calls := 0
	run := func(target Target, args ...string) (string, bool) {
		if time.Since(started) > 20*time.Second || bytesRead > 4<<20 || calls >= 28 {
			e.Errors = append(e.Errors, "Routing collection budget reached; remaining evidence is unknown.")
			return "", false
		}
		calls++
		raw, err := execute(target, args...)
		bytesRead += len(raw)
		if err != nil {
			e.Errors = append(e.Errors, shortError(err))
			return "", false
		}
		if len(raw) > 1<<20 {
			e.Errors = append(e.Errors, "Routing command output exceeded 1 MiB; evidence omitted.")
			return "", false
		}
		return raw, true
	}
	if t.ovs.Pod != "" {
		array := func(args ...string) ([]model.Row, bool) {
			raw, ok := run(t.ovs, args...)
			if !ok {
				return nil, false
			}
			var rows []model.Row
			if err := json.Unmarshal([]byte(raw), &rows); err != nil {
				e.Errors = append(e.Errors, "Could not decode host routing JSON: "+err.Error())
				return nil, false
			}
			return rows, true
		}
		var ok, ok4, ok6 bool
		e.Links, ok = array("ip", "-j", "-d", "link", "show")
		routes4, ok4 := array("ip", "-j", "-4", "route", "show", "table", "all")
		routes6, ok6 := array("ip", "-j", "-6", "route", "show", "table", "all")
		for _, r := range routes4 {
			r["family"] = "ipv4"
		}
		for _, r := range routes6 {
			r["family"] = "ipv6"
		}
		e.Routes = append(routes4, routes6...)
		e.HostComplete = ok && ok4 && ok6
		table := func(target Target, args ...string) ([]model.Row, bool) {
			raw, ok := run(target, args...)
			if !ok {
				return nil, false
			}
			rows, err := ovn.DecodeTable(raw)
			if err != nil {
				e.Errors = append(e.Errors, "Could not decode routing OVSDB table: "+err.Error())
				return nil, false
			}
			return rows, true
		}
		e.BridgeMappings, _ = run(t.ovs, "ovs-vsctl", "--timeout=10", "--if-exists", "get", "Open_vSwitch", ".", "external_ids:ovn-bridge-mappings")
		e.Bridges, _ = table(t.ovs, "ovs-vsctl", "--timeout=10", "--format=json", "--columns=_uuid,name,ports,external_ids", "list", "Bridge")
		e.OVSPorts, _ = table(t.ovs, "ovs-vsctl", "--timeout=10", "--format=json", "--columns=_uuid,name,interfaces", "list", "Port")
		e.Routers, ok = table(t.ovn, "ovn-nbctl", "--timeout=10", "--db="+c.NBDB, "--format=json", "--columns=_uuid,name,external_ids,policies,nat", "list", "Logical_Router")
		e.Policies, ok4 = table(t.ovn, "ovn-nbctl", "--timeout=10", "--db="+c.NBDB, "--format=json", "--columns=_uuid,priority,match,action,nexthops,external_ids", "list", "Logical_Router_Policy")
		e.NAT, ok6 = table(t.ovn, "ovn-nbctl", "--timeout=10", "--db="+c.NBDB, "--format=json", "--columns=_uuid,type,logical_ip,external_ip,logical_port,external_ids", "list", "NAT")
		e.OVNComplete = ok && ok4 && ok6
	}
	if t.frr.Pod != "" {
		e.FRRTarget = t.frr.Namespace + "/" + t.frr.Pod
		raw, ok := run(t.frr, "vtysh", "-c", "show bgp vrf all summary json")
		if ok {
			peers, err := parseBGPSummary(raw)
			if err != nil {
				e.Errors = append(e.Errors, err.Error())
			} else {
				for j := range peers {
					p := &peers[j]
					if j >= 16 {
						p.Errors = append(p.Errors, "Peer query limit reached.")
						continue
					}
					if !routingName.MatchString(p.VRF) || !routingName.MatchString(p.Peer) {
						p.Errors = append(p.Errors, "Peer or VRF cannot be queried safely.")
						continue
					}
					command := fmt.Sprintf("show bgp vrf %s %s unicast neighbors %s advertised-routes json", p.VRF, p.Family, p.Peer)
					raw, ok := run(t.frr, "vtysh", "-c", command)
					if !ok {
						p.Errors = append(p.Errors, "Advertised routes unavailable.")
						continue
					}
					p.Advertised, p.Complete = advertisedPrefixes(raw)
					if !p.Complete {
						p.Errors = append(p.Errors, "Advertised route output incomplete or unrecognized.")
					}
				}
				e.Peers = peers
			}
		}
	}
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	if c.routingCache == nil {
		c.routingCache = map[string]routingCache{}
	}
	delete(c.routingCache, name)
	data, _ := json.Marshal(e)
	for {
		total := len(data)
		oldest := ""
		for key, v := range c.routingCache {
			total += v.Bytes
			if oldest == "" || v.Evidence.CapturedAt.Before(c.routingCache[oldest].Evidence.CapturedAt) {
				oldest = key
			}
		}
		if total <= 16<<20 || oldest == "" {
			break
		}
		delete(c.routingCache, oldest)
	}
	c.routingCache[name] = routingCache{t, e, len(data)}
	return e
}

func parseBGPSummary(raw string) ([]model.BGPRuntime, error) {
	var vrfs map[string]map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &vrfs); err != nil {
		return nil, fmt.Errorf("Could not decode FRR summary: %w", err)
	}
	out := []model.BGPRuntime{}
	for vrf, families := range vrfs {
		for _, family := range []string{"ipv4", "ipv6"} {
			data, ok := families[family+"Unicast"]
			if !ok {
				continue
			}
			var summary struct {
				Peers map[string]struct {
					State        string `json:"state"`
					LocalAddress string `json:"localAddress"`
					Interface    string `json:"interface"`
				} `json:"peers"`
			}
			if err := json.Unmarshal(data, &summary); err != nil {
				return nil, err
			}
			for address, p := range summary.Peers {
				out = append(out, model.BGPRuntime{VRF: vrf, Peer: address, Family: family, State: p.State, LocalAddress: p.LocalAddress, Interface: p.Interface, Advertised: []string{}})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].VRF+out[i].Peer+out[i].Family < out[j].VRF+out[j].Peer+out[j].Family
	})
	return out, nil
}
func advertisedPrefixes(raw string) ([]string, bool) {
	var data struct {
		Routes map[string]json.RawMessage `json:"advertisedRoutes"`
	}
	if json.Unmarshal([]byte(raw), &data) != nil || data.Routes == nil {
		return nil, false
	}
	out := []string{}
	for value := range data.Routes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, false
		}
		out = append(out, prefix.Masked().String())
		if len(out) > 10000 {
			sort.Strings(out)
			return out[:10000], false
		}
	}
	sort.Strings(out)
	return out, true
}

func discoverFRR(inv model.Inventory) map[string]Target {
	out := map[string]Target{}
	ambiguous := map[string]bool{}
	for _, p := range inv.Pods {
		if p.Spec.NodeName == "" || p.DeletionTimestamp != nil || p.Status.Phase != "Running" {
			continue
		}
		for _, c := range p.Spec.Containers {
			if c.Name != "frr" || !strings.Contains(c.Image, "frr") {
				continue
			}
			if _, ok := out[p.Spec.NodeName]; ok {
				ambiguous[p.Spec.NodeName] = true
			}
			out[p.Spec.NodeName] = Target{p.Namespace, p.Name, c.Name}
		}
	}
	for node := range ambiguous {
		delete(out, node)
	}
	return out
}
