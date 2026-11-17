// SPDX-License-Identifier: Apache-2.0
package routing

import (
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
)

func buildUplinks(inv model.Inventory, runtime map[string]model.NodeSnapshot) []Uplink {
	out := []Uplink{}
	networks := map[string][]string{}
	explicit := map[string]bool{}
	for _, c := range inv.Resources["clusteruserdefinednetworks"] {
		for _, name := range stringsOf(obj(c.Object["spec"])["uplinks"]) {
			networks[name] = union(networks[name], "cluster/"+c.GetName())
			explicit["cluster/"+c.GetName()] = true
		}
	}
	defaultNetworks := []string{"default"}
	for _, network := range ovn.Networks(inv) {
		if strings.EqualFold(network.Role, "primary") && !explicit[network.ID] {
			defaultNetworks = union(defaultNetworks, network.ID)
		}
	}
	states := map[string]map[string]any{}
	generations := map[string]int64{}
	for _, state := range inv.Resources["uplinkstates"] {
		spec := obj(state.Object["spec"])
		id := str(spec["uplinkName"]) + "/" + str(spec["nodeName"])
		states[id] = obj(state.Object["status"])
		generations[id] = state.GetGeneration()
	}
	for _, resource := range inv.Resources["uplinks"] {
		spec := obj(resource.Object["spec"])
		for _, node := range inv.Nodes {
			matches := []map[string]any{}
			for _, raw := range arr(spec["nodeConfigs"]) {
				c := obj(raw)
				if selector(c["nodeSelector"], node.Labels) {
					matches = append(matches, c)
				}
			}
			if len(matches) == 0 {
				continue
			}
			id := resource.GetName() + "/" + node.Name
			status := states[id]
			u := Uplink{ID: id, Name: resource.GetName(), Node: node.Name, Networks: networks[resource.GetName()], HostInterface: str(status["hostInterfaceName"]), Bridge: str(obj(status["ovsBridge"])["name"]), Addresses: stringsOf(status["ipAddresses"]), Gateways: stringsOf(status["defaultGateways"]), Conditions: arr(status["conditions"]), HostFunction: status["hostFunction"], Ready: "Unknown", Warnings: []string{}, Interfaces: []Interface{}}
			if u.HostInterface == "" && len(matches) == 1 {
				u.HostInterface = str(matches[0]["hostInterfaceName"])
			}
			if len(matches) > 1 {
				u.Warnings = append(u.Warnings, "Multiple node configurations select this node.")
				u.Ready = "Not ready"
			}
			ready := 0
			for _, raw := range u.Conditions {
				c := obj(raw)
				if str(c["type"]) != "Resolved" && str(c["type"]) != "GatewayReady" {
					continue
				}
				if observed := str(c["observedGeneration"]); observed != "" && observed != str(generations[id]) {
					u.Warnings = append(u.Warnings, "Uplink condition predates the current UplinkState generation.")
					continue
				}
				if str(c["status"]) == "False" {
					u.Ready = "Not ready"
					u.Warnings = append(u.Warnings, str(c["reason"])+": "+str(c["message"]))
				}
				if str(c["status"]) == "True" {
					ready++
				}
			}
			if ready == 2 && u.Ready != "Not ready" {
				u.Ready = "Ready"
			}
			enrichUplink(&u, runtime[node.Name])
			out = append(out, u)
		}
	}
	for _, node := range inv.Nodes {
		configs := map[string]map[string]any{}
		_ = json.Unmarshal([]byte(node.Annotations["k8s.ovn.org/l3-gateway-config"]), &configs)
		gateway := configs["default"]
		if gateway == nil {
			continue
		}
		u := Uplink{ID: "default/" + node.Name, Name: "Default gateway", Node: node.Name, Default: true, Networks: defaultNetworks, Addresses: stringsOf(gateway["ip-addresses"]), Gateways: stringsOf(gateway["next-hops"]), Ready: "Configured", VRF: "default", Warnings: []string{}, Interfaces: []Interface{}}
		// interface-id is an OVN chassis port identifier, not necessarily a Linux
		// interface name. Resolve the default bridge through its network mapping.
		for _, mapping := range strings.Split(strings.Trim(runtime[node.Name].Routing.BridgeMappings, "\" \n"), ",") {
			physical, bridge, ok := strings.Cut(mapping, ":")
			if ok && physical == "physnet" {
				if u.Bridge != "" && u.Bridge != bridge {
					u.Bridge = ""
					break
				}
				u.Bridge = bridge
			}
		}

		if u.Bridge != "" {
			u.HostInterface = u.Bridge
		}
		if u.Bridge == "" {
			u.Warnings = append(u.Warnings, "Default gateway bridge could not be uniquely resolved.")
		}
		if str(gateway["mode"]) == "local" {
			u.Warnings = append(u.Warnings, "Local gateway mode can route traffic through the host stack.")
		}
		enrichUplink(&u, runtime[node.Name])
		out = append(out, u)
	}
	return out
}
func enrichUplink(u *Uplink, n model.NodeSnapshot) {
	bridgePorts := []string{}
	interfaceIDs := []string{}
	for _, b := range n.Routing.Bridges {
		if str(b["name"]) == u.Bridge {
			bridgePorts = stringsOf(b["ports"])
		}
	}
	for _, p := range n.Routing.OVSPorts {
		if has(bridgePorts, str(p["_uuid"])) {
			interfaceIDs = union(interfaceIDs, stringsOf(p["interfaces"])...)
		}
	}
	for _, i := range n.Interfaces {
		if has(interfaceIDs, str(i["_uuid"])) || str(i["name"]) == u.HostInterface {
			u.Interfaces = append(u.Interfaces, Interface{Name: str(i["name"]), Type: str(i["type"]), State: str(i["link_state"]), MTU: i["mtu"], Statistics: ovn.Map(i["statistics"])})
		}
	}
	for _, link := range n.Routing.Links {
		if str(link["ifname"]) == u.HostInterface {
			u.VRF = "default"
			if master := str(link["master"]); master != "" {
				for _, v := range n.Routing.Links {
					if str(v["ifname"]) == master && str(obj(v["linkinfo"])["info_kind"]) == "vrf" {
						u.VRF = master
					}
				}
			}
			if len(u.Interfaces) == 0 {
				u.Interfaces = append(u.Interfaces, Interface{Name: u.HostInterface, State: str(link["operstate"]), MTU: link["mtu"]})
			}
		}
	}
}

// A shared VRF alone does not establish an uplink mapping. Resolve explicit
// interface peering, or every best matching route next hop in the peer's VRF.
func peerUplinks(p Peer, uplinks []Uplink, n model.NodeSnapshot, now time.Time) ([]string, string) {
	result := []string{}
	devices := []string{}
	reason := ""
	if p.Interface != "" {
		devices = append(devices, p.Interface)
		reason = "Configured peering interface"
	} else {
		if !fresh(n.Routing.CapturedAt, now) || !n.Routing.HostComplete {
			return result, "Host route evidence unavailable or stale"
		}
		ip, err := netip.ParseAddr(p.Address)
		if err != nil {
			return result, "Peer address unresolved"
		}
		table := "main"
		if p.VRF != "default" {
			table = ""
			for _, link := range n.Routing.Links {
				if str(link["ifname"]) == p.VRF {
					table = str(obj(obj(link["linkinfo"])["info_data"])["table"])
				}
			}
			if table == "" {
				return result, "Peer VRF table unresolved"
			}
		}
		bestBits := -1
		bestMetric := float64(1 << 53)
		for _, route := range n.Routing.Routes {
			if family := str(route["family"]); family != "" && (family == "ipv4") != ip.Is4() {
				continue
			}
			t := str(route["table"])
			if t == "" || t == "254" {
				t = "main"
			}
			if t != table {
				continue
			}
			if kind := str(route["type"]); kind != "" && kind != "unicast" {
				continue
			}
			dst := str(route["dst"])
			if dst == "default" {
				if ip.Is4() {
					dst = "0.0.0.0/0"
				} else {
					dst = "::/0"
				}
			}
			prefix, err := netip.ParsePrefix(dst)
			if err != nil || !prefix.Contains(ip) {
				continue
			}
			metric, _ := route["metric"].(float64)
			if prefix.Bits() < bestBits || prefix.Bits() == bestBits && metric > bestMetric {
				continue
			}
			if prefix.Bits() > bestBits || metric < bestMetric {
				devices = nil
				bestBits = prefix.Bits()
				bestMetric = metric
			}
			devices = union(devices, str(route["dev"]))
			for _, raw := range arr(route["nexthops"]) {
				devices = union(devices, str(obj(raw)["dev"]))
			}
		}
		reason = "Host route lookup in peer VRF"
	}
	for _, u := range uplinks {
		if u.Node != p.Node {
			continue
		}
		matched := has(devices, u.HostInterface) || has(devices, u.Bridge)
		for _, i := range u.Interfaces {
			matched = matched || has(devices, i.Name)
		}
		if matched {
			result = union(result, u.ID)
		}
	}
	if len(result) == 0 {
		return result, "No unique uplink association; egress interfaces: " + strings.Join(devices, ", ")
	}
	if len(result) > 1 {
		return result, reason + "; multiple candidate uplinks"
	}
	return result, reason + "; policy routing and remote physical adjacency are not inferred"
}
