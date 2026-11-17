// SPDX-License-Identifier: Apache-2.0
package routing

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
)

func buildEgress(s model.Snapshot, v model.View, previous *Report) []Egress {
	out := []Egress{}
	inv := s.Inventory
	attachments := ovn.Attachments(inv)
	nat := natAssociations(s)
	traffic := map[string][]model.TrafficObservation{}
	for _, o := range v.Traffic {
		if o.Verdict == "forward" && o.PacketDelta != nil && *o.PacketDelta > 0 && !o.Shared && externalDestination(o.Destination, inv, attachments) {
			key := o.Network + "/" + o.Source.UID + "/" + o.Source.IP
			traffic[key] = append(traffic[key], o)
		}
	}
	namespaces := map[string]map[string]string{}
	for _, ns := range inv.Namespaces {
		namespaces[ns.Name] = ns.Labels
	}
	namespaceNetworks := map[string][]string{}
	for _, nad := range inv.Resources["network-attachment-definitions"] {
		id := nad.GetNamespace() + "/" + nad.GetName()
		conf := ovn.NADConfig(inv, id)
		if str(conf["type"]) == "ovn-k8s-cni-overlay" && strings.EqualFold(str(conf["role"]), "primary") {
			namespaceNetworks[nad.GetNamespace()] = union(namespaceNetworks[nad.GetNamespace()], ovn.NetworkForNAD(inv, id))
		}
	}
	for _, ns := range inv.Namespaces {
		if _, udn := ns.Labels["k8s.ovn.org/primary-user-defined-network"]; !udn && len(namespaceNetworks[ns.Name]) == 0 {
			namespaceNetworks[ns.Name] = []string{"default"}
		}
	}
	old := map[string]Assignment{}
	if previous != nil {
		for _, e := range previous.Egress {
			for _, a := range e.Assignments {
				old[e.UID+"/"+e.Name+"/"+a.IP] = a
			}
		}
	}
	for _, resource := range inv.Resources["egressips"] {
		spec := obj(resource.Object["spec"])
		e := Egress{UID: string(resource.GetUID()), Name: resource.GetName(), Requested: stringsOf(spec["egressIPs"]), Networks: []string{}, Assignments: []Assignment{}, Pods: []model.Endpoint{}, Paths: []EgressPath{}, Warnings: []string{}}
		// Advertisements follow selected namespaces even before their pods exist.
		for name, labels := range namespaces {
			if selector(spec["namespaceSelector"], labels) && len(namespaceNetworks[name]) == 1 {
				e.Networks = union(e.Networks, namespaceNetworks[name]...)
			}
		}
		for _, raw := range arr(obj(resource.Object["status"])["items"]) {
			item := obj(raw)
			a := Assignment{IP: str(item["egressIP"]), Node: str(item["node"]), Ready: "Unknown"}
			for _, n := range inv.Nodes {
				if n.Name == a.Node {
					for _, c := range n.Status.Conditions {
						if c.Type == "Ready" {
							a.Ready = string(c.Status)
						}
					}
				}
			}
			if prev := old[e.UID+"/"+e.Name+"/"+a.IP]; prev.Node != "" {
				if prev.Node != a.Node {
					a.PreviousNode = prev.Node
					at := s.CapturedAt
					a.MovedAt = &at
				} else {
					a.PreviousNode = prev.PreviousNode
					a.MovedAt = prev.MovedAt
				}
			}
			e.Assignments = append(e.Assignments, a)
		}
		for _, a := range attachments {
			p := a.Endpoint
			if p.Role != "primary" {
				continue
			}
			if !selector(spec["namespaceSelector"], namespaces[p.Namespace]) || !selector(spec["podSelector"], p.Labels) {
				continue
			}
			e.Pods = append(e.Pods, p)
			e.Networks = union(e.Networks, p.Network)
		}
		sort.Slice(e.Pods, func(i, j int) bool {
			return e.Pods[i].Namespace+e.Pods[i].Pod+e.Pods[i].IP < e.Pods[j].Namespace+e.Pods[j].Pod+e.Pods[j].IP
		})
		e.PodCount = len(e.Pods)
		for _, pod := range e.Pods {
			for _, a := range e.Assignments {
				src, err1 := netip.ParseAddr(pod.IP)
				dst, err2 := netip.ParseAddr(a.IP)
				if err1 != nil || err2 != nil || src.Is4() != dst.Is4() {
					continue
				}
				e.PathCount++
				if len(e.Paths) >= 200 {
					continue
				}
				path := EgressPath{Source: pod, Assignment: a, Evidence: []string{}, Traffic: []model.TrafficObservation{}}
				networkName := "default"
				if pod.Network != "default" {
					networkName = str(ovn.NADConfig(inv, pod.NAD)["name"])
				}
				if networkName != "" {
					router := "GR_" + a.Node
					if networkName != "default" {
						router = "GR_" + networkName + "_" + a.Node
					}
					path.Evidence = append(path.Evidence, nat[router+"/"+cidr(pod.IP)+"/"+a.IP]...)
					path.Programmed = len(path.Evidence) > 0
				}
				for _, o := range traffic[pod.Network+"/"+pod.UID+"/"+pod.IP] {
					if o.Node != pod.Node && o.Node != a.Node {
						continue
					}
					if len(path.Traffic) < 12 {
						path.Traffic = append(path.Traffic, o)
					}
					if o.Node == a.Node {
						path.ObservedAtEgress = true
					}
				}
				e.Paths = append(e.Paths, path)
			}
		}
		if len(e.Assignments) > 1 {
			e.Warnings = append(e.Warnings, "Multiple IP/node assignments can serve these pods. Each line is an assigned path; a per-connection choice is not inferred from selectors.")
		}
		if len(e.Paths) < e.PathCount {
			e.Warnings = append(e.Warnings, fmt.Sprintf("Retaining the first %d of %d assigned pod paths. Additional paths are omitted from this collection.", len(e.Paths), e.PathCount))
		}
		e.Warnings = append(e.Warnings, "Assignment and programmed SNAT are configuration evidence. Traffic observations do not prove the translated source address reached the external destination. Host-stack or accelerated NAT may not be visible in OVN tables.")
		if len(e.Pods) > 200 {
			e.Pods = e.Pods[:200]
		}
		out = append(out, e)
	}
	owners := map[string][]int{}
	for i, e := range out {
		for _, p := range e.Pods {
			key := p.Network + "/" + p.UID
			owners[key] = append(owners[key], i)
		}
	}
	for _, selected := range owners {
		if len(selected) < 2 {
			continue
		}
		for _, i := range selected {
			for _, j := range selected {
				if i != j {
					out[i].Warnings = union(out[i].Warnings, "Workload selection overlaps EgressIP "+out[j].Name+"; effective ownership is not inferred.")
				}
			}
		}
	}
	return out
}
func externalDestination(e model.Endpoint, inv model.Inventory, attachments []ovn.Attachment) bool {
	if e.IP == "" || e.UID != "" {
		return false
	}
	ip, err := netip.ParseAddr(e.IP)
	if err != nil {
		return false
	}
	for _, p := range attachments {
		if p.Endpoint.Network == e.Network && p.Endpoint.IP == e.IP {
			return false
		}
	}
	for _, n := range inv.Nodes {
		for _, a := range n.Status.Addresses {
			if a.Address == e.IP {
				return false
			}
		}
	}
	for _, s := range inv.Services {
		if has(s.Spec.ClusterIPs, e.IP) {
			return false
		}
	}
	for _, network := range ovn.Networks(inv) {
		if network.ID != e.Network {
			continue
		}
		for _, raw := range network.Subnets {
			prefix, err := netip.ParsePrefix(strings.Split(raw, " ")[0])
			if err == nil && prefix.Contains(ip) {
				return false
			}
		}
	}
	return true
}

// Index NAT once per collection; otherwise every selected pod scans every
// node's copy of the northbound database.
func natAssociations(s model.Snapshot) map[string][]string {
	out := map[string][]string{}
	for _, n := range s.Nodes {
		if !fresh(n.Routing.CapturedAt, s.CapturedAt) {
			continue
		}
		byID := map[string]model.Row{}
		for _, nat := range n.Routing.NAT {
			if str(nat["type"]) == "snat" {
				byID[str(nat["_uuid"])] = nat
			}
		}
		for _, router := range n.Routing.Routers {
			for _, id := range stringsOf(router["nat"]) {
				nat := byID[id]
				if nat == nil {
					continue
				}
				name := str(router["name"])
				key := name + "/" + cidr(str(nat["logical_ip"])) + "/" + str(nat["external_ip"])
				out[key] = union(out[key], "OVN SNAT "+id+" on "+name)
			}
		}
	}
	return out
}
