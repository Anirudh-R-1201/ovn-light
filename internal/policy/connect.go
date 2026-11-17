// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func buildConnect(inv model.Inventory, p *Plan) error {
	i := p.Intent
	if _, supported := inv.Resources["clusternetworkconnects"]; !supported {
		return fmt.Errorf("ClusterNetworkConnect API is unavailable on this cluster")
	}
	if len(i.Networks) != 2 || i.Networks[0] == i.Networks[1] {
		return fmt.Errorf("select two different primary UDNs")
	}
	pool, err := netip.ParsePrefix(i.ConnectCIDR)
	if err != nil || pool != pool.Masked() {
		return fmt.Errorf("choose a canonical connect subnet CIDR")
	}
	if i.NetworkPrefix <= pool.Bits() || i.NetworkPrefix > pool.Addr().BitLen()-2 {
		return fmt.Errorf("network prefix must leave at least two allocations with usable addresses")
	}
	chosen := map[string]model.Network{}
	var namespaces, clusterNames []string
	for _, n := range ovn.Networks(inv) {
		for _, id := range i.Networks {
			if id == n.ID {
				chosen[id] = n
				if !strings.EqualFold(n.Role, "Primary") || !strings.EqualFold(n.Topology, "Layer2") && !strings.EqualFold(n.Topology, "Layer3") {
					return fmt.Errorf("%s must be a primary Layer2 or Layer3 network", id)
				}
				switch n.Kind {
				case "UserDefinedNetwork":
					namespaces = append(namespaces, n.Namespace)
				case "ClusterUserDefinedNetwork":
					clusterNames = append(clusterNames, n.Name)
				default:
					return fmt.Errorf("%s is not a UserDefinedNetwork or ClusterUserDefinedNetwork", id)
				}
			}
		}
	}
	if len(chosen) != 2 {
		return fmt.Errorf("one of the networks no longer exists")
	}
	var chosenPrefixes []netip.Prefix
	for _, id := range i.Networks {
		family := false
		for _, raw := range chosen[id].Subnets {
			prefix, e := netip.ParsePrefix(raw)
			if e != nil {
				continue
			}
			if prefix.Addr().BitLen() == pool.Addr().BitLen() {
				family = true
			}
			for _, other := range chosenPrefixes {
				if prefix.Overlaps(other) {
					return fmt.Errorf("selected networks have overlapping pod subnets (%s and %s)", prefix, other)
				}
			}
		}
		if !family {
			return fmt.Errorf("connect subnet IP family must be present on %s", id)
		}
		for _, raw := range chosen[id].Subnets {
			if prefix, e := netip.ParsePrefix(raw); e == nil {
				chosenPrefixes = append(chosenPrefixes, prefix)
			}
		}
	}
	for _, n := range ovn.Networks(inv) {
		for _, raw := range n.Subnets {
			if prefix, e := netip.ParsePrefix(raw); e == nil && pool.Overlaps(prefix) {
				return fmt.Errorf("connect subnet overlaps %s subnet %s", n.ID, prefix)
			}
		}
	}
	for _, s := range inv.Services {
		for _, ip := range s.Spec.ClusterIPs {
			if a, e := netip.ParseAddr(ip); e == nil && pool.Contains(a) {
				return fmt.Errorf("connect subnet includes Service IP %s", a)
			}
		}
	}
	for _, r := range inv.Resources["clusternetworkconnects"] {
		subnets, _, _ := unstructured.NestedSlice(r.Object, "spec", "connectSubnets")
		for _, v := range subnets {
			if m, ok := v.(map[string]any); ok {
				if prefix, e := netip.ParsePrefix(ovn.Str(m["cidr"])); e == nil && pool.Overlaps(prefix) {
					return fmt.Errorf("connect subnet overlaps existing ClusterNetworkConnect %s", r.GetName())
				}
			}
		}
	}
	var selectors []any
	if len(namespaces) > 0 {
		sort.Strings(namespaces)
		selectors = append(selectors, map[string]any{"networkSelectionType": "PrimaryUserDefinedNetworks", "primaryUserDefinedNetworkSelector": map[string]any{"namespaceSelector": map[string]any{"matchExpressions": []any{map[string]any{"key": "kubernetes.io/metadata.name", "operator": "In", "values": stringSlice(namespaces)}}}}})
	}
	if len(clusterNames) > 0 {
		selector, e := clusterSelector(inv, clusterNames)
		if e != nil {
			return e
		}
		selectors = append(selectors, map[string]any{"networkSelectionType": "ClusterUserDefinedNetworks", "clusterUserDefinedNetworkSelector": map[string]any{"networkSelector": selector}})
	}
	connectivity := []any{"PodNetwork"}
	if i.Services {
		connectivity = append(connectivity, "ServiceNetwork")
	}
	name := "ovn-light-" + p.ID[:12]
	p.Objects = []unstructured.Unstructured{{Object: map[string]any{"apiVersion": "k8s.ovn.org/v1", "kind": "ClusterNetworkConnect", "metadata": map[string]any{"name": name, "labels": map[string]any{"app.kubernetes.io/managed-by": "ovn-light"}, "annotations": map[string]any{"ovn-light.io/plan": p.ID}}, "spec": map[string]any{"networkSelectors": selectors, "connectSubnets": []any{map[string]any{"cidr": pool.String(), "networkPrefix": int64(i.NetworkPrefix)}}, "connectivity": connectivity}}}}
	p.Summary = fmt.Sprintf("Connect %s ↔ %s", i.Networks[0], i.Networks[1])
	p.Affected = append(p.Affected, i.Networks...)
	p.Warnings = append(p.Warnings, "Connecting networks changes reachability for all their workloads. Existing NetworkPolicies still apply.", "Check the connect subnet against your infrastructure, node, service and external address pools; inventory cannot establish that an unused range is safe.", "Selectors also select future matching networks. Cross-network policy selector support depends on your OVN-Kubernetes version.", "Accepted status reports controller progress, not proof of end-to-end connectivity.")
	return nil
}
func stringSlice(ss []string) []any {
	out := []any{}
	for _, s := range ss {
		out = append(out, s)
	}
	return out
}
func clusterSelector(inv model.Inventory, names []string) (map[string]any, error) {
	wanted := map[string]bool{}
	for _, n := range names {
		wanted[n] = true
	}
	var first map[string]string
	for _, r := range inv.Resources["clusteruserdefinednetworks"] {
		if wanted[r.GetName()] {
			first = r.GetLabels()
			break
		}
	}
	keys := []string{}
	for k := range first {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values := map[string]bool{}
		valid := true
		for _, r := range inv.Resources["clusteruserdefinednetworks"] {
			if wanted[r.GetName()] {
				v, ok := r.GetLabels()[key]
				if !ok {
					valid = false
					break
				}
				values[v] = true
			}
		}
		if !valid {
			continue
		}
		for _, r := range inv.Resources["clusteruserdefinednetworks"] {
			v, exists := r.GetLabels()[key]
			matches := exists && values[v]
			if matches != wanted[r.GetName()] {
				valid = false
				break
			}
		}
		if valid {
			vs := []string{}
			for v := range values {
				vs = append(vs, v)
			}
			sort.Strings(vs)
			return map[string]any{"matchExpressions": []any{map[string]any{"key": key, "operator": "In", "values": stringSlice(vs)}}}, nil
		}
	}
	// A conjunction can distinguish a single network where one label cannot.
	if len(names) == 1 && len(first) > 0 {
		sel := meta.LabelSelector{MatchLabels: first}
		valid := true
		for _, r := range inv.Resources["clusteruserdefinednetworks"] {
			if selected(sel, r.GetLabels()) != wanted[r.GetName()] {
				valid = false
			}
		}
		if valid {
			ls := map[string]any{}
			for k, v := range first {
				ls[k] = v
			}
			return map[string]any{"matchLabels": ls}, nil
		}
	}
	return nil, fmt.Errorf("selected ClusterUserDefinedNetworks need a label selector that uniquely selects them; add an identifying label and refresh")
}
