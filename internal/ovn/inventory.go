// SPDX-License-Identifier: Apache-2.0
package ovn

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strings"

	"github.com/trozet/ovn-light/internal/model"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type Attachment struct {
	Endpoint    model.Endpoint
	LogicalPort string
	MAC         string
	Node        string
	Primary     bool
}

func Attachments(inv model.Inventory) []Attachment {
	var out []Attachment
	aliases, _ := networkAliases(inv)
	for _, p := range inv.Pods {
		if p.Spec.HostNetwork {
			continue
		}
		var networks map[string]struct {
			IPs  []string `json:"ip_addresses"`
			MAC  string   `json:"mac_address"`
			Role string   `json:"role"`
		}
		_ = json.Unmarshal([]byte(p.Annotations["k8s.ovn.org/pod-networks"]), &networks)
		if len(networks) == 0 {
			role := "primary"
			if p.Annotations["k8s.ovn.org/pod-networks"] != "" {
				role = "unknown"
			}
			for _, ns := range inv.Namespaces {
				if ns.Name == p.Namespace {
					if _, udn := ns.Labels["k8s.ovn.org/primary-user-defined-network"]; udn {
						role = "unknown"
					}
				}
			}
			for _, ip := range p.Status.PodIPs {
				e := endpoint(p, "default", ip.IP)
				setRole(&e, role)
				out = append(out, Attachment{Endpoint: e, LogicalPort: p.Namespace + "_" + p.Name, Node: p.Spec.NodeName, Primary: role == "primary"})
			}
			continue
		}
		hasPrimaryUDN := false
		for net, n := range networks {
			if net != "default" && (n.Role == "primary" || n.Role == "" && strings.EqualFold(Str(NADConfig(inv, net)["role"]), "primary")) {
				hasPrimaryUDN = true
			}
		}
		for net, n := range networks {
			role := strings.ToLower(n.Role)
			if net == "default" {
				if hasPrimaryUDN {
					role = "infrastructure"
				} else if role == "" {
					role = "primary"
				}
			} else if role == "" {
				config := NADConfig(inv, net)
				if Str(config["type"]) == "ovn-k8s-cni-overlay" {
					role = strings.ToLower(Str(config["role"]))
					if role == "" {
						role = "secondary"
					}
				} else {
					role = "unknown"
				}
			}
			port := p.Namespace + "_" + p.Name
			identity := net
			if alias := aliases[net]; alias != "" {
				identity = alias
			}
			if net != "default" {
				// OVN scopes pod ports by the NAD key, even when several NADs
				// share the same network name in their CNI configuration.
				port = strings.NewReplacer("/", ".", "-", ".").Replace(net) + "_" + port
			}
			for _, ip := range n.IPs {
				if prefix, err := netip.ParsePrefix(ip); err == nil {
					ip = prefix.Addr().String()
				}
				e := endpoint(p, identity, ip)
				setRole(&e, role)
				if net != "default" {
					e.NAD = net
				}
				out = append(out, Attachment{Endpoint: e, LogicalPort: port, MAC: n.MAC, Node: p.Spec.NodeName, Primary: role == "primary"})
			}
		}
	}
	return out
}

func setRole(e *model.Endpoint, role string) {
	e.Role = role
	switch role {
	case "primary":
		e.PolicyKind = "NetworkPolicy"
	case "secondary":
		e.PolicyKind = "MultiNetworkPolicy"
	}
}

func NADConfig(inv model.Inventory, nad string) map[string]any {
	for _, r := range inv.Resources["network-attachment-definitions"] {
		if r.GetNamespace()+"/"+r.GetName() == nad {
			raw, _, _ := unstructured.NestedString(r.Object, "spec", "config")
			var config map[string]any
			_ = json.Unmarshal([]byte(raw), &config)
			return config
		}
	}
	return nil
}

// Several NADs may refer to one OVN network. Policies select NADs, while flow
// identity must stay shared across those attachments and their namespaces.
func NetworkForNAD(inv model.Inventory, nad string) string {
	aliases, _ := networkAliases(inv)
	return aliases[nad]
}

func networkAliases(inv model.Inventory) (map[string]string, map[string]string) {
	aliases, names := map[string]string{}, map[string]string{}
	owners := map[string]string{}
	for _, r := range inv.Resources["network-attachment-definitions"] {
		id := r.GetNamespace() + "/" + r.GetName()
		config, _, _ := unstructured.NestedString(r.Object, "spec", "config")
		var c map[string]any
		_ = json.Unmarshal([]byte(config), &c)
		if Str(c["type"]) != "ovn-k8s-cni-overlay" {
			continue
		}
		names[id] = Str(c["name"])
		if names[id] != "" {
			aliases[id] = "network:" + names[id]
		}
		for _, owner := range r.GetOwnerReferences() {
			switch owner.Kind {
			case "ClusterUserDefinedNetwork":
				aliases[id] = "cluster/" + owner.Name
				owners[names[id]] = aliases[id]
			case "UserDefinedNetwork":
				aliases[id] = r.GetNamespace() + "/" + owner.Name
				owners[names[id]] = aliases[id]
			}
		}
	}
	for id, name := range names {
		if owners[name] != "" {
			aliases[id] = owners[name]
		}
	}
	return aliases, names
}
func endpoint(p core.Pod, network, ip string) model.Endpoint {
	return model.Endpoint{Node: p.Spec.NodeName, Namespace: p.Namespace, Pod: p.Name, UID: string(p.UID), Network: network, IP: ip, Labels: p.Labels}
}

func Networks(inv model.Inventory) []model.Network {
	aliases, _ := networkAliases(inv)
	out := []model.Network{{ID: "default", Name: "Default network", Kind: "ClusterNetwork", Role: "Primary", Topology: "Layer3", Subnets: []string{}}}
	seenNetworks := map[string]bool{}
	for _, kind := range []string{"userdefinednetworks", "clusteruserdefinednetworks", "network-attachment-definitions"} {
		for _, r := range inv.Resources[kind] {
			id := r.GetNamespace() + "/" + r.GetName()
			if kind == "network-attachment-definitions" && aliases[id] != "" {
				if !strings.HasPrefix(aliases[id], "network:") {
					continue
				}
				id = aliases[id]
				if seenNetworks[id] {
					continue
				}
				seenNetworks[id] = true
			}
			if kind == "clusteruserdefinednetworks" {
				id = "cluster/" + r.GetName()
			}
			spec, _, _ := unstructured.NestedMap(r.Object, "spec")
			if kind == "clusteruserdefinednetworks" {
				spec = Map(spec["network"])
			}
			if kind == "network-attachment-definitions" {
				var config map[string]any
				if json.Unmarshal([]byte(Str(spec["config"])), &config) != nil {
					continue
				}
				if Str(config["type"]) != "ovn-k8s-cni-overlay" {
					continue
				}
				spec = config
			}
			top := Str(spec["topology"])
			conf := Map(spec[strings.ToLower(top)])
			role := Str(conf["role"])
			if role == "" {
				role = Str(spec["role"])
			}
			if role == "" {
				role = "Secondary"
			}
			var subnets []string
			if list, ok := conf["subnets"].([]any); ok {
				for _, s := range list {
					if m, ok := s.(map[string]any); ok {
						subnets = append(subnets, Str(m["cidr"]))
					} else {
						subnets = append(subnets, Str(s))
					}
				}
			}
			if len(subnets) == 0 && Str(spec["subnets"]) != "" {
				subnets = strings.Split(Str(spec["subnets"]), ",")
			}
			conditions, _, _ := unstructured.NestedSlice(r.Object, "status", "conditions")
			out = append(out, model.Network{ID: id, Name: r.GetName(), Namespace: r.GetNamespace(), Kind: r.GetKind(), Topology: top, Role: role, Subnets: subnets, Labels: r.GetLabels(), Conditions: conditions})
		}
	}
	attachments := Attachments(inv)
	for i := range out {
		seen := map[string]bool{}
		for _, a := range attachments {
			if a.Endpoint.Network == out[i].ID {
				seen[a.Endpoint.UID] = true
			}
		}
		out[i].Pods = len(seen)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
