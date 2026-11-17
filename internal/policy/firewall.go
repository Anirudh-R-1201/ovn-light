// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
	core "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

// The original spec and UID make insertion and rollback conditional on the
// reviewed firewall. Index is zero-based in spec.egress, including after restart.
type FirewallChange struct {
	Namespace  string         `json:"namespace"`
	Name       string         `json:"name"`
	UID        string         `json:"uid"`
	Index      int            `json:"index"`
	BeforeSpec map[string]any `json:"beforeSpec"`
}

func buildFirewall(inv model.Inventory, p *Plan) error {
	i := p.Intent
	i.Protocol = strings.ToUpper(i.Protocol)
	if i.Protocol != "TCP" && i.Protocol != "UDP" && i.Protocol != "SCTP" || i.Port < 1 || i.Port > 65535 {
		return fmt.Errorf("choose TCP, UDP or SCTP and a destination port between 1 and 65535")
	}
	src, attachment, err := findPod(inv, i.Source)
	if err != nil {
		return err
	}
	if attachment.Endpoint.Network != "default" || attachment.Endpoint.Role != "primary" {
		return fmt.Errorf("EgressFirewall remediation currently supports the primary cluster default network only")
	}
	ip, err := netip.ParseAddr(i.Destination.IP)
	if err != nil || ip.Zone() != "" || !ip.IsGlobalUnicast() {
		return fmt.Errorf("choose an exact external unicast IP; DNS names and address ranges are not inferred")
	}
	ip = ip.Unmap()
	if i.Destination.Pod != "" || i.Destination.Namespace != "" || i.Destination.Network != "" && i.Destination.Network != "default" {
		return fmt.Errorf("choose an external destination on the default network")
	}
	for _, a := range ovn.Attachments(inv) {
		if a.Endpoint.Network == "default" && a.Endpoint.IP == ip.String() {
			return fmt.Errorf("destination is a cluster pod; review NetworkPolicy instead")
		}
	}
	for _, svc := range inv.Services {
		for _, address := range svc.Spec.ClusterIPs {
			if address == ip.String() {
				return fmt.Errorf("destination is a cluster Service; choose its workload instead")
			}
		}
	}
	i.Source = attachment.Endpoint
	i.Destination = model.Endpoint{Network: "default", IP: ip.String(), Port: i.Port}
	p.Intent = i
	for _, kind := range []string{"adminnetworkpolicies", "baselineadminnetworkpolicies"} {
		for _, policy := range inv.Resources[kind] {
			subject, _, _ := unstructured.NestedMap(policy.Object, "spec", "subject")
			if subjectMatches(inv, subject, src) {
				return fmt.Errorf("%s %s selects the source; review its ordered rules first", policy.GetKind(), policy.GetName())
			}
		}
	}
	if !externalEgressAllowed(inv, src, i) {
		return fmt.Errorf("NetworkPolicy also isolates this external connection; review its egress allowance before changing the EgressFirewall")
	}
	var firewalls []unstructured.Unstructured
	for _, firewall := range inv.Resources["egressfirewalls"] {
		if firewall.GetNamespace() == src.Namespace {
			firewalls = append(firewalls, firewall)
		}
	}
	if len(firewalls) != 1 || firewalls[0].GetUID() == "" {
		return fmt.Errorf("expected one existing EgressFirewall with a known UID in namespace %s", src.Namespace)
	}
	firewall := firewalls[0]
	rules, ok, err := unstructured.NestedSlice(firewall.Object, "spec", "egress")
	if err != nil || !ok || len(rules) >= 8000 {
		return fmt.Errorf("firewall rules are missing, malformed or have no insertion capacity")
	}
	index := -1
	for j, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("invalid EgressFirewall rule %d", j+1)
		}
		ports, err := firewallPortsMatch(rule, i)
		if err != nil {
			return err
		}
		if !ports {
			continue
		}
		to := ovn.Map(rule["to"])
		cidr, err := netip.ParsePrefix(ovn.Str(to["cidrSelector"]))
		if err != nil || len(to) != 1 {
			return fmt.Errorf("rule %d uses a DNS, node selector or unknown destination; its precedence must be reviewed before proposing an IP exception", j+1)
		}
		if !cidr.Contains(ip) {
			continue
		}
		switch ovn.Str(rule["type"]) {
		case "Allow":
			return fmt.Errorf("EgressFirewall %s/%s already allows this connection at rule %d; refresh the evidence", src.Namespace, firewall.GetName(), j+1)
		case "Deny":
			index = j
		default:
			return fmt.Errorf("unknown action in EgressFirewall rule %d", j+1)
		}
		break
	}
	if index < 0 {
		return fmt.Errorf("no matching EgressFirewall deny rule; unmatched external traffic is allowed by this firewall")
	}
	before, _, _ := unstructured.NestedMap(firewall.Object, "spec")
	p.FirewallChange = &FirewallChange{Namespace: src.Namespace, Name: firewall.GetName(), UID: string(firewall.GetUID()), Index: index, BeforeSpec: before}
	obj := unstructured.Unstructured{Object: map[string]any{"apiVersion": "k8s.ovn.org/v1", "kind": "EgressFirewall", "metadata": map[string]any{"name": firewall.GetName(), "namespace": src.Namespace}, "spec": before}}
	b, err := yaml.Marshal(obj.Object)
	if err != nil {
		return err
	}
	p.BeforeManifest = string(b)
	obj = *obj.DeepCopy()
	rule := map[string]any{"type": "Allow", "to": map[string]any{"cidrSelector": netip.PrefixFrom(ip, ip.BitLen()).String()}, "ports": []any{map[string]any{"protocol": i.Protocol, "port": int64(i.Port)}}}
	after := append([]any{}, rules[:index]...)
	after = append(after, rule)
	after = append(after, rules[index:]...)
	if err = unstructured.SetNestedSlice(obj.Object, after, "spec", "egress"); err != nil {
		return err
	}
	p.Objects = []unstructured.Unstructured{obj}
	p.Scope = &Scope{Network: "default", Role: "primary", PolicyKind: "EgressFirewall", NADs: []string{}}
	p.Summary = fmt.Sprintf("Allow namespace %s → %s on %s/%d before EgressFirewall %s rule %d", src.Namespace, ip, i.Protocol, i.Port, firewall.GetName(), index+1)
	p.Affected = append(p.Affected, "All current and future pods on the default network in namespace "+src.Namespace)
	for _, a := range ovn.Attachments(inv) {
		if a.Endpoint.Namespace == src.Namespace && a.Endpoint.Network == "default" {
			p.Affected = append(p.Affected, a.Endpoint.Namespace+"/"+a.Endpoint.Pod)
		}
	}
	p.Warnings = append(p.Warnings, "This edits the existing ordered EgressFirewall. The new rule affects the whole namespace, not just the observed source pod.", "The exception allows one IP and destination port. No DNS name or broader CIDR was inferred from the drop.", "Review both versions. Apply refuses a changed firewall; rollback removes only this inserted rule and refuses later spec edits.", "Allowing this firewall rule does not prove reachability. Other policies, routing and the external listener can still block the connection.")
	return nil
}

func firewallPortsMatch(rule map[string]any, i Intent) (bool, error) {
	raw, exists := rule["ports"]
	if !exists {
		return true, nil
	}
	ports, ok := raw.([]any)
	if !ok {
		return false, fmt.Errorf("invalid EgressFirewall ports")
	}
	if len(ports) == 0 {
		return true, nil
	}
	match := false
	for _, raw := range ports {
		port := ovn.Map(raw)
		protocol := ovn.Str(port["protocol"])
		n, err := strconv.Atoi(ovn.Str(port["port"]))
		if err != nil || n < 0 || n > 65535 || protocol != "TCP" && protocol != "UDP" && protocol != "SCTP" {
			return false, fmt.Errorf("invalid EgressFirewall protocol or port")
		}
		if protocol == i.Protocol && (n == 0 || n == i.Port) {
			match = true
		}
	}
	return match, nil
}

func externalEgressAllowed(inv model.Inventory, src core.Pod, i Intent) bool {
	isolated := false
	for _, np := range inv.Policies {
		if np.Namespace != src.Namespace || !selected(np.Spec.PodSelector, src.Labels) || !hasDirection(np, netv1.PolicyTypeEgress) {
			continue
		}
		isolated = true
		for _, rule := range np.Spec.Egress {
			if !portsMatch(rule.Ports, core.Pod{}, i) {
				continue
			}
			if len(rule.To) == 0 {
				return true
			}
			for _, peer := range rule.To {
				if peer.PodSelector != nil || peer.NamespaceSelector != nil {
					continue
				}
				if peersMatch(inv, src.Namespace, []netv1.NetworkPolicyPeer{peer}, core.Pod{}, i.Destination.IP) {
					return true
				}
			}
		}
	}
	return !isolated
}
