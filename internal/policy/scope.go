// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const PolicyForAnnotation = "k8s.v1.cni.cncf.io/policy-for"

type Scope struct {
	Network    string   `json:"network"`
	Role       string   `json:"role"`
	PolicyKind string   `json:"policyKind"`
	NADs       []string `json:"nads"`
}

// NetworkPolicy follows each namespace's primary network. MultiNetworkPolicy
// needs an explicit NAD target; the same pod labels alone do not select it.
func scopeFor(inv model.Inventory, source, dest ovn.Attachment, requested string) (*Scope, error) {
	s, d := source.Endpoint, dest.Endpoint
	if s.Network != d.Network {
		return nil, fmt.Errorf("cross-network policy selectors are not supported; review network connectivity separately")
	}
	if s.PolicyKind == "" || d.PolicyKind == "" {
		return nil, fmt.Errorf("the selected attachment is infrastructure-only or its role is unknown; choose the pod's primary or secondary network")
	}
	if s.PolicyKind != d.PolicyKind {
		return nil, fmt.Errorf("the endpoints do not share the same primary/secondary network role")
	}
	if requested != "Policy" && requested != s.PolicyKind {
		return nil, fmt.Errorf("%s applies to this %s network; %s cannot target it", s.PolicyKind, s.Role, requested)
	}
	scope := &Scope{Network: s.Network, Role: s.Role, PolicyKind: s.PolicyKind, NADs: []string{}}
	seen := map[string]bool{}
	for _, a := range []model.Endpoint{s, d} {
		if a.NAD != "" && !seen[a.NAD] {
			seen[a.NAD] = true
			scope.NADs = append(scope.NADs, a.NAD)
		}
	}
	sort.Strings(scope.NADs)
	if s.PolicyKind == "MultiNetworkPolicy" {
		if _, ok := inv.Resources["multi-networkpolicies"]; !ok {
			return nil, fmt.Errorf("the MultiNetworkPolicy API is unavailable; no secondary-network policy can be proposed")
		}
		for _, a := range []model.Endpoint{s, d} {
			config := ovn.NADConfig(inv, a.NAD)
			if a.NAD == "" || ovn.Str(config["type"]) != "ovn-k8s-cni-overlay" || ovn.NetworkForNAD(inv, a.NAD) != scope.Network {
				return nil, fmt.Errorf("cannot establish the OVN NAD target for %s/%s", a.Namespace, a.Pod)
			}
			if ovn.Str(config["subnets"]) == "" {
				return nil, fmt.Errorf("secondary NAD %s has no managed subnets; selector-based proposals for IPAM-less or DHCP networks are not supported", a.NAD)
			}
		}
	}
	return scope, nil
}

func policiesForScope(inv model.Inventory, scope *Scope) ([]netv1.NetworkPolicy, error) {
	if scope.PolicyKind == "NetworkPolicy" {
		return inv.Policies, nil
	}
	var policies []netv1.NetworkPolicy
	for _, mnp := range inv.Resources["multi-networkpolicies"] {
		matches := false
		for _, target := range strings.Split(strings.ReplaceAll(mnp.GetAnnotations()[PolicyForAnnotation], " ", ""), ",") {
			if target == "" {
				continue
			}
			if !strings.Contains(target, "/") {
				target = mnp.GetNamespace() + "/" + target
			}
			if ovn.NetworkForNAD(inv, target) == scope.Network {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		var policy netv1.NetworkPolicy
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(mnp.Object, &policy); err != nil {
			return nil, fmt.Errorf("read MultiNetworkPolicy %s/%s: %w", mnp.GetNamespace(), mnp.GetName(), err)
		}
		if len(policy.Spec.PolicyTypes) == 0 {
			return nil, fmt.Errorf("MultiNetworkPolicy %s/%s omits policyTypes; specify its directions before relying on isolation for this proposal", mnp.GetNamespace(), mnp.GetName())
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

// SelectingPolicies records which policies isolated this attachment in the
// observed direction. A namespace default-deny ACL can be shared by all of them.
func SelectingPolicies(inv model.Inventory, endpoint model.Endpoint, direction string) ([]string, error) {
	if endpoint.UID == "" || (endpoint.PolicyKind != "NetworkPolicy" && endpoint.PolicyKind != "MultiNetworkPolicy") {
		return nil, fmt.Errorf("attachment policy scope is unknown")
	}
	if endpoint.PolicyKind == "MultiNetworkPolicy" {
		if _, ok := inv.Resources["multi-networkpolicies"]; !ok {
			return nil, fmt.Errorf("MultiNetworkPolicy inventory unavailable")
		}
	}
	var d netv1.PolicyType
	switch strings.ToLower(direction) {
	case "ingress":
		d = netv1.PolicyTypeIngress
	case "egress":
		d = netv1.PolicyTypeEgress
	default:
		return nil, fmt.Errorf("policy direction is unknown")
	}
	policies, err := policiesForScope(inv, &Scope{Network: endpoint.Network, PolicyKind: endpoint.PolicyKind})
	if err != nil {
		return nil, err
	}
	var names []string
	for _, np := range policies {
		if np.Namespace == endpoint.Namespace && selected(np.Spec.PodSelector, endpoint.Labels) && hasDirection(np, d) {
			names = append(names, endpoint.PolicyKind+" "+np.Namespace+"/"+np.Name)
		}
	}
	sort.Strings(names)
	return names, nil
}
