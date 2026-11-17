// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"reflect"
	"strings"
	"testing"

	"github.com/trozet/ovn-light/internal/model"
	netv1 "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func firewallFixture() (model.Inventory, Intent) {
	inv, i := fixture()
	inv.Policies = nil
	i.Kind = "EgressFirewall"
	i.Destination = model.Endpoint{IP: "203.0.113.8"}
	inv.Resources["egressfirewalls"] = []unstructured.Unstructured{{Object: map[string]any{
		"apiVersion": "k8s.ovn.org/v1", "kind": "EgressFirewall", "metadata": map[string]any{"name": "default", "namespace": "source", "uid": "firewall-id"},
		"spec": map[string]any{"egress": []any{
			map[string]any{"type": "Allow", "to": map[string]any{"cidrSelector": "192.0.2.0/24"}},
			map[string]any{"type": "Deny", "to": map[string]any{"cidrSelector": "0.0.0.0/0"}},
		}},
	}}}
	return inv, i
}

func TestFirewallInsertionPreservesOrderAndScope(t *testing.T) {
	inv, i := firewallFixture()
	before, _, _ := unstructured.NestedMap(inv.Resources["egressfirewalls"][0].Object, "spec")
	p, err := Build(inv, i, testID)
	if err != nil {
		t.Fatal(err)
	}
	if p.FirewallChange.Index != 1 || p.FirewallChange.UID != "firewall-id" || p.Scope.PolicyKind != "EgressFirewall" || p.BeforeManifest == "" {
		t.Fatal(p)
	}
	rules, _, _ := unstructured.NestedSlice(p.Objects[0].Object, "spec", "egress")
	expected := map[string]any{"type": "Allow", "to": map[string]any{"cidrSelector": "203.0.113.8/32"}, "ports": []any{map[string]any{"protocol": "TCP", "port": int64(8080)}}}
	if len(rules) != 3 || !reflect.DeepEqual(rules[1], expected) || !reflect.DeepEqual([]any{rules[0], rules[2]}, before["egress"]) {
		t.Fatal(rules)
	}
	if !reflect.DeepEqual(p.FirewallChange.BeforeSpec, before) || !reflect.DeepEqual(inv.Resources["egressfirewalls"][0].Object["spec"], before) {
		t.Fatal("original rules mutated")
	}
	if !strings.Contains(strings.Join(p.Affected, " "), "All current and future pods") {
		t.Fatal("namespace scope was hidden")
	}
}

func TestFirewallDeclinesAmbiguousOrIneffectiveExceptions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*model.Inventory, *Intent)
		want   string
	}{
		{"already allowed", func(inv *model.Inventory, i *Intent) { i.Destination.IP = "192.0.2.8" }, "already allows"},
		{"no match", func(inv *model.Inventory, i *Intent) { i.Destination.IP = "2001:db8::1" }, "no matching"},
		{"pod address", func(inv *model.Inventory, i *Intent) { i.Destination.IP = "10.0.0.3" }, "cluster pod"},
		{"DNS guess", func(inv *model.Inventory, i *Intent) { i.Destination.IP = "example.com" }, "exact external"},
		{"loopback", func(inv *model.Inventory, i *Intent) { i.Destination.IP = "127.0.0.1" }, "unicast"},
		{"earlier DNS", func(inv *model.Inventory, i *Intent) {
			rules := inv.Resources["egressfirewalls"][0].Object["spec"].(map[string]any)["egress"].([]any)
			rules[0].(map[string]any)["to"] = map[string]any{"dnsName": "example.com"}
		}, "precedence"},
		{"egress policy", func(inv *model.Inventory, i *Intent) {
			inv.Policies = []netv1.NetworkPolicy{{ObjectMeta: meta.ObjectMeta{Namespace: "source"}, Spec: netv1.NetworkPolicySpec{PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress}}}}
		}, "NetworkPolicy also isolates"},
		{"namespace peer", func(inv *model.Inventory, i *Intent) {
			inv.Policies = []netv1.NetworkPolicy{{ObjectMeta: meta.ObjectMeta{Namespace: "source"}, Spec: netv1.NetworkPolicySpec{PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress}, Egress: []netv1.NetworkPolicyEgressRule{{To: []netv1.NetworkPolicyPeer{{NamespaceSelector: &meta.LabelSelector{}}}}}}}}
		}, "NetworkPolicy also isolates"},
		{"admin policy", func(inv *model.Inventory, i *Intent) {
			inv.Resources["adminnetworkpolicies"] = []unstructured.Unstructured{{Object: map[string]any{"kind": "AdminNetworkPolicy", "spec": map[string]any{"subject": map[string]any{"namespaces": map[string]any{}}}}}}
		}, "review its ordered"},
		{"primary UDN", func(inv *model.Inventory, i *Intent) {
			inv.Pods[0].Annotations = map[string]string{"k8s.ovn.org/pod-networks": `{"source/blue":{"ip_addresses":["10.0.0.2/24"],"role":"primary"}}`}
			i.Source.Network = "source/blue"
		}, "default network only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv, i := firewallFixture()
			tc.change(&inv, &i)
			if _, err := Build(inv, i, testID); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatal(err)
			}
		})
	}
}

func TestFirewallIPv6AndExternalIPBlock(t *testing.T) {
	inv, i := firewallFixture()
	i.Destination.IP = "2001:db8::8"
	rules := inv.Resources["egressfirewalls"][0].Object["spec"].(map[string]any)["egress"].([]any)
	rules[1].(map[string]any)["to"] = map[string]any{"cidrSelector": "::/0"}
	inv.Policies = []netv1.NetworkPolicy{{ObjectMeta: meta.ObjectMeta{Namespace: "source"}, Spec: netv1.NetworkPolicySpec{PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress}, Egress: []netv1.NetworkPolicyEgressRule{{To: []netv1.NetworkPolicyPeer{{IPBlock: &netv1.IPBlock{CIDR: "2001:db8::/32"}}}}}}}}
	p, err := Build(inv, i, testID)
	if err != nil || !strings.Contains(p.Manifests, "2001:db8::8/128") {
		t.Fatal(p, err)
	}
	inv.Policies[0].Spec.Egress[0].To[0].IPBlock.Except = []string{"2001:db8::8/128"}
	if _, err = Build(inv, i, testID); err == nil {
		t.Fatal("IPBlock exception ignored")
	}
}
