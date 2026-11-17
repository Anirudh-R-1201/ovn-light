// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"strings"
	"testing"

	"github.com/trozet/ovn-light/internal/model"
	core "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

const testID = "1234567890abcdef1234567890abcdef"

func fixture() (model.Inventory, Intent) {
	inv := model.Inventory{Resources: map[string][]unstructured.Unstructured{}}
	for _, ns := range []string{"source", "dest"} {
		inv.Namespaces = append(inv.Namespaces, core.Namespace{ObjectMeta: meta.ObjectMeta{Name: ns, Labels: map[string]string{"kubernetes.io/metadata.name": ns}}})
		inv.Pods = append(inv.Pods, core.Pod{ObjectMeta: meta.ObjectMeta{Name: "app", Namespace: ns, UID: types.UID(ns), Labels: map[string]string{"app": "test"}}, Status: core.PodStatus{PodIPs: []core.PodIP{{IP: map[string]string{"source": "10.0.0.2", "dest": "10.0.0.3"}[ns]}}}})
		inv.Policies = append(inv.Policies, netv1.NetworkPolicy{ObjectMeta: meta.ObjectMeta{Name: "deny", Namespace: ns}, Spec: netv1.NetworkPolicySpec{PodSelector: meta.LabelSelector{}, PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress, netv1.PolicyTypeEgress}}})
	}
	return inv, Intent{Kind: "NetworkPolicy", Source: model.Endpoint{Namespace: "source", Pod: "app", Network: "default"}, Destination: model.Endpoint{Namespace: "dest", Pod: "app", Network: "default"}, Protocol: "TCP", Port: 8080}
}
func TestAdditiveBothDirections(t *testing.T) {
	inv, i := fixture()
	p, e := Build(inv, i, testID)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Objects) != 2 {
		t.Fatalf("want both directions: %+v", p)
	}
	for _, o := range p.Objects {
		var np netv1.NetworkPolicy
		if e = runtime.DefaultUnstructuredConverter.FromUnstructured(o.Object, &np); e != nil {
			t.Fatal(e)
		}
		var peer netv1.NetworkPolicyPeer
		if len(np.Spec.Ingress) > 0 {
			peer = np.Spec.Ingress[0].From[0]
		} else {
			peer = np.Spec.Egress[0].To[0]
		}
		if peer.PodSelector == nil || peer.NamespaceSelector == nil || len(peer.PodSelector.MatchLabels) == 0 {
			t.Fatal("peer must AND namespace and pod selectors")
		}
		inv.Policies = append(inv.Policies, np)
	}
	if _, e = Build(inv, i, testID); e == nil || !strings.Contains(e.Error(), "already permit") {
		t.Fatal("existing allow should suppress duplicate proposal", e)
	}
}
func TestConservativeGuards(t *testing.T) {
	for _, tt := range []struct {
		name     string
		change   func(*model.Inventory, *Intent)
		contains string
	}{
		{"labels", func(inv *model.Inventory, i *Intent) { inv.Pods[0].Labels = nil }, "labels"},
		{"admin", func(inv *model.Inventory, i *Intent) {
			inv.Resources["adminnetworkpolicies"] = []unstructured.Unstructured{{Object: map[string]any{"kind": "AdminNetworkPolicy", "metadata": map[string]any{"name": "security"}, "spec": map[string]any{"subject": map[string]any{"namespaces": map[string]any{}}}}}}
		}, "administrator"},
		{"incomplete", func(inv *model.Inventory, i *Intent) { inv.Errors = []string{"forbidden"} }, "incomplete"},
		{"port", func(inv *model.Inventory, i *Intent) { i.Port = 0 }, "port"},
		{"no isolation", func(inv *model.Inventory, i *Intent) { inv.Policies = nil }, "already permit"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			inv, i := fixture()
			tt.change(&inv, &i)
			if _, e := Build(inv, i, testID); e == nil || !strings.Contains(e.Error(), tt.contains) {
				t.Fatal(e)
			}
		})
	}
}
func TestFingerprintIgnoresStatusButGuardsSelectors(t *testing.T) {
	inv, _ := fixture()
	before := Fingerprint(inv)
	inv.Pods[0].Status.Phase = core.PodRunning
	inv.Pods[0].ResourceVersion = "updated"
	if Fingerprint(inv) != before {
		t.Fatal("volatile status invalidated proposal")
	}
	inv.Pods[0].Labels["app"] = "other"
	if Fingerprint(inv) == before {
		t.Fatal("label change did not invalidate proposal")
	}
}
func TestNamespaceAndPodPeerIntersection(t *testing.T) {
	inv, i := fixture()
	peer := netv1.NetworkPolicyPeer{NamespaceSelector: &meta.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "source"}}, PodSelector: &meta.LabelSelector{MatchLabels: map[string]string{"app": "other"}}}
	if peersMatch(inv, "dest", []netv1.NetworkPolicyPeer{peer}, inv.Pods[0], i.Source.IP) {
		t.Fatal("namespace OR pod broadened allow")
	}
}
func TestConnectChecksOverlapAndSelectors(t *testing.T) {
	inv, _ := fixture()
	inv.Resources["clusternetworkconnects"] = []unstructured.Unstructured{}
	for _, n := range []string{"source", "dest"} {
		inv.Resources["userdefinednetworks"] = append(inv.Resources["userdefinednetworks"], unstructured.Unstructured{Object: map[string]any{"apiVersion": "k8s.ovn.org/v1", "kind": "UserDefinedNetwork", "metadata": map[string]any{"name": "net", "namespace": n}, "spec": map[string]any{"topology": "Layer2", "layer2": map[string]any{"role": "Primary", "subnets": []any{map[string]string{"source": "10.20.0.0/24", "dest": "10.21.0.0/24"}[n]}}}}})
	}
	i := Intent{Kind: "ClusterNetworkConnect", Networks: []string{"source/net", "dest/net"}, ConnectCIDR: "100.100.0.0/16", NetworkPrefix: 24}
	p, e := Build(inv, i, testID)
	if e != nil || len(p.Objects) != 1 {
		t.Fatal(p, e)
	}
	i.ConnectCIDR = "10.20.0.0/16"
	if _, e = Build(inv, i, testID); e == nil {
		t.Fatal("overlap accepted")
	}
}
