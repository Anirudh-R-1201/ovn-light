// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func secondaryFixture() (model.Inventory, Intent) {
	inv, i := fixture()
	inv.Resources["multi-networkpolicies"] = []unstructured.Unstructured{}
	for index := range inv.Pods {
		p := &inv.Pods[index]
		nad := p.Namespace + "/blue"
		config, _ := json.Marshal(map[string]any{"name": "shared-blue", "type": "ovn-k8s-cni-overlay", "topology": "layer2", "subnets": "172.20.0.0/24"})
		inv.Resources["network-attachment-definitions"] = append(inv.Resources["network-attachment-definitions"], unstructured.Unstructured{Object: map[string]any{"apiVersion": "k8s.cni.cncf.io/v1", "kind": "NetworkAttachmentDefinition", "metadata": map[string]any{"name": "blue", "namespace": p.Namespace}, "spec": map[string]any{"config": string(config)}}})
		addresses := map[string]any{"default": map[string]any{"ip_addresses": []string{p.Status.PodIPs[0].IP + "/24"}}, nad: map[string]any{"ip_addresses": []string{map[string]string{"source": "172.20.0.2/24", "dest": "172.20.0.3/24"}[p.Namespace]}}}
		annotation, _ := json.Marshal(addresses)
		p.Annotations = map[string]string{"k8s.ovn.org/pod-networks": string(annotation)}
	}
	i.Kind = "Policy"
	i.Source.Network = "network:shared-blue"
	i.Destination.Network = i.Source.Network
	return inv, i
}

func multiDeny(namespace, target, direction string) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{"apiVersion": "k8s.cni.cncf.io/v1beta1", "kind": "MultiNetworkPolicy", "metadata": map[string]any{"namespace": namespace, "name": "deny-blue", "annotations": map[string]any{PolicyForAnnotation: target}}, "spec": map[string]any{"podSelector": map[string]any{}, "policyTypes": []any{direction}}}}
}

func TestSecondaryScopeSelectsPolicyTypeAndNAD(t *testing.T) {
	inv, i := secondaryFixture()
	inv.Resources["multi-networkpolicies"] = []unstructured.Unstructured{multiDeny("source", " source/blue ", "Egress"), multiDeny("dest", "blue", "Ingress")}
	p, e := Build(inv, i, testID)
	if e != nil {
		t.Fatal(e)
	}
	if p.Kind != "MultiNetworkPolicy" || p.Intent.Kind != p.Kind || p.Scope.Network != "network:shared-blue" || p.Scope.Role != "secondary" || len(p.Objects) != 2 {
		t.Fatalf("wrong scope: %+v", p)
	}
	for _, o := range p.Objects {
		if o.GetKind() != "MultiNetworkPolicy" || o.GetAPIVersion() != "k8s.cni.cncf.io/v1beta1" || o.GetAnnotations()[PolicyForAnnotation] != o.GetNamespace()+"/blue" {
			t.Fatalf("wrong policy target: %+v", o.Object)
		}
	}
	if p.Intent.Source.IP != "172.20.0.2" || p.Intent.Destination.IP != "172.20.0.3" {
		t.Fatal("primary IP used for secondary connection")
	}
}

func TestPrimaryAndOtherSecondaryPoliciesCannotAffectSelectedSecondary(t *testing.T) {
	inv, i := secondaryFixture()
	if _, e := Build(inv, i, testID); e == nil || !strings.Contains(e.Error(), "already permit") {
		t.Fatal("primary deny affected secondary", e)
	}
	inv.Resources["multi-networkpolicies"] = []unstructured.Unstructured{multiDeny("dest", "red", "Ingress")}
	if _, e := Build(inv, i, testID); e == nil || !strings.Contains(e.Error(), "already permit") {
		t.Fatal("unrelated NAD policy affected blue", e)
	}
	inv.Resources["multi-networkpolicies"] = append(inv.Resources["multi-networkpolicies"], multiDeny("dest", "red, dest/blue", "Ingress"))
	p, e := Build(inv, i, testID)
	if e != nil || len(p.Objects) != 1 {
		t.Fatal(p, e)
	}
}

func TestExistingMultiAllowAndPrimaryIsolationAreIndependent(t *testing.T) {
	inv, i := secondaryFixture()
	inv.Resources["multi-networkpolicies"] = []unstructured.Unstructured{multiDeny("dest", "blue", "Ingress")}
	p, e := Build(inv, i, testID)
	if e != nil {
		t.Fatal(e)
	}
	inv.Resources["multi-networkpolicies"] = append(inv.Resources["multi-networkpolicies"], p.Objects...)
	if _, e = Build(inv, i, testID); e == nil || !strings.Contains(e.Error(), "already permit") {
		t.Fatal("existing secondary allow ignored", e)
	}
	i.Source.Network = "default"
	i.Destination.Network = "default"
	p, e = Build(inv, i, testID)
	if e != nil || p.Kind != "NetworkPolicy" || len(p.Objects) != 2 {
		t.Fatal("secondary allow bypassed primary isolation", p, e)
	}
}

func TestPolicyScopeRejectsWrongAPIAndUnknownRoles(t *testing.T) {
	inv, i := secondaryFixture()
	i.Kind = "NetworkPolicy"
	if _, e := Build(inv, i, testID); e == nil || !strings.Contains(e.Error(), "MultiNetworkPolicy applies") {
		t.Fatal(e)
	}
	i.Kind = "MultiNetworkPolicy"
	i.Source.Network = "default"
	i.Destination.Network = "default"
	if _, e := Build(inv, i, testID); e == nil || !strings.Contains(e.Error(), "NetworkPolicy applies") {
		t.Fatal(e)
	}
	i.Kind = "Policy"
	i.Source.Network = ""
	i.Destination.Network = ""
	if _, e := Build(inv, i, testID); e == nil || !strings.Contains(e.Error(), "multiple matching") {
		t.Fatal("ambiguous network defaulted to CDN", e)
	}
}

func TestSecondaryAvailabilityAndIPAM(t *testing.T) {
	inv, i := secondaryFixture()
	delete(inv.Resources, "multi-networkpolicies")
	if _, e := Build(inv, i, testID); e == nil || !strings.Contains(e.Error(), "API is unavailable") {
		t.Fatal(e)
	}
	inv.Resources["multi-networkpolicies"] = []unstructured.Unstructured{multiDeny("dest", "blue", "Ingress")}
	_ = unstructured.SetNestedField(inv.Resources["network-attachment-definitions"][0].Object, `{"name":"shared-blue","type":"ovn-k8s-cni-overlay","topology":"localnet"}`, "spec", "config")
	if _, e := Build(inv, i, testID); e == nil || !strings.Contains(e.Error(), "no managed subnets") {
		t.Fatal(e)
	}
}

func TestPolicyForRetargetInvalidatesReview(t *testing.T) {
	inv, _ := secondaryFixture()
	inv.Resources["multi-networkpolicies"] = []unstructured.Unstructured{multiDeny("dest", "blue", "Ingress")}
	before := Fingerprint(inv)
	inv.Resources["multi-networkpolicies"][0].SetAnnotations(map[string]string{PolicyForAnnotation: "red"})
	if Fingerprint(inv) == before {
		t.Fatal("retargeted annotation did not invalidate review")
	}
}

func TestMultiPolicyWithoutDirectionsIsNotGivenPrimaryDefaults(t *testing.T) {
	inv, i := secondaryFixture()
	mnp := multiDeny("dest", "blue", "Ingress")
	unstructured.RemoveNestedField(mnp.Object, "spec", "policyTypes")
	inv.Resources["multi-networkpolicies"] = []unstructured.Unstructured{mnp}
	if _, e := Build(inv, i, testID); e == nil || !strings.Contains(e.Error(), "omits policyTypes") {
		t.Fatal("ambiguous MultiNetworkPolicy directions accepted", e)
	}
}

func TestPrimaryUDNScopeIsExplicitAndCDNInfrastructureIsRejected(t *testing.T) {
	inv, i := secondaryFixture()
	for index := range inv.Pods {
		p := &inv.Pods[index]
		var ns map[string]any
		_ = json.Unmarshal([]byte(p.Annotations["k8s.ovn.org/pod-networks"]), &ns)
		ns[p.Namespace+"/blue"].(map[string]any)["role"] = "primary"
		b, _ := json.Marshal(ns)
		p.Annotations["k8s.ovn.org/pod-networks"] = string(b)
	}
	p, e := Build(inv, i, testID)
	if e != nil || p.Kind != "NetworkPolicy" || p.Scope.Network != "network:shared-blue" || p.Scope.Role != "primary" {
		t.Fatal(p, e)
	}
	for _, o := range p.Objects {
		if o.GetAnnotations()[PolicyForAnnotation] != "" {
			t.Fatal("regular NetworkPolicy cannot select a NAD")
		}
	}
	i.Source.Network = "default"
	i.Destination.Network = "default"
	if _, e = Build(inv, i, testID); e == nil || !strings.Contains(e.Error(), "infrastructure") {
		t.Fatal(e)
	}
	for _, a := range ovn.Attachments(inv) {
		if a.Endpoint.Network == "default" && a.Endpoint.PolicyKind != "" {
			t.Fatal("CDN marked policy eligible in a primary UDN namespace")
		}
	}
}
