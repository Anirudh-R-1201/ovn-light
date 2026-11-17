// SPDX-License-Identifier: Apache-2.0
package ovn

import (
	"testing"

	"github.com/trozet/ovn-light/internal/datapath"
	"github.com/trozet/ovn-light/internal/model"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestCUDNAliasesAndOVNPortNaming(t *testing.T) {
	nad := unstructured.Unstructured{Object: map[string]any{"metadata": map[string]any{"name": "blue", "namespace": "team-a"}, "spec": map[string]any{"config": `{"name":"cluster_udn_blue","type":"ovn-k8s-cni-overlay","topology":"layer3"}`}}}
	nad.SetOwnerReferences([]meta.OwnerReference{{Kind: "ClusterUserDefinedNetwork", Name: "blue"}})
	inv := model.Inventory{Resources: map[string][]unstructured.Unstructured{"network-attachment-definitions": {nad}}, Pods: []core.Pod{{ObjectMeta: meta.ObjectMeta{Name: "pod-1", Namespace: "team-a", UID: "p1", Annotations: map[string]string{"k8s.ovn.org/pod-networks": `{"team-a/blue":{"ip_addresses":["10.0.0.2/24"],"role":"primary"}}`}}}}}
	as := Attachments(inv)
	if len(as) != 1 || as[0].Endpoint.Network != "cluster/blue" || as[0].LogicalPort != "team.a.blue_team-a_pod-1" || !as[0].Primary {
		t.Fatalf("unexpected attachment: %+v", as)
	}
}

func TestSharedNetworkNADsResolveDistinctPodPorts(t *testing.T) {
	nads := []unstructured.Unstructured{}
	for _, name := range []string{"blue-a", "blue-b"} {
		nads = append(nads, unstructured.Unstructured{Object: map[string]any{
			"metadata": map[string]any{"namespace": "team-a", "name": name},
			"spec":     map[string]any{"config": `{"name":"shared-network","type":"ovn-k8s-cni-overlay","topology":"layer2"}`},
		}})
	}
	inv := model.Inventory{Resources: map[string][]unstructured.Unstructured{"network-attachment-definitions": nads}, Pods: []core.Pod{{
		ObjectMeta: meta.ObjectMeta{Name: "client", Namespace: "team-a", UID: "p1", Annotations: map[string]string{
			"k8s.ovn.org/pod-networks": `{"team-a/blue-a":{"ip_addresses":["10.0.0.2/24"]},"team-a/blue-b":{"ip_addresses":["10.0.0.3/24"]}}`,
		}}, Spec: core.PodSpec{NodeName: "worker"},
	}}}
	attachments := Attachments(inv)
	for _, name := range []string{"a", "b"} {
		n := model.NodeSnapshot{Name: "worker", Interfaces: []model.Row{{"name": "veth", "external_ids": map[string]any{
			"iface-id": "team.a.blue." + name + "_team-a_client", "iface-id-ver": "p1",
		}}}}
		path := datapath.Path{Flows: []datapath.Flow{{InPort: "veth"}}}
		src := resolveSource(n, path, attachments)
		if src.NAD != "team-a/blue-"+name || src.Network != "network:shared-network" || src.UID != "p1" {
			t.Fatalf("NAD %s did not resolve through its pod port: %+v", name, src)
		}
	}
}

func TestDefaultNetworkNADIsNotASecondaryNetwork(t *testing.T) {
	for _, location := range []struct{ namespace, name string }{
		{"ovn-kubernetes", "default"},
		{"openshift-ovn-kubernetes", "default"},
		{"custom-namespace", "cluster-network"},
	} {
		t.Run(location.namespace+"/"+location.name, func(t *testing.T) {
			nad := unstructured.Unstructured{Object: map[string]any{
				"metadata": map[string]any{"namespace": location.namespace, "name": location.name},
				"spec":     map[string]any{"config": `{"cniVersion":"1.1.0","name":"ovn-kubernetes","type":"ovn-k8s-cni-overlay"}`},
			}}
			secondary := unstructured.Unstructured{Object: map[string]any{
				"metadata": map[string]any{"namespace": "team-a", "name": "default"},
				"spec":     map[string]any{"config": `{"name":"blue","type":"ovn-k8s-cni-overlay","topology":"layer2","subnets":"172.20.0.0/24"}`},
			}}
			inv := model.Inventory{
				Resources: map[string][]unstructured.Unstructured{"network-attachment-definitions": {nad, secondary}},
				Pods: []core.Pod{{ObjectMeta: meta.ObjectMeta{
					Name: "client", Namespace: "team-a", UID: "client",
					Annotations: map[string]string{"k8s.ovn.org/pod-networks": `{"default":{"ip_addresses":["10.244.0.5/24"]},"team-a/default":{"ip_addresses":["172.20.0.5/24"]}}`},
				}}},
			}
			if got := NetworkForNAD(inv, location.namespace+"/"+location.name); got != "default" {
				t.Fatalf("default-network NAD resolved to %q", got)
			}
			if got := NetworkForNAD(inv, "team-a/default"); got != "network:blue" {
				t.Fatalf("secondary NAD named default resolved to %q", got)
			}
			networks := Networks(inv)
			if len(networks) != 2 {
				t.Fatalf("expected default and blue networks, got %+v", networks)
			}
			if n := networks[0]; n.ID != "default" || n.Role != "Primary" || n.Topology != "Layer3" || n.Pods != 1 {
				t.Fatalf("default network changed: %+v", n)
			}
			if n := networks[1]; n.ID != "network:blue" || n.Role != "Secondary" || n.Pods != 1 {
				t.Fatalf("secondary network changed: %+v", n)
			}
		})
	}
}
