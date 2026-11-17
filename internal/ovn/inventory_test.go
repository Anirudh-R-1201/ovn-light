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
	nad := unstructured.Unstructured{Object: map[string]any{"metadata": map[string]any{"name": "blue", "namespace": "team-a"}, "spec": map[string]any{"config": `{"name":"cluster_udn_blue","type":"ovn-k8s-cni-overlay"}`}}}
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
			"spec":     map[string]any{"config": `{"name":"shared-network","type":"ovn-k8s-cni-overlay"}`},
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
