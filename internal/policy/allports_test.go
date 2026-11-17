// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"strings"
	"testing"

	core "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestAllPortsKeepsProtocolAndWorkloadScope(t *testing.T) {
	for _, secondary := range []bool{false, true} {
		for _, protocol := range []string{"TCP", "UDP", "SCTP"} {
			inv, i := fixture()
			if secondary {
				inv, i = secondaryFixture()
				inv.Resources["multi-networkpolicies"] = []unstructured.Unstructured{multiDeny("source", "blue", "Egress"), multiDeny("dest", "blue", "Ingress")}
			}
			i.Port = 0
			i.AllPorts = true
			i.Protocol = protocol
			p, err := Build(inv, i, testID)
			if err != nil {
				t.Fatal(err)
			}
			if len(p.Objects) != 2 || !strings.Contains(p.Summary, "all "+protocol+" ports") {
				t.Fatal(p)
			}
			for _, o := range p.Objects {
				var np netv1.NetworkPolicy
				if err := runtime.DefaultUnstructuredConverter.FromUnstructured(o.Object, &np); err != nil {
					t.Fatal(err)
				}
				var ports []netv1.NetworkPolicyPort
				var peers []netv1.NetworkPolicyPeer
				if len(np.Spec.Ingress) > 0 {
					ports = np.Spec.Ingress[0].Ports
					peers = np.Spec.Ingress[0].From
				} else {
					ports = np.Spec.Egress[0].Ports
					peers = np.Spec.Egress[0].To
				}
				if len(ports) != 1 || ports[0].Protocol == nil || string(*ports[0].Protocol) != protocol || ports[0].Port != nil || ports[0].EndPort != nil {
					t.Fatalf("incorrect port scope: %+v", ports)
				}
				if len(np.Spec.PodSelector.MatchLabels) == 0 || len(peers) != 1 || peers[0].PodSelector == nil || peers[0].NamespaceSelector == nil {
					t.Fatal("lost workload selectors", np)
				}
				if secondary {
					if o.GetAnnotations()[PolicyForAnnotation] != o.GetNamespace()+"/blue" {
						t.Fatal(o)
					}
					inv.Resources["multi-networkpolicies"] = append(inv.Resources["multi-networkpolicies"], o)
				} else {
					inv.Policies = append(inv.Policies, np)
				}
			}
			if _, err = Build(inv, i, testID); err == nil || !strings.Contains(err.Error(), "already permit") {
				t.Fatal("duplicate all-port proposal", err)
			}
		}
	}
}

func TestAllPortsValidation(t *testing.T) {
	for _, i := range []Intent{{Kind: "Policy", Protocol: "TCP", Port: 8080, AllPorts: true}, {Kind: "Policy", Protocol: "TCP", Port: 0}, {Kind: "Policy", Protocol: "ICMP", AllPorts: true}, {Kind: "EgressFirewall", Protocol: "TCP", AllPorts: true}, {Kind: "ClusterNetworkConnect", AllPorts: true}} {
		inv, _ := fixture()
		if _, err := Build(inv, i, testID); err == nil {
			t.Fatal("invalid intent accepted", i)
		}
	}
}

func TestAllPortsChecksUnionForMatchingPeersAndProtocol(t *testing.T) {
	inv, i := fixture()
	i.Port = 0
	i.AllPorts = true
	src, dst := inv.Pods[0], inv.Pods[1]
	add := func(start, end int, protocol core.Protocol, matching bool) {
		p := inv.Policies[1].DeepCopy()
		port := intstr.FromInt(start)
		last := int32(end)
		peers := []netv1.NetworkPolicyPeer{}
		if !matching {
			peers = []netv1.NetworkPolicyPeer{{IPBlock: &netv1.IPBlock{CIDR: "192.0.2.0/24"}}}
		}
		p.Spec.Ingress = []netv1.NetworkPolicyIngressRule{{From: peers, Ports: []netv1.NetworkPolicyPort{{Protocol: &protocol, Port: &port, EndPort: &last}}}}
		inv.Policies = append(inv.Policies, *p)
	}
	add(1, 32767, core.ProtocolTCP, true)
	add(32768, 65535, core.ProtocolUDP, true)
	add(32768, 65535, core.ProtocolTCP, false)
	if _, allowed := directionAllowed(inv, dst, src, dst, i, netv1.PolicyTypeIngress); allowed {
		t.Fatal("another peer or protocol filled a TCP gap")
	}
	add(32769, 65535, core.ProtocolTCP, true)
	if _, allowed := directionAllowed(inv, dst, src, dst, i, netv1.PolicyTypeIngress); allowed {
		t.Fatal("missing port 32768 ignored")
	}
	add(32768, 32768, core.ProtocolTCP, true)
	if _, allowed := directionAllowed(inv, dst, src, dst, i, netv1.PolicyTypeIngress); !allowed {
		t.Fatal("additive union not recognized")
	}
}

func TestNamedPortDoesNotCoverAllPorts(t *testing.T) {
	named := intstr.FromString("http")
	dst := core.Pod{Spec: core.PodSpec{Containers: []core.Container{{Ports: []core.ContainerPort{{Name: "http", ContainerPort: 8080}}}}}}
	ports := []netv1.NetworkPolicyPort{{Port: &named}}
	if !portsMatch(ports, dst, Intent{Protocol: "TCP", Port: 8080}) || portsMatch(ports, dst, Intent{Protocol: "TCP", AllPorts: true}) || portsMatch(ports, dst, Intent{Protocol: "UDP", Port: 8080}) {
		t.Fatal("named port scope lost")
	}
}
