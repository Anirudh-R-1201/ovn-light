// SPDX-License-Identifier: Apache-2.0
package qos

import (
	"slices"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
	"k8s.io/apimachinery/pkg/api/resource"
)

func bandwidthAnnotations(s model.Snapshot, attachments []ovn.Attachment) []Bandwidth {
	out := []Bandwidth{}
	byPod := map[string][]ovn.Attachment{}
	nodes := map[string]model.NodeSnapshot{}
	for _, a := range attachments {
		if a.Endpoint.Network == "default" {
			byPod[a.Endpoint.UID] = append(byPod[a.Endpoint.UID], a)
		}
	}
	for _, n := range s.Nodes {
		nodes[n.Name] = n
	}
	for _, p := range s.Inventory.Pods {
		for _, direction := range []string{"ingress", "egress"} {
			value := p.Annotations["kubernetes.io/"+direction+"-bandwidth"]
			if value == "" {
				continue
			}
			for _, a := range byPod[string(p.UID)] {
				b := Bandwidth{Endpoint: a.Endpoint, Direction: direction, Requested: value, State: "Programming not recovered"}
				q, err := resource.ParseQuantity(value)
				if err != nil {
					b.State = "Invalid bandwidth annotation"
					out = append(out, b)
					continue
				}
				b.BitsPerSecond = q.Value()
				b.ProgrammedBitsPerSecond = interfaceRate(nodes[a.Node], a.LogicalPort, direction)
				if b.ProgrammedBitsPerSecond != nil {
					b.State = "Configured rate observed"
					expected := b.BitsPerSecond
					if direction == "egress" {
						expected = expected / 1000 * 1000
					}
					if *b.ProgrammedBitsPerSecond != expected {
						b.State = "Desired / programmed values differ"
					}
				}
				out = append(out, b)
			}
		}
	}
	return out
}

// Pod egress enters OVS and uses ingress policing. Pod ingress leaves OVS and
// uses the port's QoS max-rate. Both fields describe configuration, not loss.
func interfaceRate(n model.NodeSnapshot, logicalPort, direction string) *int64 {
	for _, iface := range n.Interfaces {
		if ovn.Str(ovn.Map(iface["external_ids"])["iface-id"]) != logicalPort {
			continue
		}
		if direction == "egress" {
			if iface["ingress_policing_rate"] == nil {
				return nil
			}
			v := number(iface["ingress_policing_rate"]) * 1000
			return &v
		}
		for _, port := range n.QoS.Ports {
			if !slices.Contains(ovn.Strings(port["interfaces"]), ovn.Str(iface["_uuid"])) {
				continue
			}
			for _, row := range n.QoS.Queues {
				if slices.Contains(ovn.Strings(port["qos"]), ovn.Str(row["_uuid"])) {
					v := number(ovn.Map(row["other_config"])["max-rate"])
					return &v
				}
			}
		}
	}
	return nil
}
