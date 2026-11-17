// SPDX-License-Identifier: Apache-2.0
package routing

import (
	"github.com/trozet/ovn-light/internal/model"
	"testing"
	"time"
)

func TestPeerUplinkVRFAndECMP(t *testing.T) {
	now := time.Now()
	p := Peer{Node: "n", VRF: "blue", Address: "192.0.2.1"}
	uplinks := []Uplink{{ID: "blue/n", Node: "n", HostInterface: "eth1"}, {ID: "red/n", Node: "n", HostInterface: "eth2"}}
	n := model.NodeSnapshot{Routing: model.RoutingEvidence{CapturedAt: now, HostComplete: true, Links: []model.Row{{"ifname": "blue", "linkinfo": map[string]any{"info_data": map[string]any{"table": 1001}}}}, Routes: []model.Row{
		{"dst": "192.0.2.0/24", "dev": "eth2"},
		{"dst": "default", "family": "ipv6", "table": 1001, "dev": "eth2"},
		{"dst": "default", "family": "ipv4", "table": 1001, "dev": "eth1"},
	}}}
	ids, _ := peerUplinks(p, uplinks, n, now)
	if len(ids) != 1 || ids[0] != "blue/n" {
		t.Fatal(ids)
	}
	n.Routing.Routes = append(n.Routing.Routes, model.Row{"dst": "192.0.2.0/24", "table": 1001, "nexthops": []any{map[string]any{"dev": "eth1"}, map[string]any{"dev": "eth2"}}})
	ids, _ = peerUplinks(p, uplinks, n, now)
	if len(ids) != 2 {
		t.Fatal("ECMP hidden", ids)
	}
	n.Routing.HostComplete = false
	ids, _ = peerUplinks(p, uplinks, n, now)
	if len(ids) != 0 {
		t.Fatal("incomplete host routes produced an association")
	}
}

func TestNetworkFilterKeepsSharedPeerPrefixesSeparate(t *testing.T) {
	r := Report{Peers: []Peer{{ID: "n/default/192.0.2.1", Networks: []string{"cluster/blue", "cluster/red"}, Prefixes: []Prefix{{CIDR: "10.1.0.0/24", Networks: []string{"cluster/blue"}}, {CIDR: "10.2.0.0/24", Networks: []string{"cluster/red"}}}}}}
	filtered := Filter(r, Options{Network: "cluster/red"})
	if len(filtered.Peers) != 1 || len(filtered.Peers[0].Prefixes) != 1 || filtered.Peers[0].Prefixes[0].CIDR != "10.2.0.0/24" {
		t.Fatal(filtered.Peers)
	}
}
