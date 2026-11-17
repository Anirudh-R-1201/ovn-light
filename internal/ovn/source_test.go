// SPDX-License-Identifier: Apache-2.0
package ovn

import (
	"testing"
	"time"

	"github.com/trozet/ovn-light/internal/model"
)

func TestSourceContextKeepsCandidateIdentityUnconfirmed(t *testing.T) {
	now := time.Now()
	delta := uint64(5)
	x := trafficIndex{hosts: map[string]string{"172.18.0.10": "node-a"}}
	for _, e := range []model.Endpoint{
		{UID: "quiet", Pod: "a-quiet", IP: "10.244.0.3", Node: "node-a", Network: "default"},
		{UID: "active", Pod: "z-active", IP: "10.244.0.5", Node: "node-a", Network: "default"},
		{UID: "other-network", IP: "10.244.0.5", Node: "node-a", Network: "udn"},
		{UID: "other-node", IP: "10.244.0.6", Node: "node-c", Network: "default"},
		{UID: "outside", IP: "10.245.0.7", Node: "node-a", Network: "default"},
	} {
		x.attachments = append(x.attachments, Attachment{Endpoint: e})
	}
	f := model.Finding{Node: "node-b", ObservedAt: now, Destination: model.Endpoint{UID: "server", IP: "10.244.1.22", Network: "default"}, Steps: []model.Step{{Match: map[string]string{"ipv4.src": "10.244.0.0/255.255.255.0", "tunnel.src": "172.18.0.10"}}}}
	outgoing := model.TrafficObservation{Network: "default", Source: x.attachments[1].Endpoint, Destination: model.Endpoint{Node: "node-b"}, Location: "source", Verdict: "forward", Protocol: "TCP", End: now, PacketDelta: &delta}
	for _, tc := range []struct {
		name   string
		change func(*model.TrafficObservation)
		active bool
	}{
		{"recent", func(*model.TrafficObservation) {}, true},
		{"stale", func(o *model.TrafficObservation) { o.End = now.Add(-2 * time.Minute) }, false},
		{"other-node", func(o *model.TrafficObservation) { o.Destination.Node = "node-c" }, false},
		{"other-destination", func(o *model.TrafficObservation) { o.Destination.IP = "10.244.1.23" }, false},
		{"baseline-only", func(o *model.TrafficObservation) { o.PacketDelta = nil }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := outgoing
			tc.change(&o)
			v := model.View{Findings: []model.Finding{f}, Traffic: []model.TrafficObservation{o}}
			sourceContexts(&v, x)
			got := v.Findings[0]
			c := got.SourceContext
			if got.Source.UID != "" || got.Source.IP != "" || got.Source.Network != "" || got.CanRecommend || got.Destination.Port != 0 || got.Source.Node != "node-a" {
				t.Fatal("candidate became confirmed", got)
			}
			if c == nil || c.Address != "10.244.0.0/24" || c.Network != "default" || len(c.Candidates) != 2 {
				t.Fatal(c)
			}
			if tc.active && (c.Candidates[0].Endpoint.UID != "active" || !c.Candidates[0].Observed) {
				t.Fatal("outgoing activity not prioritized", c)
			}
			if !tc.active {
				for _, candidate := range c.Candidates {
					if candidate.Observed {
						t.Fatal("unrelated traffic counted", candidate)
					}
				}
			}
		})
	}
}

func TestSourceConstraintDoesNotInventAddress(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"10.244.0.0/255.255.255.0", "10.244.0.0/24"}, {"10.244.0.5/32", "10.244.0.5"}, {"fd00::5/64", "fd00::/64"}, {"fd00::5/ffff:ffff:ffff:ffff::", "fd00::/64"}, {"0.0.0.0/0", ""}, {"0.0.0.0/0.0.0.0", ""}, {"::/0", ""}, {"invalid", ""},
	} {
		if got := sourceAddress(tc.raw); got != tc.want {
			t.Fatalf("%s: %s != %s", tc.raw, got, tc.want)
		}
	}
}

func TestSourceCandidatesNeedAddressAndNetwork(t *testing.T) {
	for _, tc := range []struct {
		address, network string
		count            int
	}{
		{"10.0.0.1", "default", 1}, {"0.0.0.0/0", "default", 0}, {"10.0.0.1", "", 0},
	} {
		v := model.View{Findings: []model.Finding{{Destination: model.Endpoint{Network: tc.network}, Steps: []model.Step{{Match: map[string]string{"ipv4.src": tc.address}}}}}}
		x := trafficIndex{attachments: []Attachment{{Endpoint: model.Endpoint{UID: "only-pod", IP: "10.0.0.1", Network: "default"}}}}
		sourceContexts(&v, x)
		if len(v.Findings[0].SourceContext.Candidates) != tc.count || v.Findings[0].Source.UID != "" {
			t.Fatal(tc, v.Findings[0])
		}
	}
}
