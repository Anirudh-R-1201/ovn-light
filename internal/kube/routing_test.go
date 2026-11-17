// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"encoding/json"
	"errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"strings"
	"testing"
)

func TestFRRParsers(t *testing.T) {
	peers, err := parseBGPSummary(`{"blue":{"ipv4Unicast":{"peers":{"192.0.2.1":{"state":"Established"}}},"ipv6Unicast":{"peers":{"2001:db8::1":{"state":"Active"}}}}}`)
	if err != nil || len(peers) != 2 || peers[0].VRF != "blue" || peers[0].Family != "ipv4" {
		t.Fatal(peers, err)
	}
	for _, tc := range []struct {
		raw      string
		complete bool
		count    int
	}{
		{`{"advertisedRoutes":{"10.1.0.0/24":{},"2001:db8::/64":{}}}`, true, 2},
		{`{"advertisedRoutes":{}}`, true, 0}, {`{}`, false, 0}, {`{"advertisedRoutes":{"not-a-prefix":{}}}`, false, 0}, {`permission denied`, false, 0},
	} {
		p, complete := advertisedPrefixes(tc.raw)
		if complete != tc.complete || len(p) != tc.count {
			t.Fatalf("%s: %v %v", tc.raw, p, complete)
		}
	}
}
func TestRoutingFailuresAreCached(t *testing.T) {
	c := &Collector{}
	calls := 0
	targets := nodeTargets{ovs: Target{Namespace: "ovn", Pod: "ovs", Container: "ovs"}}
	run := func(Target, ...string) (string, error) { calls++; return "", errors.New("unavailable") }
	first := c.captureRouting("node", targets, run)
	count := calls
	second := c.captureRouting("node", targets, run)
	if count > 28 || count == 0 || calls != count || first.HostComplete || first.OVNComplete || len(first.Errors) == 0 || !first.CapturedAt.Equal(second.CapturedAt) {
		t.Fatal(count, calls, first, second)
	}
	targets.ovs.Pod = "replacement"
	c.captureRouting("node", targets, run)
	if calls == count {
		t.Fatal("replacement pod reused cached state")
	}
}
func TestRoutingSnapshotRedactsCredentials(t *testing.T) {
	var u unstructured.Unstructured
	_ = json.Unmarshal([]byte(`{"metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"secret-value","k8s.ovn.org/route-advertisements":"owner"}},"spec":{"raw":{"rawConfig":"secret-value"},"bgp":{"routers":[{"asn":64512,"neighbors":[{"address":"192.0.2.1","password":"secret-value","passwordSecret":{"name":"secret-value"}}]}]}}}`), &u)
	redactRoutingResource("frrconfigurations", &u)
	raw, _ := json.Marshal(u.Object)
	if strings.Contains(string(raw), "secret-value") || !strings.Contains(string(raw), "192.0.2.1") || u.GetAnnotations()["k8s.ovn.org/route-advertisements"] != "owner" {
		t.Fatal(string(raw))
	}
	_ = json.Unmarshal([]byte(`{"status":{"runningConfig":"secret-value","lastConversionResult":"invalid secret-value","lastReloadResult":"success"}}`), &u)
	redactRoutingResource("frrnodestates", &u)
	raw, _ = json.Marshal(u.Object)
	if strings.Contains(string(raw), "secret-value") {
		t.Fatal("node status exposed a credential")
	}
}
