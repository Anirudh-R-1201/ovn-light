// SPDX-License-Identifier: Apache-2.0
package history

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/trozet/ovn-light/internal/model"
	netv1 "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func sample(at time.Time) (model.View, model.Inventory) {
	pod := model.Endpoint{UID: "abc", Namespace: "red", Pod: "server", Network: "red/net", PolicyKind: "NetworkPolicy", Role: "primary", Labels: map[string]string{"app": "server"}}
	n := netv1.NetworkPolicy{ObjectMeta: meta.ObjectMeta{Namespace: "red", Name: "old-isolation"}, Spec: netv1.NetworkPolicySpec{PodSelector: meta.LabelSelector{MatchLabels: map[string]string{"app": "server"}}}}
	inv := model.Inventory{Policies: []netv1.NetworkPolicy{n}}
	delta := uint64(3)
	f := model.Finding{ID: "a", Node: "worker", Source: model.Endpoint{Network: "red/net", Pod: "client", Namespace: "red"}, Destination: pod, CounterID: "worker/ufid", ObservedAt: at, Delta: &delta, Packets: 12, Protocol: "TCP", SharedCounter: true, Causes: []model.PolicyCause{{Type: "NetpolNamespace", Namespace: "red", Direction: "Ingress", ACL: "acl-1", Action: "drop"}}}
	o := model.TrafficObservation{Node: "worker", Source: f.Source, Destination: pod, Network: "red/net", End: at, Start: at.Add(-30 * time.Second), CounterID: f.CounterID, Verdict: "drop", Packets: 12, PacketDelta: &delta}
	forward := o
	forward.Verdict = "forward"
	forward.CounterID = "worker/forward"
	silent := o
	silent.CounterID = "worker/idle"
	zero := uint64(0)
	silent.PacketDelta = &zero
	baseline := forward
	baseline.CounterID = "worker/new"
	baseline.PacketDelta = nil
	baseline.Start = time.Time{}
	return model.View{CollectedAt: at, Pods: []model.Endpoint{pod}, Findings: []model.Finding{f, f}, Traffic: []model.TrafficObservation{o, forward, silent, baseline}}, inv
}

func TestCapturedAttribution(t *testing.T) {
	v, inv := sample(time.Now().UTC())
	b := records(v, inv)
	if len(b.entries["drop"]) != 1 || len(b.entries["forward"]) != 2 {
		t.Fatal("equivalent paths, unchanged counters or baselines mishandled", b.entries)
	}
	inv.Policies[0].Name = "replacement"
	var r Record
	if err := json.Unmarshal([]byte(b.entries["drop"][0][1]), &r); err != nil {
		t.Fatal(err)
	}
	if !r.Shared || r.Delta == nil || *r.Delta != 3 || r.Source.Labels != nil || len(r.Causes) != 1 || r.Causes[0].Name != "" || strings.Join(r.Causes[0].Selecting, ",") != "NetworkPolicy red/old-isolation" {
		t.Fatalf("incorrect historical attribution: %+v", r)
	}
	v.Pods[0].Network = "blue"
	b = records(v, inv)
	if strings.Contains(b.entries["drop"][0][1], "replacement") {
		t.Fatal("policy leaked across networks")
	}
	v.Findings[0].Causes = []model.PolicyCause{{Type: "AdminNetworkPolicy", Name: "deny-external", Direction: "Egress", Rule: "1", ACL: "acl-admin", Action: "drop", Admin: &model.AdminPolicyEvidence{RuleName: "block-test"}}}
	v.Findings = v.Findings[:1]
	b = records(v, inv)
	if !strings.Contains(b.entries["drop"][0][1], "deny-external") || !strings.Contains(b.entries["drop"][0][1], "block-test") {
		t.Fatal("missing named blocking rule")
	}
}

func TestLokiProtocol(t *testing.T) {
	var saved []stream
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Scope-OrgID") != "tenant-a" {
			t.Error("missing tenant")
		}
		switch r.URL.Path {
		case "/gateway/loki/api/v1/push":
			z, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			defer z.Close()
			var push struct{ Streams []stream }
			if json.NewDecoder(z).Decode(&push) != nil {
				t.Error("invalid push")
				return
			}
			for _, str := range push.Streams {
				if str.Labels["cluster"] != "cluster-a" || len(str.Labels) != 3 {
					t.Error("unexpected stream labels")
				}
			}
			saved = push.Streams
			w.WriteHeader(204)
		case "/gateway/loki/api/v1/query_range":
			if r.URL.Query().Get("query") != "{job=\"ovn-light\",cluster=\"cluster-a\",verdict=\"drop\"} |= \"a\\\"b\" | json observed_network=\"network\" | observed_network=\"red/net\"" {
				t.Error(r.URL.Query().Get("query"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "streams", "result": saved}})
		default:
			t.Error("unexpected path")
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	s, err := New(Config{URL: server.URL + "/gateway", Cluster: "cluster-a", Tenant: "tenant-a"})
	if err != nil {
		t.Fatal(err)
	}
	v, inv := sample(time.Now().UTC().Add(-time.Hour))
	s.write(context.Background(), records(v, inv))
	if s.Status().Written != 3 {
		t.Fatal(s.Status())
	}
	q := url.Values{"start": {v.CollectedAt.Add(-time.Minute).Format(time.RFC3339)}, "end": {v.CollectedAt.Add(time.Minute).Format(time.RFC3339)}, "verdict": {"drop"}, "search": {"a\"b"}, "network": {"red/net"}, "limit": {"1"}}
	result, err := s.Query(context.Background(), q)
	if err != nil || !result.More || len(result.Rows) != 1 {
		t.Fatal(result, err)
	}
	q.Set("start", "bad")
	if _, err = s.Query(context.Background(), q); err == nil {
		t.Fatal("invalid time accepted")
	}
	for i := 0; i < 5; i++ {
		s.Record(v, inv)
	}
	if s.Status().Omitted != 3 {
		t.Fatal("queue overflow not reported", s.Status())
	}
	var disabled *Store
	result, err = disabled.Query(context.Background(), nil)
	if err != nil || result.Status.Enabled {
		t.Fatal("disabled store queried Loki")
	}
}

func TestFailedExport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	s, err := New(Config{URL: server.URL, Cluster: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	v, inv := sample(time.Now().UTC())
	s.Record(v, inv)
	s.write(context.Background(), <-s.queue)
	status := s.Status()
	if status.Written != 0 || status.Omitted != 3 || !strings.Contains(status.LastError, "403") {
		t.Fatalf("lost export was not reported: %+v", status)
	}
}

// Run against a single-process test Loki with OVN_LIGHT_TEST_LOKI_URL. A dedicated stream
// keeps yesterday's synthetic observations out of the demo's history.
func TestLokiYesterday(t *testing.T) {
	address := os.Getenv("OVN_LIGHT_TEST_LOKI_URL")
	if address == "" {
		t.Skip("set OVN_LIGHT_TEST_LOKI_URL to run the Loki integration test")
	}
	now := time.Now().UTC()
	yesterday := now.Truncate(24 * time.Hour).Add(-12 * time.Hour)
	v, inv := sample(yesterday)
	s, err := New(Config{URL: address, Cluster: "ovn-light-test-" + nanos(now)})
	if err != nil {
		t.Fatal(err)
	}
	s.write(context.Background(), records(v, inv))
	if s.Status().Written != 3 {
		t.Fatal(s.Status())
	}
	// A previous-day query can skip the ingester for an old time range.
	// Flush this test instance so the query exercises persisted chunks.
	resp, err := s.request(context.Background(), "POST", "/flush", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("flush test Loki: %s", resp.Status)
	}
	inv.Policies = nil
	reader, err := New(s.config)
	if err != nil {
		t.Fatal(err)
	}
	q := url.Values{"start": {yesterday.Add(-time.Hour).Format(time.RFC3339)}, "end": {yesterday.Add(time.Hour).Format(time.RFC3339)}, "network": {"red/net"}, "verdict": {"drop"}, "search": {"old-isolation"}}
	var r Result
	for i := 0; i < 10; i++ {
		r, err = reader.Query(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Rows) > 0 {
			break
		}
		time.Sleep(time.Second)
	}
	if len(r.Rows) != 1 || !r.Rows[0].At.Equal(yesterday) || len(r.Rows[0].Causes) != 1 || r.Rows[0].Causes[0].ACL != "acl-1" || len(r.Rows[0].Causes[0].Selecting) != 1 {
		t.Fatal("yesterday's attribution was not preserved", r)
	}
	q.Set("network", "other")
	if r, err = reader.Query(context.Background(), q); err != nil || len(r.Rows) != 0 {
		t.Fatal("network filter", r, err)
	}
	q.Set("network", "")
	q.Set("search", "")
	q.Set("verdict", "forward")
	if r, err = reader.Query(context.Background(), q); err != nil || len(r.Rows) != 2 {
		t.Fatal("forwarded history", r, err)
	}
}
