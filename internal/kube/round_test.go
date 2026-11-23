// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/trozet/ovn-light/internal/model"
)

func TestRoundRejectsStaleOrForeignReportsAndAcceptsRetriesOnce(t *testing.T) {
	h := NewHub(nil)
	h.credentials[sha256.Sum256([]byte("agent"))] = credential{"uid", time.Now().Add(time.Minute)}
	r := &collectionRound{expected: 1, id: "first", identity: map[string]string{"uid": "worker"}, reports: map[string]model.NodeSnapshot{}, done: make(chan struct{})}
	h.current = r
	upload := func(round, node string, rawFlows bool) int {
		n := model.NodeSnapshot{Name: node, Collection: model.CollectionStats{Agent: true}, Summary: &model.NodeSummary{OffloadNode: model.OffloadNode{Name: node}}}
		if rawFlows {
			n.Flows = "raw"
		}
		body, err := encodeSummary(n)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", "/v1/collection?round="+round, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer agent")
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		return res.Code
	}
	if upload("first", "other", false) != 400 || upload("old", "worker", false) != 409 || upload("first", "worker", true) != 400 {
		t.Fatal("invalid report accepted")
	}
	if upload("first", "worker", false) != 204 {
		t.Fatal("valid report rejected")
	}
	size := r.size
	if upload("first", "worker", false) != 204 || len(r.reports) != 1 || r.size != size {
		t.Fatal("retry duplicated a report")
	}
	h.current = nil
	if upload("first", "worker", false) != 409 {
		t.Fatal("closed round accepted report")
	}
	res := httptest.NewRecorder()
	h.ServeHTTP(res, httptest.NewRequest("GET", "/v1/collection", nil))
	if res.Code != http.StatusUnauthorized {
		t.Fatal(res.Code)
	}
}

func TestOversizeReportIsAnExplicitGap(t *testing.T) {
	n := model.NodeSnapshot{Name: "n", Collection: model.CollectionStats{Agent: true, FlowComplete: true}, Summary: &model.NodeSummary{Flows: 3, OffloadNode: model.OffloadNode{Name: "n"}, Traffic: []model.TrafficObservation{{Warnings: []string{strings.Repeat("x", nodeLimit)}}}}}
	b, err := encodeSummary(n)
	if err != nil {
		t.Fatal(err)
	}
	z, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	var out model.NodeSnapshot
	if json.Unmarshal(raw, &out) != nil || !validSummary(out) || out.Collection.FlowComplete || out.Summary.Flows != 3 || len(out.Errors) == 0 || len(out.Summary.Traffic) != 0 {
		t.Fatal("oversized report lost coverage information")
	}
}

func TestMissingCollectorDoesNotReuseOldCoverage(t *testing.T) {
	h := NewHub(nil)
	nodes, err := h.collect(context.Background(), model.Inventory{}, map[string]bool{"n": true}, "v1")
	if err != nil || len(nodes) != 1 || nodes[0].Collection.FlowComplete || nodes[0].Summary != nil || len(nodes[0].Errors) == 0 {
		t.Fatalf("missing coverage: %+v %v", nodes, err)
	}
}
