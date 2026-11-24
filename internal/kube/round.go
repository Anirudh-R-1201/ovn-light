// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
	auth "k8s.io/api/authentication/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	wireLimit    = 1 << 20
	nodeLimit    = 4 << 20
	roundLimit   = 64 << 20
	contextLimit = 32 << 20
	audience     = "ovn-light-collectors"
)

type collectionRound struct {
	id, key  string
	identity map[string]string // bound pod UID to node
	reports  map[string]model.NodeSnapshot
	done     chan struct{}
	size     int
	expected int
}
type credential struct {
	uid   string
	until time.Time
}
type Hub struct {
	client      *Client
	mu          sync.Mutex
	current     *collectionRound
	changed     chan struct{}
	credentials map[[32]byte]credential
	context     []byte
	key         string
	slots       chan struct{}
}

func NewHub(c *Client) *Hub {
	return &Hub{client: c, changed: make(chan struct{}), credentials: map[[32]byte]credential{}, slots: make(chan struct{}, 8)}
}

func compress(data []byte) []byte {
	var b bytes.Buffer
	w, _ := gzip.NewWriterLevel(&b, gzip.BestSpeed)
	_, _ = w.Write(data)
	_ = w.Close()
	return b.Bytes()
}

func (h *Hub) collect(ctx context.Context, inv model.Inventory, names map[string]bool, key string) ([]model.NodeSnapshot, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("no nodes selected for DaemonSet collection")
	}
	r := &collectionRound{id: rand.Text(), key: key, identity: map[string]string{}, reports: map[string]model.NodeSnapshot{}, done: make(chan struct{})}
	scheduled := map[string]bool{}
	for _, p := range inv.Pods {
		owner := meta.GetControllerOf(&p)
		if p.Namespace == "ovn-light" && p.Spec.ServiceAccountName == "ovn-light-agent" && owner != nil && owner.Kind == "DaemonSet" && owner.Name == "ovn-light-agent" && p.DeletionTimestamp == nil && names[p.Spec.NodeName] {
			r.identity[string(p.UID)] = p.Spec.NodeName
			scheduled[p.Spec.NodeName] = true
		}
	}
	r.expected = len(scheduled)
	// Collector.Capture serializes rounds. Publish the encoded projection once
	// and keep it immutable while agents read it without holding the hub lock.
	h.mu.Lock()
	if key != h.key {
		raw, err := json.Marshal(ovn.Project(inv))
		if err != nil || len(raw) > contextLimit {
			h.mu.Unlock()
			return nil, fmt.Errorf("collector context exceeds budget or cannot be encoded")
		}
		h.context, h.key = compress(raw), key
	}
	h.current = r
	close(h.changed)
	h.changed = make(chan struct{})
	h.mu.Unlock()
	timer := time.NewTimer(95 * time.Second)
	defer timer.Stop()
	// A node without a scheduled collector can be reported immediately.
	if len(r.identity) > 0 {
		select {
		case <-r.done:
		case <-ctx.Done():
		case <-timer.C:
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.current = nil
	nodes := make([]model.NodeSnapshot, 0, len(names))
	for name := range names {
		n, ok := r.reports[name]
		if !ok {
			n = model.NodeSnapshot{Name: name, CapturedAt: time.Now().UTC(), Collection: model.CollectionStats{Agent: true}, Errors: []string{"No collector summary for this round."}}
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

func (h *Hub) identify(r *http.Request) string {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" || len(token) > 16384 {
		return ""
	}
	hash := sha256.Sum256([]byte(token))
	h.mu.Lock()
	c := h.credentials[hash]
	h.mu.Unlock()
	if time.Now().Before(c.until) {
		return c.uid
	}
	result, err := h.client.Core.AuthenticationV1().TokenReviews().Create(r.Context(), &auth.TokenReview{Spec: auth.TokenReviewSpec{Token: token, Audiences: []string{audience}}}, meta.CreateOptions{})
	if err != nil || !result.Status.Authenticated || result.Status.User.Username != "system:serviceaccount:ovn-light:ovn-light-agent" || len(result.Status.Audiences) != 1 || result.Status.Audiences[0] != audience {
		return ""
	}
	uids := result.Status.User.Extra["authentication.kubernetes.io/pod-uid"]
	if len(uids) != 1 || uids[0] == "" {
		return ""
	}
	h.mu.Lock()
	if len(h.credentials) >= 4096 {
		clear(h.credentials)
	}
	h.credentials[hash] = credential{uids[0], time.Now().Add(time.Minute)}
	h.mu.Unlock()
	return uids[0]
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/v1/collection" || req.Method != "GET" && req.Method != "POST" {
		http.NotFound(w, req)
		return
	}
	uid := h.identify(req)
	if uid == "" {
		http.Error(w, "collector authentication required", http.StatusUnauthorized)
		return
	}
	if req.Method == "GET" {
		h.work(w, req, uid)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		http.Error(w, "busy", 503)
		return
	}
	h.mu.Lock()
	r := h.current
	node := ""
	if r != nil {
		node = r.identity[uid]
	}
	h.mu.Unlock()
	if node == "" || req.URL.Query().Get("round") != r.id {
		http.Error(w, "expired round", 409)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, wireLimit))
	if err != nil {
		http.Error(w, "report too large", 413)
		return
	}
	z, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		http.Error(w, "invalid compression", 400)
		return
	}
	defer z.Close()
	raw, err := io.ReadAll(io.LimitReader(z, nodeLimit+1))
	if err != nil || len(raw) > nodeLimit {
		http.Error(w, "invalid or oversized report", 400)
		return
	}
	var n model.NodeSnapshot
	if json.Unmarshal(raw, &n) != nil || n.Name != node || !validSummary(n) {
		http.Error(w, "invalid node summary", 400)
		return
	}
	n.Collection.SummaryBytes = len(body)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.current != r {
		http.Error(w, "expired round", 409)
		return
	}
	if _, ok := r.reports[node]; !ok {
		if r.size+len(raw) > roundLimit {
			n = model.NodeSnapshot{Name: node, CapturedAt: n.CapturedAt, Collection: model.CollectionStats{Agent: true}, Errors: []string{"Cluster summary byte budget reached."}}
		} else {
			r.size += len(raw)
		}
		r.reports[node] = n
		if len(r.reports) == r.expected {
			close(r.done)
		}
	}
	w.WriteHeader(204)
}

func validSummary(n model.NodeSnapshot) bool {
	m := n.Summary
	if m == nil || !n.Collection.Agent || m.OffloadNode.Name != n.Name || n.Flows != "" || n.Ports != "" || len(n.LogicalFlows)+len(n.Bindings)+len(n.Datapaths)+len(n.ACLs)+len(n.Detraces) != 0 {
		return false
	}
	for _, f := range m.Findings {
		if f.Node != n.Name || !strings.HasPrefix(f.CounterID, n.Name+"/") {
			return false
		}
	}
	for _, o := range m.Traffic {
		if o.Node != n.Name || !strings.HasPrefix(o.CounterID, n.Name+"/") {
			return false
		}
	}
	sampleAt := n.FlowCapturedAt
	if sampleAt.IsZero() {
		sampleAt = n.CapturedAt
	}
	for _, p := range m.TestPaths {
		if p.Node != n.Name || p.PodUID == "" || !p.At.Equal(sampleAt) {
			return false
		}
	}
	for _, p := range m.Paths {
		if p.Path.Node != n.Name {
			return false
		}
	}
	return true
}

func (h *Hub) work(w http.ResponseWriter, req *http.Request, uid string) {
	timer := time.NewTimer(25 * time.Second)
	defer timer.Stop()
	for {
		h.mu.Lock()
		r, ch := h.current, h.changed
		if r != nil && r.identity[uid] != "" && r.id != req.URL.Query().Get("after") {
			_, done := r.reports[r.identity[uid]]
			if !done {
				data := h.context
				h.mu.Unlock()
				w.Header().Set("X-Collection-Round", r.id)
				w.Header().Set("X-Context-Key", r.key)
				if req.URL.Query().Get("key") == r.key {
					w.WriteHeader(200)
					return
				}
				w.Header().Set("Content-Encoding", "gzip")
				_, _ = w.Write(data)
				return
			}
		}
		h.mu.Unlock()
		select {
		case <-req.Context().Done():
			return
		case <-timer.C:
			w.WriteHeader(204)
			return
		case <-ch:
		}
	}
}
