// SPDX-License-Identifier: Apache-2.0
package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trozet/ovn-light/internal/app"
	"github.com/trozet/ovn-light/internal/topology"
)

func TestTopologyAuthenticationAndBounds(t *testing.T) {
	a, _ := app.New("demo", "", nil, nil, false)
	s := app.Demo()
	a.Load(app.DemoBaseline(s))
	a.Load(s)
	h := Handler(a, "secret")
	for _, path := range []string{"/api/topology", "/api/topology?limit=101", "/api/topology?window=-1", "/api/topology?level=invalid"} {
		r := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatal("topology bypassed auth", w.Code)
		}
		r.Header.Set("Authorization", "Bearer secret")
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if path != "/api/topology" {
			if w.Code != 400 {
				t.Fatal(path, w.Code)
			}
			continue
		}
		var g topology.Graph
		if err := json.Unmarshal(w.Body.Bytes(), &g); err != nil || len(g.Edges) == 0 {
			t.Fatal(w.Code, err, g)
		}
	}
}

func TestAuthAndOrigin(t *testing.T) {
	a, e := app.New("demo", "", nil, nil, false)
	if e != nil {
		t.Fatal(e)
	}
	a.Load(app.Demo())
	h := Handler(a, "test-token-with-enough-entropy")
	for _, tt := range []struct {
		path, token, origin, method string
		status                      int
	}{{"/api/state", "", "", "GET", 401}, {"/api/state", "wrong", "", "GET", 401}, {"/api/state", "test-token-with-enough-entropy", "", "GET", 200}, {"/api/refresh", "test-token-with-enough-entropy", "http://evil.example", "POST", 403}, {"/api/refresh", "test-token-with-enough-entropy", "http://example.com", "POST", 200}, {"/", "", "", "GET", 200}} {
		t.Run(tt.path+tt.token+tt.origin, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "http://example.com"+tt.path, nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tt.status {
				t.Fatalf("status=%d want=%d: %s", w.Code, tt.status, w.Body.String())
			}
			if w.Header().Get("Content-Security-Policy") == "" {
				t.Fatal("missing CSP")
			}
		})
	}
}
func TestRejectUntrustedManifestAndDemoWrites(t *testing.T) {
	a, _ := app.New("demo", "", nil, nil, false)
	a.Load(app.Demo())
	h := Handler(a, "")
	for _, body := range []string{`{"kind":"NetworkPolicy","objects":[{"kind":"Pod"}]}`, `{} {}`, strings.Repeat("x", 65537)} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://example.com/api/plans", strings.NewReader(body))
		h.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Fatalf("untrusted input accepted: %d", w.Code)
		}
	}
}

func TestOffloadAPIAuthenticationFiltersAndDetails(t *testing.T) {
	a, _ := app.New("demo", "", nil, nil, false)
	s := app.Demo()
	a.Load(app.DemoBaseline(s))
	a.Load(s)
	h := Handler(a, "secret")
	for _, path := range []string{"/api/offload", "/api/offload?limit=101", "/api/offload?status=bad", "/api/offload?node=missing"} {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 401 {
			t.Fatal("offload bypassed authentication")
		}
		req.Header.Set("Authorization", "Bearer secret")
		w = httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if strings.Contains(path, "101") || strings.Contains(path, "bad") {
			if w.Code != 400 {
				t.Fatal(path, w.Code)
			}
			continue
		}
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		var r struct {
			Paths []struct {
				ID     string `json:"id"`
				Stages []any  `json:"stages"`
			}
		}
		if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(path, "missing") {
			if len(r.Paths) != 0 {
				t.Fatal("node filter leaked")
			}
			continue
		}
		if len(r.Paths) == 0 || len(r.Paths[0].Stages) != 0 {
			t.Fatal("summary should omit raw stages", r)
		}
		req = httptest.NewRequest("GET", "/api/offload?id="+r.Paths[0].ID, nil)
		req.Header.Set("Authorization", "Bearer secret")
		w = httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil || len(r.Paths) != 1 || len(r.Paths[0].Stages) == 0 {
			t.Fatal("detail lost stage evidence", w.Body.String())
		}
	}
}
