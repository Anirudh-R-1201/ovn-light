// SPDX-License-Identifier: Apache-2.0
package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trozet/ovn-light/internal/app"
)

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
