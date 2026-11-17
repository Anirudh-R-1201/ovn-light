// SPDX-License-Identifier: Apache-2.0
package web

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/trozet/ovn-light/internal/app"
	"github.com/trozet/ovn-light/internal/offload"
	"github.com/trozet/ovn-light/internal/policy"
	"github.com/trozet/ovn-light/internal/routing"
	"github.com/trozet/ovn-light/internal/topology"
	trace "github.com/trozet/ovn-light/internal/trace"
)

//go:embed assets/*
var assets embed.FS

func Handler(a *app.App, token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /api/trace/context", func(w http.ResponseWriter, r *http.Request) { respond(w, a.TraceContext(), nil) })
	mux.HandleFunc("POST /api/trace", func(w http.ResponseWriter, r *http.Request) {
		var request trace.Request
		if err := decode(w, r, &request); err != nil {
			respond(w, nil, err)
			return
		}
		report, err := a.Simulate(r.Context(), request)
		respond(w, report, err)
	})
	mux.HandleFunc("POST /api/trace/tcp", func(w http.ResponseWriter, r *http.Request) {
		var request trace.Request
		if err := decode(w, r, &request); err != nil {
			respond(w, nil, err)
			return
		}
		result, err := a.TraceCheck(r.Context(), "tcp", request, trace.Check{})
		respond(w, result, err)
	})
	mux.HandleFunc("POST /api/trace/dns", func(w http.ResponseWriter, r *http.Request) {
		var request trace.Check
		if err := decode(w, r, &request); err != nil {
			respond(w, nil, err)
			return
		}
		result, err := a.TraceCheck(r.Context(), "dns", trace.Request{}, request)
		respond(w, result, err)
	})
	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) { respond(w, a.State(), nil) })
	mux.HandleFunc("GET /api/offload", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		for _, field := range []string{"node", "network", "status", "search", "id"} {
			if len(q.Get(field)) > 256 {
				respond(w, nil, fmt.Errorf("%s filter is too long", field))
				return
			}
		}
		limit := 50
		if q.Has("limit") {
			var err error
			limit, err = strconv.Atoi(q.Get("limit"))
			if err != nil || limit < 1 || limit > 100 {
				respond(w, nil, fmt.Errorf("limit must be 1–100"))
				return
			}
		}
		switch q.Get("status") {
		case "", "issues", "hardware", "partial", "software", "failure", "unknown", "pending", "not-expected":
		default:
			respond(w, nil, fmt.Errorf("invalid offload status"))
			return
		}
		respond(w, a.Offload(offload.Options{Node: q.Get("node"), Network: q.Get("network"), Status: q.Get("status"), Search: q.Get("search"), ID: q.Get("id"), Limit: limit}), nil)
	})
	mux.HandleFunc("GET /api/routing", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		o := routing.Options{Network: q.Get("network"), Node: q.Get("node"), Search: q.Get("search"), Limit: 40}
		for _, value := range []string{o.Network, o.Node, o.Search} {
			if len(value) > 256 {
				respond(w, nil, fmt.Errorf("filter is too long"))
				return
			}
		}
		var err error
		if q.Has("limit") {
			o.Limit, err = strconv.Atoi(q.Get("limit"))
			if err != nil || o.Limit < 1 || o.Limit > 100 {
				respond(w, nil, fmt.Errorf("limit must be 1–100"))
				return
			}
		}
		if q.Has("offset") {
			o.Offset, err = strconv.Atoi(q.Get("offset"))
			if err != nil || o.Offset < 0 || o.Offset > 100000 {
				respond(w, nil, fmt.Errorf("invalid offset"))
				return
			}
		}
		respond(w, a.Routing(o), nil)
	})
	mux.HandleFunc("GET /api/context", func(w http.ResponseWriter, r *http.Request) {
		v := a.State()
		respond(w, map[string]any{"mode": v.Mode, "writesEnabled": v.WritesEnabled, "collectedAt": v.CollectedAt, "collecting": v.Collecting, "networks": v.Networks, "nodes": v.Nodes}, nil)
	})
	mux.HandleFunc("GET /api/topology", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		for _, field := range []string{"network", "node", "edge"} {
			if len(q.Get(field)) > 256 {
				respond(w, nil, fmt.Errorf("%s filter is too long", field))
				return
			}
		}
		limit, window := 40, 120
		var err error
		if q.Has("limit") {
			limit, err = strconv.Atoi(q.Get("limit"))
			if err != nil || limit < 1 || limit > 100 {
				respond(w, nil, fmt.Errorf("limit must be 1–100"))
				return
			}
		}
		if q.Has("window") {
			window, err = strconv.Atoi(q.Get("window"))
			if err != nil || window < 30 || window > 600 {
				respond(w, nil, fmt.Errorf("window must be 30–600 seconds"))
				return
			}
		}
		if level := q.Get("level"); level != "" && level != "nodes" && level != "pods" {
			respond(w, nil, fmt.Errorf("level must be nodes or pods"))
			return
		}
		o := topology.Options{Network: q.Get("network"), Node: q.Get("node"), Level: q.Get("level"), Filter: q.Get("filter"), Sort: q.Get("sort"), Edge: q.Get("edge"), Window: time.Duration(window) * time.Second, Limit: limit}
		respond(w, a.Topology(o), nil)
	})
	mux.HandleFunc("GET /api/plans", func(w http.ResponseWriter, r *http.Request) { respond(w, a.Plans(), nil) })
	mux.HandleFunc("GET /api/snapshot", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="ovn-light-snapshot.json"`)
		respond(w, a.Snapshot(), nil)
	})
	mux.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, r *http.Request) {
		err := a.Refresh(r.Context())
		respond(w, a.State(), err)
	})
	mux.HandleFunc("POST /api/plans", func(w http.ResponseWriter, r *http.Request) {
		var i policy.Intent
		if err := decode(w, r, &i); err != nil {
			respond(w, nil, err)
			return
		}
		p, err := a.Prepare(r.Context(), i)
		respond(w, p, err)
	})
	mux.HandleFunc("POST /api/plans/{id}/{action}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if len(id) != 32 {
			respond(w, nil, fmt.Errorf("invalid proposal ID"))
			return
		}
		var p policy.Plan
		var err error
		switch r.PathValue("action") {
		case "apply":
			p, err = a.Apply(r.Context(), id)
		case "rollback":
			p, err = a.Rollback(r.Context(), id)
		case "verify":
			var probe struct {
				Port int `json:"port"`
			}
			if r.ContentLength != 0 {
				if err = decode(w, r, &probe); err != nil {
					respond(w, nil, err)
					return
				}
			}
			p, err = a.Verify(r.Context(), id, probe.Port)
		default:
			http.NotFound(w, r)
			return
		}
		respond(w, p, err)
	})
	root, _ := fs.Sub(assets, "assets")
	mux.Handle("GET /", http.FileServer(http.FS(root)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
			if token != "" && subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")), []byte(token)) != 1 {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || u.Host != r.Host || u.Scheme != "http" && u.Scheme != "https" {
					http.Error(w, "cross-origin request rejected", http.StatusForbidden)
					return
				}
			}
			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				http.Error(w, "cross-site request rejected", http.StatusForbidden)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("expected one JSON object")
	}
	return nil
}
func respond(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "result": v})
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

func Server(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
}
