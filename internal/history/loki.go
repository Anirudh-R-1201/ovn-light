// SPDX-License-Identifier: Apache-2.0
package history

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trozet/ovn-light/internal/model"
)

type Config struct {
	URL, Cluster              string
	Tenant, TokenFile, CAFile string
}

type Status struct {
	Enabled   bool       `json:"enabled"`
	Written   uint64     `json:"written"`
	Omitted   uint64     `json:"omitted"`
	LastWrite *time.Time `json:"lastWrite,omitempty"`
	LastError string     `json:"lastError,omitempty"`
}

type Store struct {
	config  Config
	client  *http.Client
	queue   chan batch
	queries chan struct{}
	mu      sync.Mutex
	status  Status
}

func New(c Config) (*Store, error) {
	base, err := url.Parse(c.URL)
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, fmt.Errorf("configure an HTTP or HTTPS Loki base URL without credentials or query parameters")
	}
	if c.Cluster == "" || len(c.Cluster) > 128 || strings.ContainsAny(c.Cluster+c.Tenant, "\r\n") {
		return nil, fmt.Errorf("configure a stable Loki cluster name and a valid tenant")
	}
	if c.TokenFile != "" && base.Scheme != "https" {
		return nil, fmt.Errorf("Loki bearer authentication requires HTTPS")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("invalid Loki trust bundle")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	c.URL = strings.TrimRight(c.URL, "/")
	return &Store{
		config:  c,
		queue:   make(chan batch, 4),
		queries: make(chan struct{}, 2),
		client: &http.Client{
			Transport:     tr,
			Timeout:       12 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		status: Status{Enabled: true},
	}, nil
}

func (s *Store) Status() Status {
	if s == nil {
		return Status{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// Record queues a bounded projection so a slow archive cannot hold up collection.
func (s *Store) Record(v model.View, inv model.Inventory) {
	b := records(v, inv)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.Omitted += uint64(b.omitted)
	if b.bytes == 0 {
		return
	}
	select {
	case s.queue <- b:
	default:
		for _, values := range b.entries {
			s.status.Omitted += uint64(len(values))
		}
		s.status.LastError = "Loki export queue full"
	}
}

type stream struct {
	Labels map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

func (s *Store) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-s.queue:
			s.write(ctx, b)
		}
	}
}

func (s *Store) write(ctx context.Context, b batch) {
	var streams []stream
	count := 0
	for _, verdict := range []string{"drop", "forward"} {
		values := b.entries[verdict]
		if len(values) == 0 {
			continue
		}
		sort.SliceStable(values, func(i, j int) bool { return values[i][0] < values[j][0] })
		streams = append(streams, stream{map[string]string{"job": "ovn-light", "cluster": s.config.Cluster, "verdict": verdict}, values})
		count += len(values)
	}
	var buf bytes.Buffer
	z, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	err := json.NewEncoder(z).Encode(map[string]any{"streams": streams})
	if closeErr := z.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		for attempt := 0; attempt < 3; attempt++ {
			var res *http.Response
			res, err = s.request(ctx, "POST", "/loki/api/v1/push", nil, buf.Bytes())
			if err == nil {
				res.Body.Close()
				if res.StatusCode == http.StatusNoContent {
					break
				}
				err = fmt.Errorf("Loki push returned HTTP %d", res.StatusCode)
				if res.StatusCode != 429 && res.StatusCode != 260 && res.StatusCode < 500 {
					break
				}
			}
			if attempt < 2 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second << attempt):
				}
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.status.Omitted += uint64(count)
		s.status.LastError = err.Error()
		log.Printf("traffic history: %v", err)
		return
	}
	t := time.Now().UTC()
	s.status.LastWrite = &t
	s.status.LastError = ""
	s.status.Written += uint64(count)
}

func (s *Store) request(ctx context.Context, method, path string, q url.Values, body []byte) (*http.Response, error) {
	address := s.config.URL + path
	if len(q) > 0 {
		address += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, address, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if method == "POST" {
		req.Header.Set("Content-Encoding", "gzip")
		req.Header.Set("Content-Type", "application/json")
	}
	if s.config.Tenant != "" {
		req.Header.Set("X-Scope-OrgID", s.config.Tenant)
	}
	if s.config.TokenFile != "" {
		b, err := os.ReadFile(s.config.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("could not read Loki bearer token")
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(b)))
	}
	return s.client.Do(req)
}

type Result struct {
	Status Status   `json:"status"`
	Rows   []Record `json:"rows"`
	More   bool     `json:"more"`
}

func nanos(t time.Time) string { return strconv.FormatInt(t.UnixNano(), 10) }

// Query accepts only bounded time ranges and literal filters. Loki applies
// the filters before its result limit so a rare drop remains discoverable.
func (s *Store) Query(ctx context.Context, q url.Values) (Result, error) {
	out := Result{Status: s.Status(), Rows: []Record{}}
	if s == nil {
		return out, nil
	}
	start, e1 := time.Parse(time.RFC3339Nano, q.Get("start"))
	end, e2 := time.Parse(time.RFC3339Nano, q.Get("end"))
	if e1 != nil || e2 != nil || start.Before(time.Unix(0, 0)) || end.After(time.Now().Add(time.Minute)) || !end.After(start) || end.Sub(start) > 7*24*time.Hour {
		return out, fmt.Errorf("choose a past time range of up to 7 days")
	}
	limit := 100
	if q.Has("limit") {
		n, err := strconv.Atoi(q.Get("limit"))
		if err != nil || n < 1 || n > 200 {
			return out, fmt.Errorf("limit must be 1–200")
		}
		limit = n
	}
	selector := "{job=\"ovn-light\",cluster=" + strconv.Quote(s.config.Cluster)
	switch v := q.Get("verdict"); v {
	case "":
	case "forward", "drop":
		selector += ",verdict=" + strconv.Quote(v)
	default:
		return out, fmt.Errorf("unknown verdict")
	}
	query := selector + "}"
	search, network := q.Get("search"), q.Get("network")
	if len(search) > 256 || len(network) > 256 {
		return out, fmt.Errorf("history filter exceeds 256 bytes")
	}
	if search != "" {
		query += " |= " + strconv.Quote(search)
	}
	if network != "" {
		query += " | json observed_network=\"network\" | observed_network=" + strconv.Quote(network)
	}
	select {
	case s.queries <- struct{}{}:
		defer func() { <-s.queries }()
	default:
		return out, fmt.Errorf("history queries busy; retry shortly")
	}
	values := url.Values{"query": {query}, "start": {nanos(start)}, "end": {nanos(end)}, "direction": {"backward"}, "limit": {strconv.Itoa(limit + 1)}}
	res, err := s.request(ctx, "GET", "/loki/api/v1/query_range", values, nil)
	if err != nil {
		return out, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return out, fmt.Errorf("Loki query returned HTTP %d", res.StatusCode)
	}
	const responseLimit = 8 << 20
	raw, err := io.ReadAll(io.LimitReader(res.Body, responseLimit+1))
	if err != nil || len(raw) > responseLimit {
		return out, fmt.Errorf("could not read bounded Loki query response")
	}
	var reply struct {
		Status string
		Data   struct {
			ResultType string
			Result     []stream
		}
	}
	if json.Unmarshal(raw, &reply) != nil || reply.Status != "success" || reply.Data.ResultType != "streams" {
		return out, fmt.Errorf("unexpected Loki query response")
	}
	for _, stream := range reply.Data.Result {
		for _, entry := range stream.Values {
			var row Record
			if len(entry[1]) > lineLimit || json.Unmarshal([]byte(entry[1]), &row) != nil || row.At.IsZero() {
				return out, fmt.Errorf("invalid OVN-Light history record")
			}
			out.Rows = append(out.Rows, row)
		}
	}
	sort.SliceStable(out.Rows, func(i, j int) bool { return out.Rows[i].At.After(out.Rows[j].At) })
	out.More = len(out.Rows) > limit
	if out.More {
		out.Rows = out.Rows[:limit]
	}
	return out, nil
}
