// SPDX-License-Identifier: Apache-2.0
package offload

import (
	"sort"
	"strings"
	"time"

	"github.com/trozet/ovn-light/internal/model"
)

type history struct {
	signature, datapath      string
	at, since, diagnosticsAt time.Time
	sampleComplete           bool
	samples, ctSamples       int
	stages                   []model.OffloadStage
}
type Store struct {
	Grace   time.Duration
	history map[string]history
	report  model.OffloadReport
}
type Options struct {
	Stale                             bool
	Node, Network, Status, Search, ID string
	Limit                             int
}

// Update counts only increasing counters from consecutive comparable samples.
// Missing nodes, counter resets, and changed actions discard the alert history.
func (s *Store) Update(r model.OffloadReport) []model.OffloadIssue {
	grace := s.Grace
	if grace <= 0 {
		grace = time.Minute
	}
	r.GraceSeconds = int(grace.Seconds())
	next := map[string]history{}
	issues := []model.OffloadIssue{}
	retained := make([]model.OffloadPath, 0, min(len(r.Paths), 4000))
	bytes := 0
	for _, p := range r.Paths {
		size := 0
		for _, st := range p.Stages {
			size += len(st.Raw) + len(st.Reason) + 256
		}
		for _, ct := range p.Conntrack {
			size += len(ct.Raw) + 256
		}
		if len(retained) >= 4000 || bytes+size > 16<<20 {
			r.Omitted++
			continue
		}
		bytes += size
		before, ok := s.history[p.ID]
		comparable := ok && p.SampleComplete && before.sampleComplete && before.signature == p.Signature && before.datapath == p.Datapath && p.ObservedAt.After(before.at) && p.ObservedAt.Sub(before.at) <= 2*time.Minute && len(before.stages) == len(p.Stages)
		active, bad := false, false
		var maxDelta, maxPartial uint64
		if comparable {
			for i, st := range p.Stages {
				old := before.stages[i]
				if st.ID != old.ID || st.Status != old.Status || st.Packets < old.Packets || st.Bytes < old.Bytes || st.PartialPackets < old.PartialPackets || st.PartialBytes < old.PartialBytes || strings.HasPrefix(st.ID, "synthetic-") {
					comparable = false
					break
				}
				d, part := st.Packets-old.Packets, st.PartialPackets-old.PartialPackets
				p.Stages[i].PacketDelta, p.Stages[i].PartialDelta = &d, &part
				maxDelta = max(maxDelta, d)
				maxPartial = max(maxPartial, part)
				active = active || d > 0 || part > 0
				bad = bad || part > 0 || d > 0 && (st.Status == "software" || st.Status == "partial")
			}
		}
		if comparable {
			p.ActivityDelta, p.PartialDelta = &maxDelta, &maxPartial
			if maxPartial > 0 && p.Eligible && p.Status != "failure" {
				p.Status = "partial"
				p.Summary = "Partial-offload packets are still being processed in software."
			}
			bad = bad || p.CTProblem && active
		} else {
			active, bad = false, false
			for i := range p.Stages {
				p.Stages[i].PacketDelta = nil
				p.Stages[i].PartialDelta = nil
			}
		}
		h := history{sampleComplete: p.SampleComplete, signature: p.Signature, datapath: p.Datapath, at: p.ObservedAt, diagnosticsAt: p.DiagnosticsAt}
		if comparable && active && bad && p.Eligible {
			h.since, h.samples, h.ctSamples = before.since, before.samples+1, before.ctSamples
			if h.since.IsZero() {
				h.since = p.ObservedAt
			}
			if p.DiagnosticsAt.After(before.diagnosticsAt) {
				h.ctSamples++
			}
			// Cached CT output is one observation, even across several flow polls.
			if p.CTProblem && h.ctSamples < 2 {
				h.samples = min(h.samples, 2)
			}
			p.Since = h.since
			if h.samples >= 3 && p.ObservedAt.Sub(h.since) >= grace {
				p.Issue = true
				switch p.Status {
				case "failure":
					p.Summary = "Persistent provider-reported offload failure."
				case "partial":
					p.Summary = "Persistent partial offload with continuing software activity."
				default:
					p.Summary = "Persistent software fallback on an offload-capable path."
				}
			}
		}
		h.stages = append([]model.OffloadStage{}, p.Stages...)
		for i := range h.stages {
			h.stages[i].Raw = ""
			h.stages[i].Reason = ""
		}
		next[p.ID] = h
		if p.Issue {
			issues = append(issues, model.OffloadIssue{ID: p.ID, Node: p.Node, Network: p.Network, Summary: p.Summary, Source: p.Source, Destination: p.Destination})
		}
		retained = append(retained, p)
	}
	r.Paths = retained
	r.Total = len(retained) + r.Omitted
	r.Issues = len(issues)
	sort.Slice(r.Paths, func(i, j int) bool {
		a, b := r.Paths[i], r.Paths[j]
		if a.Issue != b.Issue {
			return a.Issue
		}
		if value(a.PartialDelta) != value(b.PartialDelta) {
			return value(a.PartialDelta) > value(b.PartialDelta)
		}
		if value(a.ActivityDelta) != value(b.ActivityDelta) {
			return value(a.ActivityDelta) > value(b.ActivityDelta)
		}
		return a.ID < b.ID
	})
	s.history, s.report = next, r
	return issues
}
func value(v *uint64) uint64 {
	if v == nil {
		return 0
	}
	return *v
}

func (s *Store) Report(o Options) model.OffloadReport {
	r := s.report
	r.Paths = []model.OffloadPath{}
	r.Nodes = []model.OffloadNode{}
	r.Total, r.Issues = 0, 0
	for _, n := range s.report.Nodes {
		if o.Stale {
			n.State = "unknown"
			n.Errors = append(append([]string{}, n.Errors...), "Collection is stale; current offload health is unknown.")
		}
		if o.Node == "" || n.Name == o.Node {
			if o.Node == "" && o.ID == "" {
				n.Stats = ""
				n.PMDStats = ""
			}
			r.Nodes = append(r.Nodes, n)
		}
	}
	limit := o.Limit
	if limit <= 0 {
		limit = 50
	}
	limit = min(limit, 100)
	for _, p := range s.report.Paths {
		if o.Stale {
			p.Issue = false
			p.Status = "unknown"
			p.Summary = "Collection is stale; current offload health is unknown."
		}
		if o.Node != "" && p.Node != o.Node || o.Network != "" && p.Network != o.Network || o.Status != "" && o.Status != p.Status && !(o.Status == "issues" && p.Issue) || o.ID != "" && o.ID != p.ID {
			continue
		}
		if o.Search != "" && !strings.Contains(strings.ToLower(strings.Join([]string{p.Node, p.Network, p.Source.Namespace, p.Source.Pod, p.Source.IP, p.Destination.Namespace, p.Destination.Pod, p.Destination.IP, p.Summary}, " ")), strings.ToLower(o.Search)) {
			continue
		}
		r.Total++
		if p.Issue {
			r.Issues++
		}
		if len(r.Paths) >= limit {
			continue
		}
		if o.ID == "" {
			p.Stages = nil
			p.Conntrack = nil
		}
		r.Paths = append(r.Paths, p)
	}
	r.Omitted += r.Total - len(r.Paths)
	return r
}
