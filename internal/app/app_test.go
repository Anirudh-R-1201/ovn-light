// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"github.com/trozet/ovn-light/internal/offload"
	"testing"
	"time"

	"github.com/trozet/ovn-light/internal/policy"
)

func TestProposalPersistenceAndDemoImmutability(t *testing.T) {
	dir := t.TempDir()
	a, e := New("demo", dir, nil, nil, true)
	if e != nil {
		t.Fatal(e)
	}
	s := Demo()
	a.Load(s)
	if a.Writes {
		t.Fatal("demo must never permit writes")
	}
	v := a.State()
	var intent policy.Intent
	for _, f := range v.Findings {
		if f.CanRecommend {
			intent = policy.Intent{Kind: "NetworkPolicy", Source: f.Source, Destination: f.Destination, Protocol: f.Protocol, Port: f.Destination.Port}
		}
	}
	p, e := a.Prepare(context.Background(), intent)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Apply(context.Background(), p.ID); e == nil {
		t.Fatal("demo wrote to cluster")
	}
	b, e := New("demo", dir, nil, nil, false)
	if e != nil {
		t.Fatal(e)
	}
	if len(b.Plans()) != 1 || b.Plans()[0].ID != p.ID {
		t.Fatal("audit record did not survive restart")
	}
	returned := b.Plans()
	returned[0].Objects[0].SetName("tampered")
	if b.Plans()[0].Objects[0].GetName() == "tampered" {
		t.Fatal("API response mutated server proposal")
	}
}

func TestDropProposalRetainsObservedNetwork(t *testing.T) {
	a, _ := New("demo", "", nil, nil, false)
	a.Load(Demo())
	for _, f := range a.State().Findings {
		if !f.CanRecommend {
			continue
		}
		i := policy.Intent{Kind: "Policy", FindingID: f.ID, Source: f.Source, Destination: f.Destination, Protocol: f.Protocol, Port: f.Destination.Port}
		p, e := a.Prepare(context.Background(), i)
		if e != nil || p.Scope.Network != "default" {
			t.Fatal(p, e)
		}
		i.Source.Network = "analytics/data"
		if _, e = a.Prepare(context.Background(), i); e == nil {
			t.Fatal("drop proposal was moved to another network")
		}
		i.FindingID = "expired"
		if _, e = a.Prepare(context.Background(), i); e == nil {
			t.Fatal("missing observation was silently ignored")
		}
		return
	}
	t.Fatal("missing demo finding")
}

func TestOffloadStaleLiveEvidence(t *testing.T) {
	a, _ := New("live", "", nil, nil, false)
	s := Demo()
	s.CapturedAt = time.Now().Add(-5 * time.Minute)
	for i := range s.Nodes {
		s.Nodes[i].CapturedAt = s.CapturedAt
		s.Nodes[i].Offload.CapturedAt = s.CapturedAt
	}
	a.Load(s)
	r := a.Offload(offload.Options{})
	if len(r.Nodes) == 0 || r.Nodes[0].State != "unknown" || r.Issues != 0 {
		t.Fatal(r)
	}
	for _, p := range r.Paths {
		if p.Status != "unknown" || p.Issue {
			t.Fatal(p)
		}
	}
}
