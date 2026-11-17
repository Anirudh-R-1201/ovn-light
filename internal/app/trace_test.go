// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"github.com/trozet/ovn-light/internal/ovn"
	trace "github.com/trozet/ovn-light/internal/trace"
	"testing"
)

func TestTraceSimulationAndProbeBoundaries(t *testing.T) {
	a, _ := New("demo", "", nil, nil, false)
	s := Demo()
	a.Load(s)
	pods := ovn.Attachments(s.Inventory)
	r := trace.Request{Source: pods[0].Endpoint, Destination: pods[1].Endpoint, Protocol: "TCP", Port: 8080}
	report, err := a.Simulate(context.Background(), r)
	if err != nil || report.Mode != "demo" || len(report.Results) != 1 {
		t.Fatalf("%+v %v", report, err)
	}
	if _, err = a.TraceCheck(context.Background(), "tcp", r, trace.Check{}); err == nil {
		t.Fatal("demo sent real traffic")
	}
	a.diagnostic.Lock()
	if _, err = a.Simulate(context.Background(), r); err == nil {
		t.Fatal("concurrent trace accepted")
	}
	a.diagnostic.Unlock()
	a.Mode = "snapshot"
	if _, err = a.Simulate(context.Background(), r); err == nil {
		t.Fatal("snapshot accepted live trace")
	}
}
