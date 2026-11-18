// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"fmt"
	"time"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
	"github.com/trozet/ovn-light/internal/qos"
	trace "github.com/trozet/ovn-light/internal/trace"
)

func (a *App) TraceContext() map[string]any {
	s := a.Snapshot()
	return map[string]any{"mode": a.Mode, "services": s.Inventory.Services, "pods": traceEndpoints(s.Inventory)}
}

func (a *App) Simulate(ctx context.Context, r trace.Request) (trace.Report, error) {
	if !a.diagnostic.TryLock() {
		return trace.Report{}, fmt.Errorf("another diagnostic is running; try again after it finishes")
	}
	defer a.diagnostic.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := trace.Validate(&r); err != nil {
		return trace.Report{}, err
	}
	if a.Mode == "demo" {
		inv := a.Snapshot().Inventory
		src, err := trace.Resolve(inv, r.Source)
		if err != nil {
			return trace.Report{}, err
		}
		r.Source = src.Endpoint
		dst, err := trace.Resolve(inv, r.Destination)
		if err != nil {
			return trace.Report{}, fmt.Errorf("demo simulation requires a destination pod: %w", err)
		}
		r.Destination = dst.Endpoint
		r.Destination.Port = r.Port
		return trace.Report{At: time.Now().UTC(), Mode: "demo", Request: r, Warnings: []string{"DEMO: illustrative output; no cluster command or real traffic was run."}, Results: []trace.Result{{Destination: r.Destination, Status: "predicted-drop", Segments: []trace.Segment{{Node: src.Node, Status: "predicted-drop", Summary: "Demo policy denies the selected connection.", Stages: []trace.Stage{{Name: "ls_in_port_sec", Pipeline: "ingress", Datapath: src.Node, InPort: src.LogicalPort, Actions: []string{"next;"}}, {Name: "ls_out_acl_eval", Pipeline: "egress", Datapath: dst.Node, OutPort: dst.LogicalPort, Actions: []string{"drop;"}}}, Causes: []model.PolicyCause{{Type: "NetpolNamespace", Namespace: dst.Endpoint.Namespace, Direction: "Ingress", Action: "drop", ACL: "demo-acl"}}}}}}}, nil
	}
	if a.Mode != "live" || a.Collector == nil || a.Client == nil {
		return trace.Report{}, fmt.Errorf("simulation requires a live OVN connection; snapshots retain only observed evidence")
	}
	inv, err := a.Client.Inventory(ctx)
	if err != nil {
		return trace.Report{}, err
	}
	report, err := a.Collector.Simulate(ctx, inv, r)
	s := a.Snapshot()
	s.Inventory = inv
	for _, p := range qos.Analyze(s).Policies {
		for _, e := range p.Targets {
			if e.UID == report.Request.Source.UID && e.Network == report.Request.Source.Network {
				p.Targets = nil
				p.Programs = p.Programs[:min(30, len(p.Programs))]
				report.QoS = append(report.QoS, p)
				break
			}
		}
		if len(report.QoS) >= 30 {
			report.Warnings = append(report.Warnings, "QoS context limited to 30 source policies; use the QoS page for full inventory.")
			break
		}
	}
	return report, err
}

func (a *App) TraceCheck(ctx context.Context, kind string, r trace.Request, dns trace.Check) (trace.CheckResult, error) {
	if !a.diagnostic.TryLock() {
		return trace.CheckResult{}, fmt.Errorf("another diagnostic is running; try again after it finishes")
	}
	defer a.diagnostic.Unlock()
	if a.Mode != "live" || a.Client == nil || !a.Writes {
		return trace.CheckResult{}, fmt.Errorf("real connection tests require a live server with active changes enabled and pods/exec permission in the source namespace")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	inv, err := a.Client.Inventory(ctx)
	if err != nil {
		return trace.CheckResult{}, err
	}
	if kind == "dns" {
		return a.Client.TraceDNS(ctx, inv, dns)
	}
	return a.Client.TraceProbe(ctx, inv, r)
}

// Keep the trace menu on the same canonical network identities as the rest of
// the dashboard. The live operation resolves them again before executing.
func traceEndpoints(inv model.Inventory) []model.Endpoint {
	var out []model.Endpoint
	for _, a := range ovn.Attachments(inv) {
		out = append(out, a.Endpoint)
	}
	return out
}
