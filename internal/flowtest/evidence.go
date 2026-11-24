// SPDX-License-Identifier: Apache-2.0
package flowtest

import (
	"strings"
	"time"

	"github.com/trozet/ovn-light/internal/model"
	core "k8s.io/api/core/v1"
)

type Endpoint struct {
	Node string `json:"node"`
	Pod  string `json:"pod,omitempty"`
	UID  string `json:"uid,omitempty"`
	IP   string `json:"ip,omitempty"`
}
type NodeEvidence struct {
	Node    string              `json:"node"`
	State   string              `json:"state"`
	At      time.Time           `json:"at,omitempty"`
	Paths   []model.OffloadPath `json:"paths,omitempty"`
	Limited bool                `json:"limited,omitempty"`
}
type Traffic struct {
	Delivered     bool    `json:"delivered"`
	Bytes         int64   `json:"bytes,omitempty"`
	BPS           float64 `json:"bps,omitempty"`
	SourceIP      string  `json:"sourceIP,omitempty"`
	DestinationIP string  `json:"destinationIP,omitempty"`
	Error         string  `json:"error,omitempty"`
}
type Run struct {
	ID          string         `json:"id"`
	JobUID      string         `json:"jobUID"`
	Phase       string         `json:"phase"`
	Network     string         `json:"network"`
	Source      Endpoint       `json:"source"`
	Destination Endpoint       `json:"destination"`
	Started     time.Time      `json:"started"`
	Finished    *time.Time     `json:"finished,omitempty"`
	Nodes       []NodeEvidence `json:"nodes"`
	Traffic     *Traffic       `json:"traffic,omitempty"`
	Drop        string         `json:"drop,omitempty"`
}

func (r *Run) matches(p model.OffloadPath) bool {
	t := p.Tuple
	if r.Source.UID == "" || r.Destination.UID == "" || t == nil || t.Protocol != "tcp" || p.Network != r.Network || p.ObservedAt.Before(r.Started) {
		return false
	}
	src, dst := r.Source, r.Destination
	if t.SourcePort == "5201" && t.DestinationPort == "35201" {
		src, dst = dst, src
	} else if t.SourcePort != "35201" || t.DestinationPort != "5201" {
		return false
	}
	return src.IP == t.SourceIP && dst.IP == t.DestinationIP && (p.Source.UID == "" || p.Source.UID == src.UID) && (p.Destination.UID == "" || p.Destination.UID == dst.UID)
}

// Preserve a problem seen during the run even if the flow expires before the user opens the result.
func severity(p model.OffloadPath) int {
	switch p.Status {
	case "failure":
		return 5
	case "partial":
		return 4
	case "software":
		return 3
	case "hardware":
		return 2
	default:
		return 1
	}
}

func (r *Run) observe(v model.View, report model.OffloadReport, pods []core.Pod) {
	// TFT connects to status.podIP. A dual-stack pod can have two attachments
	// in the inventory; only the one on the test socket can identify this run.
	primary := map[string]string{}
	for _, pod := range pods {
		if pod.Namespace != namespace || pod.Labels[runLabel] != r.ID {
			continue
		}
		for _, owner := range pod.OwnerReferences {
			if owner.Kind == "Job" && owner.Name == jobName && string(owner.UID) == r.JobUID {
				primary[string(pod.UID)] = pod.Status.PodIP
			}
		}
	}
	for _, pod := range v.Pods {
		if pod.Namespace != namespace || pod.Network != r.Network || pod.Role != "primary" || pod.IP == "" || pod.IP != primary[pod.UID] || pod.Labels[runLabel] != r.ID {
			continue
		}
		var e *Endpoint
		switch pod.Labels["ovn-light.io/role"] {
		case "client":
			e = &r.Source
		case "server":
			e = &r.Destination
		default:
			continue
		}
		if pod.Node == e.Node && (e.UID == "" || e.UID == pod.UID) {
			e.Pod, e.UID, e.IP = pod.Pod, pod.UID, pod.IP
		}
	}
	for i := range r.Nodes {
		n := &r.Nodes[i]
		before := n.At
		for _, node := range report.Nodes {
			if node.Name == n.Node && node.CapturedAt.After(n.At) && !node.CapturedAt.Before(r.Started) {
				n.At = node.CapturedAt
				if node.DiagnosticsAt.Before(r.Started) {
					continue
				}
				n.State = node.State
			}
		}
		// Only comparable intervals wholly within this run can demonstrate activity.
		if before.IsZero() || !n.At.After(before) {
			continue
		}
		for _, p := range report.Paths {
			if p.Node != n.Node || !p.ObservedAt.Equal(n.At) || !r.matches(p) || (p.ActivityDelta == nil || *p.ActivityDelta == 0) && (p.PartialDelta == nil || *p.PartialDelta == 0) {
				continue
			}
			p.Stages = append([]model.OffloadStage(nil), p.Stages...)
			for i := range p.Stages {
				p.Stages[i].Raw = ""
			}
			p.Conntrack = append([]model.OffloadCT(nil), p.Conntrack...)
			for i := range p.Conntrack {
				ct := &p.Conntrack[i]
				ct.Raw = ""
				if ct.CapturedAt.Before(r.Started) {
					*ct = model.OffloadCT{Zone: ct.Zone, Status: "unknown", Reason: "Conntrack sample predates this test."}
					if p.Status == "hardware" || (p.CTProblem && p.Status == "software") {
						p.Status = "unknown"
						p.Summary = "Current conntrack evidence unavailable."
						p.Issue = false
					}
				}
			}
			// Limit stored evidence independently of the cluster's number of flows.
			if len(p.Stages) > 32 {
				p.Stages = p.Stages[:32]
				n.Limited = true
			}
			if len(p.Conntrack) > 8 {
				p.Conntrack = p.Conntrack[:8]
				n.Limited = true
			}
			slot := -1
			for j, old := range n.Paths {
				if old.ID == p.ID {
					slot = j
					break
				}
			}
			if slot >= 0 {
				old := n.Paths[slot]
				if severity(p) > severity(old) || severity(p) == severity(old) && (p.Issue || !old.Issue) && (old.PartialDelta == nil || p.PartialDelta != nil && *p.PartialDelta >= *old.PartialDelta) {
					n.Paths[slot] = p
				}
			} else if len(n.Paths) < 12 {
				n.Paths = append(n.Paths, p)
			} else {
				n.Limited = true
			}
		}
	}
	for _, f := range v.Findings {
		if r.Source.UID != "" && r.Destination.UID != "" && f.Source.UID == r.Source.UID && f.Destination.UID == r.Destination.UID && f.Source.Network == r.Network && f.Destination.Port == 5201 && strings.EqualFold(f.Protocol, "TCP") && f.Delta != nil && *f.Delta > 0 && !f.SharedCounter && f.ObservedAt.After(r.Started) {
			for _, c := range f.Causes {
				if c.ACL != "" {
					r.Drop = strings.TrimSpace(strings.Join([]string{c.Type, c.Namespace, c.Name, c.Direction, c.Action, c.ACL}, " "))
					break
				}
			}
		}
	}
}
