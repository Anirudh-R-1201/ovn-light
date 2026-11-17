// SPDX-License-Identifier: Apache-2.0
package trace

import (
	"regexp"
	"strings"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
)

var pipelineRE = regexp.MustCompile(`^(ingress|egress)\(dp="([^"]+)", inport="([^"]*)"(?:, outport="([^"]*)")?\)`)
var stageRE = regexp.MustCompile(`^\s*\d+\. ([a-z0-9_]+) \([^)]*\): (.*), priority \d+, uuid ([0-9a-f-]+)$`)
var outputRE = regexp.MustCompile(`/\* output to "([^"]+)"(?:, type "([^"]*)")? \*/`)
var lookupRE = regexp.MustCompile(`(?m)^ct_(?:next|lb(?:_mark)?|dnat|snat)(?:\(|$)`)

// Parse retains the raw trace because OVN's human-readable format can change.
// An ACL action may end by clearing registers without printing "drop".
func Parse(raw, target string, n model.NodeSnapshot, inv model.Inventory) Segment {
	s := Segment{Node: n.Name, Status: "unknown", Summary: "The simulated path did not establish a final outcome.", Raw: raw}
	var current Stage
	var ids []string
	for _, line := range strings.Split(raw, "\n") {
		if m := pipelineRE.FindStringSubmatch(line); m != nil {
			current = Stage{Pipeline: m[1], Datapath: m[2], InPort: m[3], OutPort: m[4]}
			continue
		}
		if m := stageRE.FindStringSubmatch(line); m != nil {
			st := current
			st.Name = m[1]
			st.Match = m[2]
			st.Flow = m[3]
			s.Stages = append(s.Stages, st)
			ids = append(ids, m[3])
			continue
		}
		if m := outputRE.FindStringSubmatch(line); m != nil {
			s.Outputs = append(s.Outputs, m[1])
		}
		if len(s.Stages) > 0 && strings.HasPrefix(line, "    ") {
			s.Stages[len(s.Stages)-1].Actions = append(s.Stages[len(s.Stages)-1].Actions, strings.TrimSpace(line))
		}
	}
	lower := strings.ToLower(raw)
	if len(s.Stages) == 0 || strings.Contains(lower, "***") || strings.Contains(lower, "error:") || strings.Contains(lower, "ovn-trace:") || len(lookupRE.FindAllString(raw, -1)) > MaxLookups {
		s.Warnings = append(s.Warnings, "Trace output was incomplete, contained a diagnostic, or exceeded the explicit conntrack assumptions.")
		return s
	}
	s.Causes = ovn.TraceCauses(n, inv, ids)
	for _, out := range s.Outputs {
		if target != "" && out == target {
			s.Status = "predicted-delivery"
			s.Summary = "OVN predicts output to the destination logical port. Physical delivery and the application listener are untested."
			return s
		}
	}
	last := s.Stages[len(s.Stages)-1]
	actions := strings.Join(last.Actions, " ")
	terminal := len(last.Actions) > 0 && !strings.Contains(actions, "next;") && !strings.Contains(actions, "next(") && !strings.Contains(actions, "output;") && !strings.Contains(actions, "ct_") && !strings.Contains(actions, "clone")
	if len(s.Causes) > 0 && strings.Contains(last.Name, "acl") && terminal || strings.Contains(actions, "drop;") || strings.Contains(actions, "/* drop */") {
		s.Status = "predicted-drop"
		s.Summary = "OVN predicts a drop for the selected packet and connection state."
		return s
	}
	// Patch outputs are intermediate. Remote or localnet outputs are the last
	// logical evidence available in this zone, not proof of delivery.
	for _, m := range outputRE.FindAllStringSubmatch(raw, -1) {
		if m[2] == "remote" || m[2] == "localnet" || m[2] == "l3gateway" {
			s.Status = "handoff"
			s.Summary = "OVN predicts a handoff beyond this zone; the receiving path is not established by this segment."
		}
	}
	return s
}
