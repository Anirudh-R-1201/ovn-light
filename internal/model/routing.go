// SPDX-License-Identifier: Apache-2.0
package model

import "time"

// Runtime evidence is collected independently of packet counters. Empty or
// incomplete tables must not be interpreted as a withdrawal or a broken path.
type RoutingEvidence struct {
	BridgeMappings string       `json:"bridgeMappings,omitempty"`
	CapturedAt     time.Time    `json:"capturedAt"`
	Links          []Row        `json:"links,omitempty"`
	Routes         []Row        `json:"routes,omitempty"`
	Bridges        []Row        `json:"bridges,omitempty"`
	OVSPorts       []Row        `json:"ovsPorts,omitempty"`
	Routers        []Row        `json:"routers,omitempty"`
	Policies       []Row        `json:"policies,omitempty"`
	NAT            []Row        `json:"nat,omitempty"`
	OVNComplete    bool         `json:"ovnComplete"`
	HostComplete   bool         `json:"hostComplete"`
	FRRTarget      string       `json:"frrTarget,omitempty"`
	Peers          []BGPRuntime `json:"peers"`
	Errors         []string     `json:"errors"`
}

type BGPRuntime struct {
	VRF          string   `json:"vrf"`
	Peer         string   `json:"peer"`
	Family       string   `json:"family"`
	State        string   `json:"state"`
	LocalAddress string   `json:"localAddress,omitempty"`
	Interface    string   `json:"interface,omitempty"`
	Advertised   []string `json:"advertised"`
	Complete     bool     `json:"complete"`
	Errors       []string `json:"errors,omitempty"`
}

type AdminPolicyEvidence struct {
	Kind        string         `json:"kind"`
	Name        string         `json:"name"`
	Priority    *int64         `json:"priority,omitempty"`
	Direction   string         `json:"direction"`
	RuleIndex   int            `json:"ruleIndex"`
	RuleName    string         `json:"ruleName,omitempty"`
	Rule        map[string]any `json:"rule,omitempty"`
	Subject     map[string]any `json:"subject,omitempty"`
	Explanation string         `json:"explanation"`
	Warnings    []string       `json:"warnings"`
}
