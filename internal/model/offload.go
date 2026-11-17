// SPDX-License-Identifier: Apache-2.0
package model

import "time"

// OffloadEvidence is collected separately from the flow dump. Its timestamps
// allow cached or failed diagnostics to remain visible without implying freshness.
type OffloadEvidence struct {
	CapturedAt  time.Time         `json:"capturedAt"`
	ConfigKnown bool              `json:"configKnown"`
	Enabled     bool              `json:"enabled"`
	Provider    string            `json:"provider"`
	Version     string            `json:"version"`
	Config      map[string]string `json:"config,omitempty"`
	Commands    []string          `json:"commands,omitempty"`
	Stats       string            `json:"stats,omitempty"`
	PMDStats    string            `json:"pmdStats,omitempty"`
	Conntrack   string            `json:"conntrack,omitempty"`
	CTComplete  bool              `json:"ctComplete"`
	CTSupported bool              `json:"ctSupported"`
	Errors      []string          `json:"errors,omitempty"`
}

type OffloadNode struct {
	Name          string            `json:"name"`
	State         string            `json:"state"`
	Provider      string            `json:"provider"`
	Version       string            `json:"version"`
	CapturedAt    time.Time         `json:"capturedAt"`
	DiagnosticsAt time.Time         `json:"diagnosticsAt"`
	Counts        map[string]int    `json:"counts"`
	Config        map[string]string `json:"config,omitempty"`
	Stats         string            `json:"stats,omitempty"`
	PMDStats      string            `json:"pmdStats,omitempty"`
	Errors        []string          `json:"errors,omitempty"`
}

type OffloadStage struct {
	ID             string  `json:"id"`
	Recirc         string  `json:"recirc"`
	InPort         string  `json:"inPort"`
	Status         string  `json:"status"`
	Provider       string  `json:"provider"`
	Reason         string  `json:"reason,omitempty"`
	Packets        uint64  `json:"packets"`
	Bytes          uint64  `json:"bytes"`
	PartialPackets uint64  `json:"partialPackets"`
	PartialBytes   uint64  `json:"partialBytes"`
	PacketDelta    *uint64 `json:"packetDelta,omitempty"`
	PartialDelta   *uint64 `json:"partialDelta,omitempty"`
	Raw            string  `json:"raw"`
}

type OffloadCT struct {
	Zone       string    `json:"zone"`
	Status     string    `json:"status"`
	Original   string    `json:"original"`
	Reply      string    `json:"reply"`
	Direction  string    `json:"direction,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Raw        string    `json:"raw,omitempty"`
	CapturedAt time.Time `json:"capturedAt,omitempty"`
}

type OffloadPath struct {
	ID            string         `json:"id"`
	Node          string         `json:"node"`
	Network       string         `json:"network,omitempty"`
	Source        Endpoint       `json:"source"`
	Destination   Endpoint       `json:"destination"`
	Protocol      string         `json:"protocol,omitempty"`
	Status        string         `json:"status"`
	Issue         bool           `json:"issue"`
	Summary       string         `json:"summary"`
	Guidance      string         `json:"guidance"`
	Complete      bool           `json:"complete"`
	ObservedAt    time.Time      `json:"observedAt"`
	Since         time.Time      `json:"since,omitempty"`
	ActivityDelta *uint64        `json:"activityDelta,omitempty"`
	PartialDelta  *uint64        `json:"partialDelta,omitempty"`
	Stages        []OffloadStage `json:"stages,omitempty"`
	Conntrack     []OffloadCT    `json:"conntrack,omitempty"`
	Warnings      []string       `json:"warnings,omitempty"`
	// The signature excludes counters but includes actions and matches. A UFID
	// can survive modification; history must not carry over to its new behavior.
	Signature      string    `json:"-"`
	SampleComplete bool      `json:"-"`
	Datapath       string    `json:"-"`
	Eligible       bool      `json:"-"`
	CTProblem      bool      `json:"-"`
	DiagnosticsAt  time.Time `json:"-"`
}

type OffloadReport struct {
	CollectedAt  time.Time     `json:"collectedAt"`
	GraceSeconds int           `json:"graceSeconds"`
	Nodes        []OffloadNode `json:"nodes"`
	Paths        []OffloadPath `json:"paths"`
	Total        int           `json:"total"`
	Omitted      int           `json:"omitted"`
	Issues       int           `json:"issues"`
}

type OffloadIssue struct {
	ID          string   `json:"id"`
	Node        string   `json:"node"`
	Network     string   `json:"network,omitempty"`
	Summary     string   `json:"summary"`
	Source      Endpoint `json:"source"`
	Destination Endpoint `json:"destination"`
}
