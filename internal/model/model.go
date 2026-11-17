// SPDX-License-Identifier: Apache-2.0
package model

import (
	"time"

	core "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type Row map[string]any

type Inventory struct {
	Pods       []core.Pod                             `json:"pods"`
	Namespaces []core.Namespace                       `json:"namespaces"`
	Policies   []netv1.NetworkPolicy                  `json:"policies"`
	Services   []core.Service                         `json:"services"`
	Resources  map[string][]unstructured.Unstructured `json:"resources"`
	Errors     []string                               `json:"errors,omitempty"`
}

type NodeSnapshot struct {
	Name           string            `json:"name"`
	CapturedAt     time.Time         `json:"capturedAt"`
	Datapath       string            `json:"datapath"`
	Flows          string            `json:"flows"`
	Ports          string            `json:"ports"`
	Interfaces     []Row             `json:"interfaces"`
	Bindings       []Row             `json:"bindings"`
	Datapaths      []Row             `json:"datapaths"`
	LogicalFlows   []Row             `json:"logicalFlows"`
	ACLs           []Row             `json:"acls"`
	Detraces       map[string]string `json:"detraces"`
	Errors         []string          `json:"errors,omitempty"`
	FlowCapturedAt time.Time         `json:"flowCapturedAt,omitempty"`
	MetadataAt     time.Time         `json:"metadataAt,omitempty"`
	Collection     CollectionStats   `json:"collection"`
}

type CollectionStats struct {
	DurationMS     int64 `json:"durationMs"`
	Commands       int   `json:"commands"`
	Bytes          int   `json:"bytes"`
	MetadataCached bool  `json:"metadataCached"`
	DetraceHits    int   `json:"detraceHits"`
	FlowComplete   bool  `json:"flowComplete"`
}

type Snapshot struct {
	Version    int            `json:"version"`
	CapturedAt time.Time      `json:"capturedAt"`
	Inventory  Inventory      `json:"inventory"`
	Nodes      []NodeSnapshot `json:"nodes"`
}

type Endpoint struct {
	Node       string            `json:"node,omitempty"`
	Namespace  string            `json:"namespace,omitempty"`
	Pod        string            `json:"pod,omitempty"`
	UID        string            `json:"uid,omitempty"`
	Network    string            `json:"network,omitempty"`
	NAD        string            `json:"nad,omitempty"`
	Role       string            `json:"role,omitempty"`
	PolicyKind string            `json:"policyKind,omitempty"`
	IP         string            `json:"ip,omitempty"`
	Port       int               `json:"port,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

type PolicyCause struct {
	Type      string `json:"type"`
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Direction string `json:"direction,omitempty"`
	Rule      string `json:"rule,omitempty"`
	ACL       string `json:"acl"`
	Action    string `json:"action"`
	Match     string `json:"match,omitempty"`
}

type Step struct {
	ID        string            `json:"id"`
	Recirc    string            `json:"recirc"`
	InPort    string            `json:"inPort"`
	Match     map[string]string `json:"match"`
	Actions   string            `json:"actions"`
	Packets   uint64            `json:"packets"`
	Offloaded bool              `json:"offloaded"`
	OpenFlow  string            `json:"openFlow,omitempty"`
}

type Finding struct {
	ID            string        `json:"id"`
	Node          string        `json:"node"`
	Title         string        `json:"title"`
	Source        Endpoint      `json:"source"`
	Destination   Endpoint      `json:"destination"`
	Protocol      string        `json:"protocol"`
	Verdict       string        `json:"verdict"`
	Confidence    string        `json:"confidence"`
	Packets       uint64        `json:"packets"`
	Delta         *uint64       `json:"delta,omitempty"`
	CounterID     string        `json:"counterID"`
	SharedCounter bool          `json:"sharedCounter"`
	ObservedAt    time.Time     `json:"observedAt"`
	Causes        []PolicyCause `json:"causes"`
	Steps         []Step        `json:"steps"`
	Warnings      []string      `json:"warnings"`
	CanRecommend  bool          `json:"canRecommend"`
}

type Network struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Namespace  string            `json:"namespace,omitempty"`
	Kind       string            `json:"kind"`
	Role       string            `json:"role"`
	Topology   string            `json:"topology"`
	Subnets    []string          `json:"subnets"`
	Labels     map[string]string `json:"labels,omitempty"`
	Pods       int               `json:"pods"`
	Conditions any               `json:"conditions,omitempty"`
}

type View struct {
	Mode          string                      `json:"mode"`
	CollectedAt   time.Time                   `json:"collectedAt"`
	Collecting    bool                        `json:"collecting"`
	WritesEnabled bool                        `json:"writesEnabled"`
	Findings      []Finding                   `json:"findings"`
	Networks      []Network                   `json:"networks"`
	Nodes         []NodeStatus                `json:"nodes"`
	Pods          []Endpoint                  `json:"pods"`
	Connections   []unstructured.Unstructured `json:"connections"`
	Errors        []string                    `json:"errors"`
	Traffic       []TrafficObservation        `json:"-"`
}

type NodeStatus struct {
	Name       string          `json:"name"`
	Flows      int             `json:"flows"`
	Offloaded  int             `json:"offloaded"`
	CapturedAt time.Time       `json:"capturedAt"`
	Errors     []string        `json:"errors"`
	Collection CollectionStats `json:"collection"`
}

// A counter belongs to one observation point. Source and destination counters
// remain separate even when they describe the same traffic.
type TrafficObservation struct {
	CounterID    string    `json:"counterID"`
	Node         string    `json:"node"`
	Network      string    `json:"network"`
	Source       Endpoint  `json:"source"`
	Destination  Endpoint  `json:"destination"`
	Protocol     string    `json:"protocol"`
	Verdict      string    `json:"verdict"`
	Location     string    `json:"location"`
	CounterScope string    `json:"counterScope"`
	Packets      uint64    `json:"packets"`
	Bytes        uint64    `json:"bytes"`
	PacketDelta  *uint64   `json:"packetDelta,omitempty"`
	ByteDelta    *uint64   `json:"byteDelta,omitempty"`
	Start        time.Time `json:"start"`
	End          time.Time `json:"end"`
	Shared       bool      `json:"shared"`
	Partial      bool      `json:"partial"`
	Offloaded    bool      `json:"offloaded"`
	Warnings     []string  `json:"warnings"`
	FindingIDs   []string  `json:"findingIDs,omitempty"`
}
