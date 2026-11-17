// SPDX-License-Identifier: Apache-2.0
package routing

import (
	"github.com/trozet/ovn-light/internal/model"
	"time"
)

type Options struct {
	Network, Node, Search string
	Limit, Offset         int
	Stale                 bool
}
type Issue struct {
	Kind     string   `json:"kind"`
	Name     string   `json:"name"`
	Node     string   `json:"node,omitempty"`
	Networks []string `json:"networks"`
	Message  string   `json:"message"`
}
type Prefix struct {
	CIDR          string   `json:"cidr"`
	Kind          string   `json:"kind"`
	Networks      []string `json:"networks"`
	Advertisement string   `json:"advertisement,omitempty"`
	State         string   `json:"state"`
}
type Peer struct {
	ID             string    `json:"id"`
	Node           string    `json:"node"`
	VRF            string    `json:"vrf"`
	Address        string    `json:"address"`
	LocalASN       string    `json:"localASN"`
	RemoteASN      string    `json:"remoteASN"`
	Source         string    `json:"source,omitempty"`
	Interface      string    `json:"interface,omitempty"`
	BGP            string    `json:"bgp"`
	BFD            string    `json:"bfd"`
	StateSource    string    `json:"stateSource"`
	Configurations []string  `json:"configurations"`
	Networks       []string  `json:"networks"`
	Uplinks        []string  `json:"uplinks"`
	Mapping        string    `json:"mapping"`
	Prefixes       []Prefix  `json:"prefixes"`
	PrefixCount    int       `json:"prefixCount"`
	CapturedAt     time.Time `json:"capturedAt"`
	Warnings       []string  `json:"warnings"`
}
type Interface struct {
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	State      string         `json:"state"`
	MTU        any            `json:"mtu,omitempty"`
	Statistics map[string]any `json:"statistics,omitempty"`
}
type Uplink struct {
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	Node          string      `json:"node"`
	Networks      []string    `json:"networks"`
	VRF           string      `json:"vrf"`
	HostInterface string      `json:"hostInterface"`
	Bridge        string      `json:"bridge"`
	Addresses     []string    `json:"addresses"`
	Gateways      []string    `json:"gateways"`
	Conditions    []any       `json:"conditions"`
	HostFunction  any         `json:"hostFunction,omitempty"`
	Interfaces    []Interface `json:"interfaces"`
	Ready         string      `json:"ready"`
	Default       bool        `json:"default"`
	Warnings      []string    `json:"warnings"`
}
type Advertisement struct {
	Name           string   `json:"name"`
	Networks       []string `json:"networks"`
	Nodes          []string `json:"nodes"`
	Types          []string `json:"types"`
	VRF            string   `json:"vrf"`
	Conditions     []any    `json:"conditions"`
	Status         string   `json:"status"`
	Configurations []string `json:"configurations"`
}
type Assignment struct {
	IP           string     `json:"ip"`
	Node         string     `json:"node"`
	Ready        string     `json:"ready"`
	PreviousNode string     `json:"previousNode,omitempty"`
	MovedAt      *time.Time `json:"movedAt,omitempty"`
}
type EgressPath struct {
	Source     model.Endpoint             `json:"source"`
	Assignment Assignment                 `json:"assignment"`
	Programmed bool                       `json:"programmed"`
	Evidence   []string                   `json:"evidence"`
	Traffic    []model.TrafficObservation `json:"traffic"`
	// Destination-side observations identify arrival on an assigned node. A
	// separate NAT association is required before calling the translated IP observed.
	ObservedAtEgress bool `json:"observedAtEgress"`
}
type Egress struct {
	UID         string           `json:"uid,omitempty"`
	Name        string           `json:"name"`
	Networks    []string         `json:"networks"`
	Requested   []string         `json:"requested"`
	Assignments []Assignment     `json:"assignments"`
	Pods        []model.Endpoint `json:"pods"`
	PodCount    int              `json:"podCount"`
	Paths       []EgressPath     `json:"paths"`
	PathCount   int              `json:"pathCount"`
	Warnings    []string         `json:"warnings"`
}
type Report struct {
	CollectedAt    time.Time         `json:"collectedAt"`
	Stale          bool              `json:"stale"`
	Capabilities   map[string]string `json:"capabilities"`
	Peers          []Peer            `json:"peers"`
	Uplinks        []Uplink          `json:"uplinks"`
	Advertisements []Advertisement   `json:"advertisements"`
	Egress         []Egress          `json:"egress"`
	Issues         []Issue           `json:"issues"`
	Totals         map[string]int    `json:"totals"`
	Offset         int               `json:"offset"`
	Limit          int               `json:"limit"`
	Warnings       []string          `json:"warnings"`
}
