// SPDX-License-Identifier: Apache-2.0
// Package trace describes requested simulations separately from observed flows.
package trace

import (
	"time"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/qos"
	core "k8s.io/api/core/v1"
)

type ServiceRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

type Request struct {
	Source      model.Endpoint `json:"source"`
	Destination model.Endpoint `json:"destination"`
	Service     *ServiceRef    `json:"service,omitempty"`
	Protocol    string         `json:"protocol"`
	Port        int            `json:"port"`
	SourcePort  int            `json:"sourcePort"`
	State       string         `json:"state"`
	OVS         bool           `json:"ovs"`
	AllBackends bool           `json:"allBackends"`
}

type Backend struct {
	Endpoint model.Endpoint `json:"endpoint"`
	Port     int            `json:"port"`
	Ready    bool           `json:"ready"`
}

type Service struct {
	Ref      ServiceRef         `json:"ref"`
	Type     core.ServiceType   `json:"type"`
	IPs      []string           `json:"ips"`
	Ports    []core.ServicePort `json:"ports"`
	Backends []Backend          `json:"backends"`
	Warnings []string           `json:"warnings"`
}

type Stage struct {
	Pipeline string   `json:"pipeline"`
	Datapath string   `json:"datapath"`
	InPort   string   `json:"inPort"`
	OutPort  string   `json:"outPort,omitempty"`
	Name     string   `json:"name"`
	Flow     string   `json:"flow"`
	Match    string   `json:"match"`
	Actions  []string `json:"actions"`
}

type Segment struct {
	Node     string              `json:"node"`
	Status   string              `json:"status"`
	Summary  string              `json:"summary"`
	Stages   []Stage             `json:"stages"`
	Outputs  []string            `json:"outputs"`
	Causes   []model.PolicyCause `json:"causes"`
	Raw      string              `json:"raw"`
	OVS      string              `json:"ovs,omitempty"`
	Warnings []string            `json:"warnings"`
}

type Result struct {
	Destination model.Endpoint `json:"destination"`
	Status      string         `json:"status"`
	Segments    []Segment      `json:"segments"`
	Warnings    []string       `json:"warnings"`
}

type Report struct {
	QoS      []qos.Policy `json:"qos,omitempty"`
	At       time.Time    `json:"at"`
	Mode     string       `json:"mode"`
	Request  Request      `json:"request"`
	Service  *Service     `json:"service,omitempty"`
	Results  []Result     `json:"results"`
	Warnings []string     `json:"warnings"`
}

type Check struct {
	Source  model.Endpoint `json:"source"`
	Service *ServiceRef    `json:"service,omitempty"`
	Name    string         `json:"name,omitempty"`
}

type CheckResult struct {
	At      time.Time `json:"at"`
	Success bool      `json:"success"`
	Summary string    `json:"summary"`
	Output  string    `json:"output,omitempty"`
}
