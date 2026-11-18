// SPDX-License-Identifier: Apache-2.0
package model

import "time"

// These are configuration tables. Their presence does not measure policer loss
// or prove that a packet received a DSCP marking in hardware.
type QoSEvidence struct {
	At       time.Time `json:"at"`
	Rules    []Row     `json:"rules"`
	Switches []Row     `json:"switches"`
	Queues   []Row     `json:"queues"`
	Ports    []Row     `json:"ports"`
	Errors   []string  `json:"errors,omitempty"`
}
