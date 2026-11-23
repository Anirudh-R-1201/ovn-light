// SPDX-License-Identifier: Apache-2.0
package ovn

import (
	"github.com/trozet/ovn-light/internal/model"
	"testing"
	"time"
)

func TestLocalAggregationSeparatesIndependentObservations(t *testing.T) {
	p, b := uint64(4), uint64(64)
	o := model.TrafficObservation{Node: "n", Network: "red", Location: "source", Start: time.Unix(1, 0), End: time.Unix(3, 0), PacketDelta: &p, ByteDelta: &b, CounterScope: "terminal"}
	other := o
	other.Network = "blue"
	shared := o
	shared.Shared = true
	rx := o
	rx.Location = "destination"
	baseline := o
	baseline.PacketDelta, baseline.ByteDelta = nil, nil
	result := groupTraffic([]model.TrafficObservation{o, o, shared, other, rx, baseline})
	if len(result) != 5 || *result[0].PacketDelta != 8 || *result[0].ByteDelta != 128 || p != 4 || b != 64 || !result[1].Shared || result[4].PacketDelta != nil {
		t.Fatalf("unexpected groups: %+v", result)
	}
}
