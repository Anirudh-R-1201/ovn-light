// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/trozet/ovn-light/internal/policy"
	"github.com/trozet/ovn-light/internal/qos"
)

func (a *App) QoS(o qos.Options) qos.Report {
	a.mu.RLock()
	r := a.qos
	r.Stale = a.Mode == "live" && time.Since(r.At) > 2*time.Minute
	a.mu.RUnlock()
	return qos.Filter(r, o)
}
func (a *App) PrepareQoS(ctx context.Context, r policy.QoSRequest) (policy.Plan, error) {
	a.operation.Lock()
	defer a.operation.Unlock()
	inv := a.Snapshot().Inventory
	if a.Mode == "live" {
		var err error
		inv, err = a.Client.Inventory(ctx)
		if err != nil {
			return policy.Plan{}, err
		}
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return policy.Plan{}, err
	}
	p, err := policy.BuildQoS(inv, r, hex.EncodeToString(b))
	if err != nil {
		return p, err
	}
	if a.Mode == "live" && a.Writes {
		if _, err = a.writeObject(ctx, &p, p.Objects[0], true); err != nil {
			return p, fmt.Errorf("admission dry-run failed: %w", err)
		}
	} else {
		p.Warnings = append(p.Warnings, "Export only; no cluster admission check was performed.")
	}
	if err = a.persist(&p); err != nil {
		return p, err
	}
	a.plans[p.ID] = &p
	return clonePlan(&p), nil
}
