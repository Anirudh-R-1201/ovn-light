// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestTraceCommandBudgetAndDeadline(t *testing.T) {
	calls := 0
	c := &Collector{exec: func(ctx context.Context, _ Target, _ []string) (string, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 15*time.Second {
			t.Fatal("missing bounded exec deadline")
		}
		return strings.Repeat("x", 8), nil
	}}
	session := &traceSession{collector: c, remaining: 8}
	if _, err := session.exec(context.Background(), Target{}, []string{"ovn-trace"}, 16); err != nil {
		t.Fatal(err)
	}
	if _, err := session.exec(context.Background(), Target{}, []string{"ovn-trace"}, 16); err == nil || calls != 1 {
		t.Fatal("ran after exhausting request budget", calls, err)
	}
	session.remaining = 16
	if _, err := session.exec(context.Background(), Target{}, []string{"ovn-trace"}, 4); err == nil {
		t.Fatal("accepted output beyond command cap")
	}
}
