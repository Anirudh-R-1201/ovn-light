// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestOffloadCollectionCapabilitiesCacheAndFailures(t *testing.T) {
	var c Collector
	calls := 0
	failCT := false
	enabled := true
	execute := func(_ Target, args ...string) (string, error) {
		calls++
		cmd := strings.Join(args, " ")
		switch {
		case args[0] == "ovs-vsctl":
			return fmt.Sprintf(`{"headings":["other_config","ovs_version"],"data":[[["map",[["hw-offload","%t"],["doca-init","true"]]],"test"]]}`, enabled), nil
		case strings.Contains(cmd, "list-commands"):
			return "doca/dump-offloads\ndpctl/offload-stats-show\ndpif-doca/pmd-stats-show\ndpctl/dump-conntrack", nil
		case strings.Contains(cmd, "dump-conntrack"):
			if failCT {
				return "tcp,orig=(truncated)", fmt.Errorf("output truncated")
			}
			return "", nil
		default:
			return "counter: 1", nil
		}
	}
	target := Target{Pod: "ovs"}
	e := c.captureOffload(context.Background(), "node", target, execute)
	if !e.Enabled || !e.CTComplete || !e.CTSupported || e.Provider != "doca" || calls != 5 {
		t.Fatal(e, calls)
	}
	c.captureOffload(context.Background(), "node", target, execute)
	if calls != 5 {
		t.Fatal("cache missed", calls)
	}
	failCT = true
	target.Pod = "replacement"
	e = c.captureOffload(context.Background(), "node", target, execute)
	if e.CTComplete || e.Conntrack != "" || len(e.Errors) != 1 {
		t.Fatal("failed CT dump retained", e)
	}
	enabled = false
	cache := c.offloadCache["node"]
	cache.Evidence.CapturedAt = time.Now().Add(-2 * time.Minute)
	c.offloadCache["node"] = cache
	before := calls
	e = c.captureOffload(context.Background(), "node", target, execute)
	if e.Enabled || calls-before != 1 {
		t.Fatal("disabled node queried CT/PMD", e, calls-before)
	}
}
