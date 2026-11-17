// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
)

type offloadCache struct {
	Target   Target
	Evidence model.OffloadEvidence
}

func shortError(err error) string {
	s := err.Error()
	if len(s) > 2048 {
		s = s[:2048] + "…"
	}
	return s
}

// Diagnostics share the node's command and byte budgets. Cache failures too:
// an unsupported command must not be retried every time someone opens the UI.
func (c *Collector) captureOffload(ctx context.Context, name string, target Target, execute func(Target, ...string) (string, error)) model.OffloadEvidence {
	c.cacheMu.Lock()
	cached := c.offloadCache[name]
	c.cacheMu.Unlock()
	if cached.Target == target && time.Since(cached.Evidence.CapturedAt) < time.Minute {
		return cached.Evidence
	}
	e := model.OffloadEvidence{CapturedAt: time.Now().UTC(), Config: map[string]string{}}
	run := func(limit int, args ...string) (string, bool) {
		out, err := execute(target, args...)
		if err == nil && len(out) > limit {
			err = fmt.Errorf("output exceeds offload evidence limit (%d bytes)", limit)
		}
		if err != nil {
			e.Errors = append(e.Errors, args[0]+" "+args[len(args)-1]+": "+shortError(err))
			return "", false
		}
		return out, true
	}
	raw, ok := run(64<<10, "ovs-vsctl", "--timeout=10", "--format=json", "--columns=other_config,ovs_version", "list", "Open_vSwitch")
	if ok {
		rows, err := ovn.DecodeTable(raw)
		if err != nil || len(rows) != 1 {
			e.Errors = append(e.Errors, "OVS offload configuration could not be decoded.")
		} else {
			cfg := ovn.Map(rows[0]["other_config"])
			e.ConfigKnown = true
			e.Enabled = ovn.Str(cfg["hw-offload"]) == "true"
			e.Version = ovn.Str(rows[0]["ovs_version"])
			for _, key := range []string{"hw-offload", "doca-init", "dpdk-init", "doca-ct", "hw-offload-ct-size", "hw-offload-ct-ipv6-enabled", "hw-offload-ct-unidir-udp-enabled", "n-offload-threads", "tc-policy"} {
				if v, exists := cfg[key]; exists {
					e.Config[key] = ovn.Str(v)
				}
			}
			if e.Config["doca-init"] == "true" {
				e.Provider = "doca"
			} else if e.Config["dpdk-init"] == "true" {
				e.Provider = "dpdk"
			} else {
				e.Provider = "tc"
			}
		}
	}
	if e.Enabled && ctx.Err() == nil {
		commands, available := run(128<<10, "ovs-appctl", "-t", "ovs-vswitchd", "list-commands")
		supported := map[string]bool{}
		if available {
			for _, line := range strings.Split(commands, "\n") {
				if f := strings.Fields(line); len(f) > 0 {
					supported[f[0]] = true
				}
			}
		}
		if supported["doca/dump-offloads"] || supported["dpif-doca/pmd-stats-show"] {
			e.Provider = "doca"
		}
		for _, cmd := range []string{"dpctl/offload-stats-show", "dpctl/dump-conntrack", "dpif-doca/pmd-stats-show", "dpif-netdev/pmd-stats-show"} {
			if supported[cmd] {
				e.Commands = append(e.Commands, cmd)
			}
		}
		if supported["dpctl/offload-stats-show"] {
			e.Stats, _ = run(128<<10, "ovs-appctl", "-t", "ovs-vswitchd", "dpctl/offload-stats-show")
		}
		pmd := "dpif-netdev/pmd-stats-show"
		if supported["dpif-doca/pmd-stats-show"] {
			pmd = "dpif-doca/pmd-stats-show"
		}
		if supported[pmd] && e.Provider != "tc" {
			e.PMDStats, _ = run(128<<10, "ovs-appctl", "-t", "ovs-vswitchd", pmd)
		}
		// These direction flags belong to the DOCA conntrack implementation.
		// An upstream dump without them cannot establish CT offload status.
		e.CTSupported = e.Provider == "doca" && supported["dpctl/dump-conntrack"]
		if e.CTSupported {
			e.Conntrack, e.CTComplete = run(4<<20, "ovs-appctl", "-t", "ovs-vswitchd", "dpctl/dump-conntrack", "-m")
		}
	}
	c.cacheMu.Lock()
	if c.offloadCache == nil {
		c.offloadCache = map[string]offloadCache{}
	}
	// Retain at most 16 MiB of diagnostic output across nodes.
	delete(c.offloadCache, name)
	size := len(e.Conntrack) + len(e.Stats) + len(e.PMDStats)
	for {
		total, oldest := size, ""
		for k, v := range c.offloadCache {
			total += len(v.Evidence.Conntrack) + len(v.Evidence.Stats) + len(v.Evidence.PMDStats)
			if oldest == "" || v.Evidence.CapturedAt.Before(c.offloadCache[oldest].Evidence.CapturedAt) {
				oldest = k
			}
		}
		if total <= 16<<20 && len(c.offloadCache) < 1024 {
			break
		}
		delete(c.offloadCache, oldest)
	}
	c.offloadCache[name] = offloadCache{Target: target, Evidence: e}
	c.cacheMu.Unlock()
	return e
}
