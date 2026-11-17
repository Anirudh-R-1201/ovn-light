// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/trozet/ovn-light/internal/datapath"
	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
)

type Collector struct {
	Client                *Client
	Namespace, NBDB, SBDB string
	MaxDetraces           int
}
type nodeTargets struct{ ovs, ovn Target }

func (c *Collector) Capture(ctx context.Context) (model.Snapshot, error) {
	s := model.Snapshot{Version: 1, CapturedAt: time.Now().UTC()}
	inv, err := c.Client.Inventory(ctx)
	if err != nil {
		return s, err
	}
	s.Inventory = inv
	targets := map[string]nodeTargets{}
	for _, p := range inv.Pods {
		if p.Namespace != c.Namespace || p.Spec.NodeName == "" || p.DeletionTimestamp != nil {
			continue
		}
		t := targets[p.Spec.NodeName]
		for _, container := range p.Spec.Containers {
			target := Target{p.Namespace, p.Name, container.Name}
			switch container.Name {
			case "ovs-daemons", "ovs-vswitchd":
				t.ovs = target
			case "ovnkube-controller":
				t.ovn = target
			}
		}
		targets[p.Spec.NodeName] = t
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 3)
	for name, t := range targets {
		if t.ovs.Pod == "" && t.ovn.Pod == "" {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			n := c.captureNode(ctx, name, t)
			mu.Lock()
			s.Nodes = append(s.Nodes, n)
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(s.Nodes, func(i, j int) bool { return s.Nodes[i].Name < s.Nodes[j].Name })
	if len(s.Nodes) == 0 {
		return s, fmt.Errorf("no OVS/OVN pods found in namespace %s (expected ovs-daemons and ovnkube-controller containers)", c.Namespace)
	}
	return s, nil
}

func (c *Collector) captureNode(ctx context.Context, name string, t nodeTargets) model.NodeSnapshot {
	ctx, cancelNode := context.WithTimeout(ctx, 90*time.Second)
	defer cancelNode()
	n := model.NodeSnapshot{Name: name, CapturedAt: time.Now().UTC(), Detraces: map[string]string{}}
	run := func(target Target, args ...string) string {
		if ctx.Err() != nil {
			return ""
		}
		if target.Pod == "" {
			return ""
		}
		call, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		out, err := c.Client.Exec(call, target, args, nil)
		if err != nil {
			n.Errors = append(n.Errors, err.Error())
		}
		return out
	}
	if t.ovs.Pod == "" {
		t.ovs = t.ovn
	}
	if t.ovn.Pod == "" {
		n.Errors = append(n.Errors, "No ovnkube-controller container; ACL attribution is unavailable.")
	}
	n.Flows = run(t.ovs, "ovs-appctl", "-t", "ovs-vswitchd", "dpctl/dump-flows", "-m")
	n.Ports = run(t.ovs, "ovs-appctl", "-t", "ovs-vswitchd", "dpctl/show")
	for _, line := range strings.Split(n.Ports, "\n") {
		if strings.HasPrefix(line, "system@") || strings.HasPrefix(line, "netdev@") {
			n.Datapath = strings.TrimSpace(line)
			break
		}
	}
	table := func(target Target, args ...string) []model.Row {
		raw := run(target, args...)
		if raw == "" {
			return nil
		}
		rows, err := ovn.DecodeTable(raw)
		if err != nil {
			n.Errors = append(n.Errors, fmt.Sprintf("decode %s: %v", args[len(args)-1], err))
		}
		return rows
	}
	n.Interfaces = table(t.ovs, "ovs-vsctl", "--timeout=10", "--format=json", "--columns=name,ofport,external_ids", "list", "Interface")
	n.Bindings = table(t.ovn, "ovn-sbctl", "--timeout=10", "--db="+c.SBDB, "--format=json", "--columns=_uuid,logical_port,datapath,tunnel_key,type,options", "list", "Port_Binding")
	n.Datapaths = table(t.ovn, "ovn-sbctl", "--timeout=10", "--db="+c.SBDB, "--format=json", "--columns=_uuid,tunnel_key,external_ids", "list", "Datapath_Binding")
	n.LogicalFlows = table(t.ovn, "ovn-sbctl", "--timeout=10", "--db="+c.SBDB, "--format=json", "--columns=_uuid,external_ids,match,actions", "list", "Logical_Flow")
	n.ACLs = table(t.ovn, "ovn-nbctl", "--timeout=10", "--db="+c.NBDB, "--format=json", "--columns=_uuid,external_ids,action,match,direction,priority", "list", "ACL")
	flows, _ := datapath.Parse(n.Flows)
	paths := datapath.Reconstruct(flows)
	wanted := map[string]bool{}
	for _, p := range paths {
		if p.Flows[len(p.Flows)-1].Packets == 0 {
			continue
		}
		for _, f := range p.Flows {
			wanted[f.ID] = true
		}
	}
	var ids []string
	for id := range wanted {
		if !strings.HasPrefix(id, "synthetic-") {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	limit := c.MaxDetraces
	if limit <= 0 {
		limit = 128
	}
	if len(ids) > limit {
		n.Errors = append(n.Errors, fmt.Sprintf("Attribution limited to %d of %d UFIDs this poll", limit, len(ids)))
		ids = ids[:limit]
	}
	for _, id := range ids {
		before := len(n.Errors)
		out := run(t.ovs, "ovs-appctl", "-t", "ovs-vswitchd", "ofproto/detrace", "ufid:"+id)
		if len(n.Errors) > before {
			err := n.Errors[len(n.Errors)-1]
			if strings.Contains(err, "not a valid command") || strings.Contains(err, "unknown command") {
				break
			}
		}
		if strings.Contains(out, "Cache was not found") || strings.Contains(out, "UFID was not found") {
			continue
		}
		n.Detraces[id] = out
		if ctx.Err() != nil {
			break
		}
	}
	if ctx.Err() != nil {
		n.Errors = append(n.Errors, "Node collection did not complete: "+ctx.Err().Error())
	}
	return n
}
