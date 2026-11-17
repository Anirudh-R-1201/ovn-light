// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"context"
	"crypto/sha256"
	"encoding/json"
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
	Concurrency           int
	CacheTTL              time.Duration
	captureMu             sync.Mutex
	cacheMu               sync.Mutex
	cache                 map[string]nodeCache
	exec                  func(context.Context, Target, []string) (string, error)
}
type nodeTargets struct{ ovs, ovn Target }

type traceCache struct{ Signature, Text string }
type nodeCache struct {
	Key                                     string
	At                                      time.Time
	Bindings, Datapaths, LogicalFlows, ACLs []model.Row
	Traces                                  map[string]traceCache
	Bytes                                   int
}

func inventoryKey(inv model.Inventory) string {
	var versions []string
	for _, p := range inv.Pods {
		versions = append(versions, "pod/"+string(p.UID)+"/"+p.ResourceVersion)
	}
	for _, p := range inv.Policies {
		versions = append(versions, "policy/"+string(p.UID)+"/"+p.ResourceVersion)
	}
	for _, svc := range inv.Services {
		versions = append(versions, "service/"+string(svc.UID)+"/"+svc.ResourceVersion)
	}
	for _, p := range inv.Namespaces {
		versions = append(versions, "ns/"+string(p.UID)+"/"+p.ResourceVersion)
	}
	for kind, resources := range inv.Resources {
		for _, r := range resources {
			versions = append(versions, kind+"/"+string(r.GetUID())+"/"+r.GetResourceVersion())
		}
	}
	sort.Strings(versions)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(versions, "\n"))))
}

func (c *Collector) cached(name, key string) nodeCache {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	ttl := c.CacheTTL
	if ttl <= 0 {
		ttl = time.Minute
	}
	if cached, ok := c.cache[name]; ok && cached.Key == key && time.Since(cached.At) < ttl {
		return cached
	}
	return nodeCache{Key: key, Traces: map[string]traceCache{}}
}
func (c *Collector) remember(name string, n nodeCache) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	if c.cache == nil {
		c.cache = map[string]nodeCache{}
	}
	delete(c.cache, name)
	if n.Bytes > 16<<20 {
		return
	}
	for {
		total := n.Bytes
		oldest := ""
		for k, v := range c.cache {
			total += v.Bytes
			if oldest == "" || v.At.Before(c.cache[oldest].At) {
				oldest = k
			}
		}
		if total <= 32<<20 {
			break
		}
		delete(c.cache, oldest)
	}
	c.cache[name] = n
}

func (c *Collector) Capture(ctx context.Context) (model.Snapshot, error) {
	c.captureMu.Lock()
	defer c.captureMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	s := model.Snapshot{Version: 1, CapturedAt: time.Now().UTC()}
	inv, err := c.Client.Inventory(ctx)
	if err != nil {
		return s, err
	}
	s.Inventory = inv
	key := inventoryKey(inv)
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
	concurrency := c.Concurrency
	if concurrency <= 0 {
		concurrency = 3
	}
	sem := make(chan struct{}, concurrency)
	snapshotBytes := 0
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
				mu.Lock()
				s.Nodes = append(s.Nodes, model.NodeSnapshot{Name: name, CapturedAt: time.Now().UTC(), Errors: []string{"Collection deadline reached before this node could be inspected."}})
				mu.Unlock()
				return
			}
			defer func() { <-sem }()
			n := c.captureNode(ctx, name, t, key)
			mu.Lock()
			// Raw snapshots are retained for evidence, so their total size must
			// stay bounded even when many nodes finish a large dump together.
			encoded, _ := json.Marshal(n)
			if snapshotBytes+len(encoded) > 64<<20 {
				n = model.NodeSnapshot{Name: name, CapturedAt: n.CapturedAt, Collection: n.Collection, Errors: []string{"Snapshot size limit reached; this node's evidence was omitted."}}
				n.Collection.FlowComplete = false
			} else {
				snapshotBytes += len(encoded)
			}
			s.Nodes = append(s.Nodes, n)
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(s.Nodes, func(i, j int) bool { return s.Nodes[i].Name < s.Nodes[j].Name })
	if len(s.Nodes) == 0 {
		return s, fmt.Errorf("no OVS/OVN pods found in namespace %s (expected ovs-daemons and ovnkube-controller containers)", c.Namespace)
	}
	s.CapturedAt = time.Now().UTC()
	return s, nil
}

func (c *Collector) captureNode(ctx context.Context, name string, t nodeTargets, key string) (n model.NodeSnapshot) {
	started := time.Now()
	defer func() { n.Collection.DurationMS = time.Since(started).Milliseconds() }()
	ctx, cancelNode := context.WithTimeout(ctx, 90*time.Second)
	defer cancelNode()
	n = model.NodeSnapshot{Name: name, CapturedAt: time.Now().UTC(), Detraces: map[string]string{}}
	run := func(target Target, args ...string) string {
		if ctx.Err() != nil {
			return ""
		}
		if target.Pod == "" {
			return ""
		}
		if n.Collection.Bytes >= 24<<20 {
			n.Errors = append(n.Errors, "Node collection byte budget reached.")
			return ""
		}
		call, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		var out string
		var err error
		n.Collection.Commands++
		if c.exec != nil {
			out, err = c.exec(call, target, args)
		} else {
			out, err = c.Client.execBounded(call, target, args, nil, min(8<<20, (24<<20)-n.Collection.Bytes))
		}
		n.Collection.Bytes += len(out)
		if err != nil {
			message := err.Error()
			if len(message) > 2048 {
				message = message[:2048] + "…"
			}
			n.Errors = append(n.Errors, message)
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
	n.FlowCapturedAt = time.Now().UTC()
	n.Collection.FlowComplete = len(n.Errors) == 0 && n.Flows != ""
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
	key += fmt.Sprintf("/%v/%v", t.ovs, t.ovn)
	cached := c.cached(name, key)
	if !cached.At.IsZero() {
		n.Collection.MetadataCached = true
		for _, trace := range cached.Traces {
			cached.Bytes -= len(trace.Text) + len(trace.Signature)
		}
	} else {
		beforeErrors, beforeBytes := len(n.Errors), n.Collection.Bytes
		cached.Bindings = table(t.ovn, "ovn-sbctl", "--timeout=10", "--db="+c.SBDB, "--format=json", "--columns=_uuid,logical_port,datapath,tunnel_key,type,options", "list", "Port_Binding")
		cached.Datapaths = table(t.ovn, "ovn-sbctl", "--timeout=10", "--db="+c.SBDB, "--format=json", "--columns=_uuid,tunnel_key,external_ids", "list", "Datapath_Binding")
		cached.LogicalFlows = table(t.ovn, "ovn-sbctl", "--timeout=10", "--db="+c.SBDB, "--format=json", "--columns=_uuid,external_ids,match,actions", "list", "Logical_Flow")
		cached.ACLs = table(t.ovn, "ovn-nbctl", "--timeout=10", "--db="+c.NBDB, "--format=json", "--columns=_uuid,external_ids,action,match,direction,priority", "list", "ACL")
		cached.Bytes = n.Collection.Bytes - beforeBytes
		if len(n.Errors) == beforeErrors && ctx.Err() == nil && t.ovn.Pod != "" {
			cached.At = time.Now().UTC()
		}
	}
	n.Bindings, n.Datapaths, n.LogicalFlows, n.ACLs, n.MetadataAt = cached.Bindings, cached.Datapaths, cached.LogicalFlows, cached.ACLs, cached.At
	flows, parseErrors := datapath.Parse(n.Flows)
	if len(parseErrors) > 0 {
		n.Collection.FlowComplete = false
		n.Errors = append(n.Errors, parseErrors...)
	}
	paths := datapath.ReconstructTraffic(flows, datapath.PortNames(n.Ports)...)
	wanted := map[string]int{}
	localPods := map[string]bool{}
	for _, iface := range n.Interfaces {
		if ovn.Str(ovn.Map(iface["external_ids"])["iface-id-ver"]) != "" {
			localPods[ovn.Str(iface["name"])] = true
		}
	}
	for _, line := range strings.Split(n.Ports, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "port" && localPods[fields[2]] {
			localPods[strings.TrimSuffix(fields[1], ":")] = true
		}
	}
	for _, p := range paths {
		if p.Flows[len(p.Flows)-1].Packets == 0 {
			continue
		}
		if p.Verdict == "forward" {
			// A pod-facing output already identifies the destination. Remote
			// outputs need only the terminal translation for logical outport.
			if !localPods[p.Output] {
				last := p.Flows[len(p.Flows)-1]
				if wanted[last.ID] < 1 {
					wanted[last.ID] = 1
				}
			}
			continue
		}
		for _, f := range p.Flows {
			priority := 1
			if p.Verdict == "drop" {
				priority = 2
			}
			if wanted[f.ID] < priority {
				wanted[f.ID] = priority
			}
		}
	}
	var ids []string
	for id := range wanted {
		if !strings.HasPrefix(id, "synthetic-") {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		if wanted[ids[i]] != wanted[ids[j]] {
			return wanted[ids[i]] > wanted[ids[j]]
		}
		return ids[i] < ids[j]
	})
	flowByID := map[string]datapath.Flow{}
	for _, f := range flows {
		flowByID[f.ID] = f
	}
	limit := c.MaxDetraces
	if limit <= 0 {
		limit = 128
	}
	traces := map[string]traceCache{}
	lookups, omitted := 0, 0
	for _, id := range ids {
		f := flowByID[id]
		match, _ := json.Marshal(f.Match)
		signature := string(match) + f.Actions
		if trace, ok := cached.Traces[id]; ok && trace.Signature == signature {
			n.Detraces[id] = trace.Text
			traces[id] = trace
			n.Collection.DetraceHits++
			continue
		}
		if lookups >= limit {
			omitted++
			continue
		}
		lookups++
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
		if len(out) > 0 && len(out) < 256<<10 && len(traces) < 256 {
			traces[id] = traceCache{Signature: signature, Text: out}
		}
		if ctx.Err() != nil {
			break
		}
	}
	if omitted > 0 {
		n.Errors = append(n.Errors, fmt.Sprintf("Translation budget reached; %d UFIDs have no translation evidence this poll.", omitted))
	}
	cached.Traces = traces
	if !cached.At.IsZero() {
		for _, trace := range traces {
			cached.Bytes += len(trace.Text) + len(trace.Signature)
		}
		c.remember(name, cached)
	}
	if ctx.Err() != nil {
		n.Errors = append(n.Errors, "Node collection did not complete: "+ctx.Err().Error())
	}
	return n
}
