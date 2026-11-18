// SPDX-License-Identifier: Apache-2.0
package topology

import (
	"strings"

	"github.com/trozet/ovn-light/internal/model"
	"k8s.io/apimachinery/pkg/labels"
)

type inventory struct {
	scope     string
	labels    map[string]map[string]string
	workloads map[string]string
}

// Replace metadata as one immutable value so a query can use a snapshot while
// the next collection updates node labels or replaces a pod.
func (s *Store) Inventory(inv model.Inventory) {
	m := inventory{scope: inv.DiagnosticErrors["collectionScope"], labels: map[string]map[string]string{}, workloads: map[string]string{}}
	for _, n := range inv.Nodes {
		m.labels[n.Name] = n.Labels
	}
	for _, p := range inv.Pods {
		owner := "Pod/" + p.Name
		for _, r := range p.OwnerReferences {
			if r.Controller != nil && *r.Controller {
				owner = r.Kind + "/" + r.Name
				break
			}
		}
		m.workloads[string(p.UID)] = p.Namespace + "/" + owner
	}
	s.metadata = m
}

func ValidLevel(level string) bool {
	switch level {
	case "nodes", "pods", "zones", "namespaces", "workloads":
		return true
	}
	return false
}

func (s *Store) matcher(o Options) func(model.Endpoint, model.Endpoint) bool {
	selected := map[string]bool{}
	for _, n := range strings.Split(o.Nodes, ",") {
		if n = strings.TrimSpace(n); n != "" {
			selected[n] = true
		}
	}
	if o.Node != "" {
		selected[o.Node] = true
	}
	selector, err := labels.Parse(o.NodeSelector)
	nodeMatch := func(e model.Endpoint) bool {
		if err != nil {
			return false
		}
		if len(selected) > 0 && !selected[e.Node] {
			return false
		}
		if o.NodeSelector != "" && (e.Node == "" || !selector.Matches(labels.Set(s.metadata.labels[e.Node]))) {
			return false
		}
		if o.Zone != "" && s.zone(e.Node) != o.Zone {
			return false
		}
		return true
	}
	endpointMatch := func(e model.Endpoint) bool {
		return (o.Namespace == "" || e.Namespace == o.Namespace) && (o.Workload == "" || strings.Contains(strings.ToLower(s.workload(e)+"/"+e.Pod), strings.ToLower(o.Workload)))
	}
	return func(a, b model.Endpoint) bool {
		if !endpointMatch(a) && !endpointMatch(b) {
			return false
		}
		if o.Paths == "between" {
			return nodeMatch(a) && nodeMatch(b)
		}
		return nodeMatch(a) || nodeMatch(b)
	}
}
func (s *Store) zone(name string) string {
	if z := s.metadata.labels[name]["topology.kubernetes.io/zone"]; z != "" {
		return z
	}
	return "Zone not labeled"
}
func (s *Store) workload(e model.Endpoint) string {
	if w := s.metadata.workloads[e.UID]; w != "" {
		return w
	}
	if e.Pod != "" {
		return e.Namespace + "/Pod/" + e.Pod
	}
	return "External / unresolved"
}
func (s *Store) group(e model.Endpoint, network, level string) Node {
	n := node(e, network, level)
	var group string
	switch level {
	case "zones":
		group = s.zone(e.Node)
		if e.Node == "" {
			group = "External / unresolved"
		}
	case "namespaces":
		group = e.Namespace
		if group == "" {
			group = "External / unresolved"
		}
	case "workloads":
		group = s.workload(e)
	default:
		return n
	}
	n.ID, n.Name, n.Group, n.Node = id(network, level, group), group, level, ""
	return n
}
