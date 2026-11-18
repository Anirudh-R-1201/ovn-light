// SPDX-License-Identifier: Apache-2.0
package qos

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type Rule struct {
	Index       int            `json:"index"`
	DSCP        int64          `json:"dscp"`
	Rate        int64          `json:"rateKbps,omitempty"`
	Burst       int64          `json:"burstKbits,omitempty"`
	Classifier  map[string]any `json:"classifier"`
	PodSelector any            `json:"podSelector,omitempty"`
}
type Program struct {
	Node      string    `json:"node"`
	Network   string    `json:"network"`
	UUID      string    `json:"uuid"`
	Rule      int       `json:"rule"`
	Priority  int64     `json:"priority"`
	Match     string    `json:"match"`
	Action    any       `json:"action"`
	Bandwidth any       `json:"bandwidth"`
	Switches  []string  `json:"switches"`
	State     string    `json:"state"`
	At        time.Time `json:"at"`
}
type Policy struct {
	Kind        string           `json:"kind"`
	Namespace   string           `json:"namespace"`
	Name        string           `json:"name"`
	UID         string           `json:"uid"`
	Priority    int64            `json:"priority"`
	Status      any              `json:"status"`
	Spec        map[string]any   `json:"spec"`
	Networks    []string         `json:"networks"`
	Rules       []Rule           `json:"rules"`
	Targets     []model.Endpoint `json:"targets"`
	TargetCount int              `json:"targetCount"`
	Programs    []Program        `json:"programs"`
	Warnings    []string         `json:"warnings"`
}
type Bandwidth struct {
	Endpoint                model.Endpoint `json:"endpoint"`
	Direction               string         `json:"direction"`
	Requested               string         `json:"requested"`
	BitsPerSecond           int64          `json:"bitsPerSecond"`
	ProgrammedBitsPerSecond *int64         `json:"programmedBitsPerSecond,omitempty"`
	State                   string         `json:"state"`
}
type Report struct {
	At           time.Time         `json:"at"`
	Stale        bool              `json:"stale"`
	Capabilities map[string]string `json:"capabilities"`
	Policies     []Policy          `json:"policies"`
	Bandwidth    []Bandwidth       `json:"bandwidth"`
	Total        int               `json:"total"`
	Hidden       int               `json:"hidden"`
	Warnings     []string          `json:"warnings"`
}
type Options struct {
	Network, Node, Namespace, Search string
	Offset, Limit                    int
}

func number(v any) int64 { n, _ := strconv.ParseInt(ovn.Str(v), 10, 64); return n }
func array(v any) []any  { a, _ := v.([]any); return a }
func selector(v any, l map[string]string) bool {
	if v == nil {
		return true
	}
	b, err := json.Marshal(v)
	if err != nil {
		return false
	}
	var m meta.LabelSelector
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	s, err := meta.LabelSelectorAsSelector(&m)
	return err == nil && s.Matches(labels.Set(l))
}

func networks(inv model.Inventory, spec map[string]any) []string {
	selections := array(spec["networkSelectors"])
	if len(selections) == 0 {
		return []string{"default"}
	}
	result := map[string]bool{}
	nsLabels := map[string]map[string]string{}
	for _, n := range inv.Namespaces {
		nsLabels[n.Name] = n.Labels
	}
	for _, raw := range selections {
		sel := ovn.Map(raw)
		kind := ovn.Str(sel["networkSelectionType"])
		if kind == "DefaultNetwork" {
			result["default"] = true
			continue
		}
		for _, nad := range inv.Resources["network-attachment-definitions"] {
			match := false
			switch kind {
			case "NetworkAttachmentDefinitions":
				v := ovn.Map(sel["networkAttachmentDefinitionSelector"])
				match = len(v) > 0 && selector(v["namespaceSelector"], nsLabels[nad.GetNamespace()]) && selector(v["networkSelector"], nad.GetLabels())
			case "ClusterUserDefinedNetworks":
				v := ovn.Map(sel["clusterUserDefinedNetworkSelector"])
				for _, owner := range nad.GetOwnerReferences() {
					if owner.Kind == "ClusterUserDefinedNetwork" && owner.APIVersion == "k8s.ovn.org/v1" && owner.Controller != nil && *owner.Controller && len(v) > 0 && selector(v["networkSelector"], nad.GetLabels()) {
						match = true
					}
				}
			}
			if match {
				result[ovn.NetworkForNAD(inv, nad.GetNamespace()+"/"+nad.GetName())] = true
			}
		}
	}
	out := []string{}
	for n := range result {
		if n != "" {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func Analyze(s model.Snapshot) Report {
	inv := s.Inventory
	r := Report{At: s.CapturedAt, Capabilities: map[string]string{}, Policies: []Policy{}, Bandwidth: []Bandwidth{}, Warnings: []string{"Configured marking and limits do not establish packet treatment. Policer drops, queue delay and hardware meter counters are not collected. DSCP priority also depends on the downstream network."}}
	for _, n := range s.Nodes {
		if len(n.QoS.Errors) > 0 && len(r.Warnings) < 10 {
			r.Warnings = append(r.Warnings, n.Name+": QoS collection incomplete: "+strings.Join(n.QoS.Errors, "; "))
		}
	}
	if scope := inv.DiagnosticErrors["collectionScope"]; scope != "" {
		r.Warnings = append(r.Warnings, scope)
	}
	attachments := ovn.Attachments(inv)
	for _, kind := range []string{"networkqoses", "egressqoses"} {
		r.Capabilities[kind] = "API not discovered"
		if _, ok := inv.Resources[kind]; ok {
			r.Capabilities[kind] = "Available"
		}
		if e := inv.DiagnosticErrors[kind]; e != "" {
			r.Capabilities[kind] = e
		}
		for _, u := range inv.Resources[kind] {
			spec := ovn.Map(u.Object["spec"])
			p := Policy{Kind: u.GetKind(), Namespace: u.GetNamespace(), Name: u.GetName(), UID: string(u.GetUID()), Priority: number(spec["priority"]), Status: u.Object["status"], Spec: spec, Networks: []string{"default"}, Targets: []model.Endpoint{}, Programs: []Program{}, Rules: []Rule{}, Warnings: []string{}}
			if kind == "networkqoses" {
				p.Kind = "NetworkQoS"
				p.Networks = networks(inv, spec)
				p.Warnings = append(p.Warnings, "Higher OVN priorities win. Later NetworkQoS rules have higher precedence; inspect programmed priorities when policies overlap.")
			} else {
				p.Kind = "EgressQoS"
				p.Warnings = append(p.Warnings, "EgressQoS marks default-network traffic. Earlier rules have higher precedence; it does not configure bandwidth policing.")
			}
			for i, raw := range array(spec["egress"]) {
				v := ovn.Map(raw)
				bw := ovn.Map(v["bandwidth"])
				rule := Rule{Index: i, DSCP: number(v["dscp"]), Rate: number(bw["rate"]), Burst: number(bw["burst"]), Classifier: ovn.Map(v["classifier"]), PodSelector: v["podSelector"]}
				if kind == "egressqoses" {
					rule.Classifier = map[string]any{"dstCIDR": v["dstCIDR"]}
				}
				p.Rules = append(p.Rules, rule)
			}
			for _, a := range attachments {
				e := a.Endpoint
				if e.Namespace != p.Namespace || !slices.Contains(p.Networks, e.Network) || !selector(spec["podSelector"], e.Labels) {
					continue
				}
				selected := kind == "networkqoses"
				for _, rule := range p.Rules {
					if selector(rule.PodSelector, e.Labels) {
						selected = true
					}
				}
				if selected {
					p.Targets = append(p.Targets, e)
				}
			}
			p.TargetCount = len(p.Targets)
			for _, n := range s.Nodes {
				for _, row := range n.QoS.Rules {
					ids := ovn.Map(row["external_ids"])
					owner, name := ovn.Str(ids["k8s.ovn.org/owner-type"]), ovn.Str(ids["k8s.ovn.org/name"])
					index := -1
					if p.Kind == "NetworkQoS" && owner == p.Kind && name == p.Namespace+":"+p.Name {
						if v, err := strconv.Atoi(ovn.Str(ids["rule-index"])); err == nil {
							index = v
						}
					}
					if p.Kind == "EgressQoS" && ((owner == p.Kind && name == p.Namespace) || ovn.Str(ids["EgressQoS"]) == p.Namespace) {
						index = 1000 - int(number(row["priority"]))
					}
					if index < 0 {
						continue
					}
					network := ovn.Str(ids["k8s.ovn.org/network"])
					if network == "" {
						network = "default"
					}
					for _, nad := range inv.Resources["network-attachment-definitions"] {
						key := nad.GetNamespace() + "/" + nad.GetName()
						if ovn.Str(ovn.NADConfig(inv, key)["name"]) == network {
							if canonical := ovn.NetworkForNAD(inv, key); canonical != "" {
								network = canonical
							}
							break
						}
					}
					if strings.HasPrefix(network, "cluster_udn_") {
						network = "cluster/" + strings.TrimPrefix(network, "cluster_udn_")
					}
					program := Program{Node: n.Name, Network: network, UUID: ovn.Str(row["_uuid"]), Rule: index, Priority: number(row["priority"]), Match: ovn.Str(row["match"]), Action: row["action"], Bandwidth: row["bandwidth"], Switches: []string{}, State: "OVN row observed", At: n.QoS.At}
					for _, sw := range n.QoS.Switches {
						if slices.Contains(ovn.Strings(sw["qos_rules"]), program.UUID) {
							program.Switches = append(program.Switches, ovn.Str(sw["name"]))
						}
					}
					if len(program.Switches) == 0 {
						program.State = "Switch attachment not observed"
					}
					if index >= len(p.Rules) {
						program.State = "Rule no longer in desired policy"
					} else {
						rule := p.Rules[index]
						action, bw := ovn.Map(program.Action), ovn.Map(program.Bandwidth)
						if action["dscp"] == nil || number(action["dscp"]) != rule.DSCP || number(bw["rate"]) != rule.Rate || number(bw["burst"]) != rule.Burst {
							program.State = "Desired / programmed values differ"
						}
					}
					p.Programs = append(p.Programs, program)
				}

			}
			if len(p.Programs) == 0 && p.TargetCount > 0 {
				p.Warnings = append(p.Warnings, "No owned OVN QoS rows recovered. Check feature enablement, controller status, node coverage and convergence.")
			}
			if len(p.Networks) == 0 {
				p.Warnings = append(p.Warnings, "Network selectors did not resolve to a discovered attachment; no network has been assumed.")
			}
			r.Policies = append(r.Policies, p)
		}
	}
	r.Bandwidth = bandwidthAnnotations(s, attachments)
	sort.Slice(r.Policies, func(i, j int) bool {
		a, b := r.Policies[i], r.Policies[j]
		return a.Kind+a.Namespace+a.Name < b.Kind+b.Namespace+b.Name
	})
	// Only policies sharing an attachment can overlap. Index those memberships
	// instead of comparing every pod against every other policy's pods.
	memberships := map[string][]int{}
	for i, p := range r.Policies {
		seen := map[string]bool{}
		for _, e := range p.Targets {
			key := e.UID + "/" + e.Network
			if !seen[key] {
				memberships[key] = append(memberships[key], i)
				seen[key] = true
			}
		}
	}
	overlaps := map[[2]int]bool{}
	for _, indices := range memberships {
		for x, i := range indices {
			for _, j := range indices[x+1:] {
				pair := [2]int{i, j}
				if overlaps[pair] {
					continue
				}
				overlaps[pair] = true
				a, b := &r.Policies[i], &r.Policies[j]
				if len(a.Warnings) < 10 {
					a.Warnings = append(a.Warnings, fmt.Sprintf("Shares source attachments with %s %s/%s; destination classifiers and programmed priorities determine which rule applies.", b.Kind, b.Namespace, b.Name))
				}
				if len(b.Warnings) < 10 {
					b.Warnings = append(b.Warnings, "Shares source attachments with "+a.Kind+" "+a.Namespace+"/"+a.Name)
				}
			}
		}
	}
	r.Total = len(r.Policies)
	return r
}

func Filter(r Report, o Options) Report {
	out := r
	out.Policies = []Policy{}
	out.Bandwidth = []Bandwidth{}
	for _, p := range r.Policies {
		if o.Namespace != "" && p.Namespace != o.Namespace || o.Network != "" && !slices.Contains(p.Networks, o.Network) || o.Search != "" && !strings.Contains(strings.ToLower(p.Kind+"/"+p.Namespace+"/"+p.Name), strings.ToLower(o.Search)) {
			continue
		}
		if o.Node != "" && !slices.ContainsFunc(p.Targets, func(e model.Endpoint) bool { return e.Node == o.Node }) {
			continue
		}
		out.Policies = append(out.Policies, p)
	}
	out.Total = len(out.Policies)
	limit := o.Limit
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	start := max(0, min(o.Offset, out.Total))
	end := min(start+limit, out.Total)
	out.Policies = append([]Policy{}, out.Policies[start:end]...)
	out.Hidden = out.Total - len(out.Policies)
	for i := range out.Policies {
		p := &out.Policies[i]
		p.Targets = p.Targets[:min(100, len(p.Targets))]
		p.Programs = p.Programs[:min(100, len(p.Programs))]
	}
	for _, b := range r.Bandwidth {
		if (o.Namespace == "" || o.Namespace == b.Endpoint.Namespace) && (o.Node == "" || o.Node == b.Endpoint.Node) && (o.Network == "" || o.Network == b.Endpoint.Network) {
			out.Bandwidth = append(out.Bandwidth, b)
		}
	}
	if len(out.Bandwidth) > 100 {
		out.Warnings = append(append([]string{}, out.Warnings...), "Only the first 100 bandwidth annotations are shown; narrow the filters.")
		out.Bandwidth = out.Bandwidth[:100]
	}
	return out
}
