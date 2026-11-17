// SPDX-License-Identifier: Apache-2.0
// Package policy builds additive, reviewable changes from an explicit connection
// intent. It never accepts a manifest from the browser for execution.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
	core "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"
)

type Intent struct {
	Kind          string         `json:"kind"`
	FindingID     string         `json:"findingID,omitempty"`
	Source        model.Endpoint `json:"source"`
	Destination   model.Endpoint `json:"destination"`
	Protocol      string         `json:"protocol"`
	Port          int            `json:"port"`
	Networks      []string       `json:"networks,omitempty"`
	ConnectCIDR   string         `json:"connectCIDR,omitempty"`
	NetworkPrefix int            `json:"networkPrefix,omitempty"`
	Services      bool           `json:"services,omitempty"`
}
type ObjectRef struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
	SpecHash  string `json:"specHash"`
}
type Plan struct {
	ID             string                      `json:"id"`
	Kind           string                      `json:"kind"`
	Scope          *Scope                      `json:"scope,omitempty"`
	FirewallChange *FirewallChange             `json:"firewallChange,omitempty"`
	BeforeManifest string                      `json:"beforeManifest,omitempty"`
	CreatedAt      time.Time                   `json:"createdAt"`
	ExpiresAt      time.Time                   `json:"expiresAt"`
	Intent         Intent                      `json:"intent"`
	Fingerprint    string                      `json:"-"`
	Summary        string                      `json:"summary"`
	Manifests      string                      `json:"manifests"`
	Objects        []unstructured.Unstructured `json:"objects"`
	Affected       []string                    `json:"affected"`
	Warnings       []string                    `json:"warnings"`
	Status         string                      `json:"status"`
	Applied        []ObjectRef                 `json:"applied"`
	Verification   string                      `json:"verification,omitempty"`
}

func Build(inv model.Inventory, intent Intent, id string) (Plan, error) {
	p := Plan{ID: id, Kind: intent.Kind, Intent: intent, CreatedAt: time.Now().UTC(), Status: "review", Objects: []unstructured.Unstructured{}, Affected: []string{}, Warnings: []string{}}
	p.ExpiresAt = p.CreatedAt.Add(10 * time.Minute)
	if len(inv.Errors) > 0 {
		return p, fmt.Errorf("inventory is incomplete; refresh or fix collection permissions before proposing changes: %s", strings.Join(inv.Errors, "; "))
	}
	var err error
	switch intent.Kind {
	case "Policy", "NetworkPolicy", "MultiNetworkPolicy":
		err = buildPolicy(inv, &p)
	case "ClusterNetworkConnect":
		err = buildConnect(inv, &p)
	case "EgressFirewall":
		err = buildFirewall(inv, &p)
	default:
		err = fmt.Errorf("unsupported action kind %q", intent.Kind)
	}
	if err != nil {
		return p, err
	}
	p.Fingerprint = Fingerprint(inv)
	var manifests []string
	for _, o := range p.Objects {
		b, e := yaml.Marshal(o.Object)
		if e != nil {
			return p, e
		}
		manifests = append(manifests, string(b))
	}
	p.Manifests = strings.Join(manifests, "---\n")
	sort.Strings(p.Affected)
	return p, nil
}

// Ignore volatile pod status, while guarding identity, labels, attachments and
// every policy/network input. A changed inventory requires a fresh review.
func Fingerprint(inv model.Inventory) string {
	var parts []string
	add := func(v any) { b, _ := json.Marshal(v); parts = append(parts, string(b)) }
	for _, p := range inv.Pods {
		add([]any{p.Namespace, p.Name, p.UID, p.Labels, p.Annotations["k8s.ovn.org/pod-networks"], p.Spec.HostNetwork, p.Spec.Containers})
	}
	for _, n := range inv.Namespaces {
		add([]any{n.Name, n.UID, n.Labels})
	}
	for _, p := range inv.Policies {
		add([]any{p.Namespace, p.Name, p.UID, p.Spec})
	}
	for k, rs := range inv.Resources {
		for _, r := range rs {
			add([]any{k, r.GetNamespace(), r.GetName(), r.GetUID(), r.GetLabels(), r.GetAnnotations(), r.GetOwnerReferences(), r.Object["spec"]})
		}
	}
	for _, s := range inv.Services {
		add([]any{s.Namespace, s.Name, s.UID, s.Spec})
	}
	sort.Strings(parts)
	h := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(h[:])
}

func findPod(inv model.Inventory, e model.Endpoint) (core.Pod, ovn.Attachment, error) {
	for _, p := range inv.Pods {
		if p.Namespace != e.Namespace || p.Name != e.Pod {
			continue
		}
		if e.UID != "" && e.UID != string(p.UID) {
			return p, ovn.Attachment{}, fmt.Errorf("pod %s/%s was replaced; refresh and select it again", e.Namespace, e.Pod)
		}
		if p.DeletionTimestamp != nil {
			return p, ovn.Attachment{}, fmt.Errorf("pod %s/%s is terminating", e.Namespace, e.Pod)
		}
		var candidates []ovn.Attachment
		for _, a := range ovn.Attachments(inv) {
			if a.Endpoint.UID == string(p.UID) && (e.Network == "" || a.Endpoint.Network == e.Network) && (e.NAD == "" || e.NAD == a.Endpoint.NAD) && (e.IP == "" || e.IP == a.Endpoint.IP) {
				candidates = append(candidates, a)
			}
		}
		if len(candidates) == 1 {
			return p, candidates[0], nil
		}
		if len(candidates) > 1 {
			return p, ovn.Attachment{}, fmt.Errorf("pod %s/%s has multiple matching attachments; choose the network and IP explicitly", p.Namespace, p.Name)
		}
	}
	return core.Pod{}, ovn.Attachment{}, fmt.Errorf("pod attachment %s/%s on %s no longer exists", e.Namespace, e.Pod, e.Network)
}
func selected(sel meta.LabelSelector, values map[string]string) bool {
	s, err := meta.LabelSelectorAsSelector(&sel)
	return err == nil && s.Matches(labels.Set(values))
}
func namespaceLabels(inv model.Inventory, ns string) map[string]string {
	for _, n := range inv.Namespaces {
		if n.Name == ns {
			return n.Labels
		}
	}
	return nil
}

func buildPolicy(inv model.Inventory, p *Plan) error {
	i := p.Intent
	i.Protocol = strings.ToUpper(i.Protocol)
	if i.Protocol != "TCP" && i.Protocol != "UDP" && i.Protocol != "SCTP" {
		return fmt.Errorf("choose TCP, UDP or SCTP")
	}
	if i.Port < 1 || i.Port > 65535 {
		return fmt.Errorf("choose a destination port between 1 and 65535")
	}
	src, sa, err := findPod(inv, i.Source)
	if err != nil {
		return err
	}
	dst, da, err := findPod(inv, i.Destination)
	if err != nil {
		return err
	}
	scope, err := scopeFor(inv, sa, da, i.Kind)
	if err != nil {
		return err
	}
	p.Scope = scope
	p.Kind = scope.PolicyKind
	i.Kind = p.Kind
	scopedPolicies, err := policiesForScope(inv, scope)
	if err != nil {
		return err
	}
	policyInventory := inv
	policyInventory.Policies = scopedPolicies
	if len(src.Labels) == 0 || len(dst.Labels) == 0 {
		return fmt.Errorf("both workloads need pod labels to generate a scoped policy")
	}
	i.Source = sa.Endpoint
	i.Destination = da.Endpoint
	p.Intent = i
	// Administrative policies govern primary networks. Their ordered rules must
	// be reviewed separately before proposing an ordinary NetworkPolicy.
	if scope.Role == "primary" {
		for _, kind := range []string{"adminnetworkpolicies", "baselineadminnetworkpolicies"} {
			for _, r := range inv.Resources[kind] {
				subject, _, _ := unstructured.NestedMap(r.Object, "spec", "subject")
				for _, pod := range []core.Pod{src, dst} {
					if subjectMatches(inv, subject, pod) {
						return fmt.Errorf("%s %s selects an endpoint; review its ordered rules with the administrator before adding a NetworkPolicy", r.GetKind(), r.GetName())
					}
				}
			}
		}
		for _, r := range inv.Resources["egressfirewalls"] {
			if r.GetNamespace() == src.Namespace {
				return fmt.Errorf("EgressFirewall %s/%s controls the source; review it before generating an allow", r.GetNamespace(), r.GetName())
			}
		}
	}
	attachedPods := map[string]bool{}
	for _, a := range ovn.Attachments(inv) {
		if a.Endpoint.Network == scope.Network && a.Endpoint.Role == scope.Role {
			attachedPods[a.Endpoint.UID] = true
		}
	}
	for _, direction := range []netv1.PolicyType{netv1.PolicyTypeEgress, netv1.PolicyTypeIngress} {
		target, peer := src, dst
		targetAttachment := sa
		if direction == netv1.PolicyTypeIngress {
			target, peer = dst, src
			targetAttachment = da
		}
		isolated, allowed := directionAllowed(policyInventory, target, peer, dst, i, direction)
		if !isolated || allowed {
			continue
		}
		// All current labels intentionally narrow the scope; the UI lists every
		// matching pod, including replicas. No empty selectors are generated.
		selector := meta.LabelSelector{MatchLabels: copyLabels(target.Labels)}
		peerSelector := meta.LabelSelector{MatchLabels: copyLabels(peer.Labels)}
		namespaceSelector := meta.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": peer.Namespace}}
		protocol := core.Protocol(i.Protocol)
		port := intstr.FromInt32(int32(i.Port))
		rulePeer := netv1.NetworkPolicyPeer{PodSelector: &peerSelector, NamespaceSelector: &namespaceSelector}
		rulePort := netv1.NetworkPolicyPort{Protocol: &protocol, Port: &port}
		name := "ovn-light-" + p.ID[:12] + "-" + strings.ToLower(string(direction))
		np := netv1.NetworkPolicy{TypeMeta: meta.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: target.Namespace, Labels: map[string]string{"app.kubernetes.io/managed-by": "ovn-light"}, Annotations: map[string]string{"ovn-light.io/plan": p.ID}}, Spec: netv1.NetworkPolicySpec{PodSelector: selector, PolicyTypes: []netv1.PolicyType{direction}}}
		if direction == netv1.PolicyTypeIngress {
			np.Spec.Ingress = []netv1.NetworkPolicyIngressRule{{From: []netv1.NetworkPolicyPeer{rulePeer}, Ports: []netv1.NetworkPolicyPort{rulePort}}}
		} else {
			np.Spec.Egress = []netv1.NetworkPolicyEgressRule{{To: []netv1.NetworkPolicyPeer{rulePeer}, Ports: []netv1.NetworkPolicyPort{rulePort}}}
		}
		obj, e := runtime.DefaultUnstructuredConverter.ToUnstructured(&np)
		if e != nil {
			return e
		}
		delete(obj, "status")
		object := unstructured.Unstructured{Object: obj}
		annotations := object.GetAnnotations()
		annotations["ovn-light.io/network"] = scope.Network
		if scope.PolicyKind == "MultiNetworkPolicy" {
			object.SetKind(scope.PolicyKind)
			object.SetAPIVersion("k8s.cni.cncf.io/v1beta1")
			annotations[PolicyForAnnotation] = targetAttachment.Endpoint.NAD
		}
		object.SetAnnotations(annotations)
		p.Objects = append(p.Objects, object)
		for _, candidate := range inv.Pods {
			if !attachedPods[string(candidate.UID)] {
				continue
			}
			if candidate.Namespace == target.Namespace && selected(selector, candidate.Labels) {
				p.Affected = append(p.Affected, fmt.Sprintf("%s target: %s/%s", direction, candidate.Namespace, candidate.Name))
			}
			if candidate.Namespace == peer.Namespace && selected(peerSelector, candidate.Labels) {
				p.Affected = append(p.Affected, fmt.Sprintf("%s peer: %s/%s", direction, candidate.Namespace, candidate.Name))
			}
		}
	}
	if len(p.Objects) == 0 {
		return fmt.Errorf("current %s rules on %s already permit this connection; a new allow rule would not fix the drop. Inspect routing, other policy and OVN convergence", scope.PolicyKind, scope.Network)
	}
	p.Summary = fmt.Sprintf("Allow %s/%s → %s/%s on %s/%d · %s (%d additive %s resources)", src.Namespace, src.Name, dst.Namespace, dst.Name, i.Protocol, i.Port, scope.Network, len(p.Objects), scope.PolicyKind)
	if scope.Role == "primary" {
		p.Warnings = append(p.Warnings, "NetworkPolicy follows the namespace's primary network. The ovn-light.io/network annotation records this proposal's scope; it does not select the network.")
	} else {
		p.Warnings = append(p.Warnings, "The policy-for annotation selects the secondary OVN network. OVN multi-network-policy enforcement must be enabled; API admission alone does not establish enforcement.", "Verify traffic on the selected secondary interface. The built-in TCP verification currently supports primary networks only.")
	}
	p.Warnings = append(p.Warnings, "This is an operator-selected connection intent, not proof that the application should be allowed.", "All pods with these labels, including future replicas, will receive this permission. Full pod labels may include rollout hashes; review the YAML before applying.", "The policy is additive. Existing policies are not edited. Applying it does not prove connectivity.")
	return nil
}
func copyLabels(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
func subjectMatches(inv model.Inventory, subject map[string]any, p core.Pod) bool {
	if raw, ok := subject["namespaces"].(map[string]any); ok {
		var s meta.LabelSelector
		if runtime.DefaultUnstructuredConverter.FromUnstructured(raw, &s) != nil {
			return true
		}
		return selected(s, namespaceLabels(inv, p.Namespace))
	}
	if raw, ok := subject["pods"].(map[string]any); ok {
		var s struct {
			NamespaceSelector meta.LabelSelector `json:"namespaceSelector"`
			PodSelector       meta.LabelSelector `json:"podSelector"`
		}
		if runtime.DefaultUnstructuredConverter.FromUnstructured(raw, &s) != nil {
			return true
		}
		return selected(s.NamespaceSelector, namespaceLabels(inv, p.Namespace)) && selected(s.PodSelector, p.Labels)
	}
	return true
}

func directionAllowed(inv model.Inventory, target, peer, dst core.Pod, i Intent, direction netv1.PolicyType) (isolated, allowed bool) {
	for _, np := range inv.Policies {
		if np.Namespace != target.Namespace || !selected(np.Spec.PodSelector, target.Labels) || !hasDirection(np, direction) {
			continue
		}
		isolated = true
		if direction == netv1.PolicyTypeIngress {
			for _, r := range np.Spec.Ingress {
				if peersMatch(inv, np.Namespace, r.From, peer, i.Source.IP) && portsMatch(r.Ports, dst, i) {
					allowed = true
				}
			}
		} else {
			for _, r := range np.Spec.Egress {
				if peersMatch(inv, np.Namespace, r.To, peer, i.Destination.IP) && portsMatch(r.Ports, dst, i) {
					allowed = true
				}
			}
		}
	}
	return
}
func hasDirection(np netv1.NetworkPolicy, d netv1.PolicyType) bool {
	if len(np.Spec.PolicyTypes) == 0 {
		return d == netv1.PolicyTypeIngress || d == netv1.PolicyTypeEgress && len(np.Spec.Egress) > 0
	}
	for _, t := range np.Spec.PolicyTypes {
		if t == d {
			return true
		}
	}
	return false
}
func peersMatch(inv model.Inventory, ns string, peers []netv1.NetworkPolicyPeer, pod core.Pod, ip string) bool {
	if len(peers) == 0 {
		return true
	}
	for _, p := range peers {
		if p.IPBlock != nil {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				continue
			}
			prefix, err := netip.ParsePrefix(p.IPBlock.CIDR)
			if err != nil || !prefix.Contains(addr) {
				continue
			}
			except := false
			for _, raw := range p.IPBlock.Except {
				cidr, e := netip.ParsePrefix(raw)
				if e == nil && cidr.Contains(addr) {
					except = true
				}
			}
			if !except {
				return true
			}
			continue
		}
		if p.NamespaceSelector != nil {
			if !selected(*p.NamespaceSelector, namespaceLabels(inv, pod.Namespace)) {
				continue
			}
		} else if p.PodSelector != nil && pod.Namespace != ns {
			continue
		}
		if p.PodSelector == nil || selected(*p.PodSelector, pod.Labels) {
			return true
		}
	}
	return false
}
func portsMatch(ports []netv1.NetworkPolicyPort, dst core.Pod, i Intent) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		protocol := core.ProtocolTCP
		if p.Protocol != nil {
			protocol = *p.Protocol
		}
		if string(protocol) != i.Protocol {
			continue
		}
		if p.Port == nil {
			return true
		}
		if p.Port.Type == intstr.Int {
			end := p.Port.IntVal
			if p.EndPort != nil {
				end = *p.EndPort
			}
			if int(p.Port.IntVal) <= i.Port && i.Port <= int(end) {
				return true
			}
		} else {
			for _, c := range dst.Spec.Containers {
				for _, port := range c.Ports {
					proto := port.Protocol
					if proto == "" {
						proto = core.ProtocolTCP
					}
					if port.Name == p.Port.StrVal && int(port.ContainerPort) == i.Port && proto == protocol {
						return true
					}
				}
			}
		}
	}
	return false
}
