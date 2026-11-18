// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"fmt"
	"time"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/qos"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

type QoSRequest struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
	Rule      int    `json:"rule"`
	DSCP      int64  `json:"dscp"`
	Rate      *int64 `json:"rateKbps,omitempty"`
	Burst     *int64 `json:"burstKbits,omitempty"`
}
type QoSChange struct {
	Kind       string         `json:"kind"`
	Namespace  string         `json:"namespace"`
	Name       string         `json:"name"`
	UID        string         `json:"uid"`
	BeforeSpec map[string]any `json:"beforeSpec"`
}

// The browser supplies values for one existing rule, never a manifest or new
// selectors. Review and rollback preserve that object's identity and scope.
func BuildQoS(inv model.Inventory, r QoSRequest, id string) (Plan, error) {
	p := Plan{ID: id, Kind: r.Kind, Intent: Intent{Kind: r.Kind}, CreatedAt: time.Now().UTC(), Status: "review", Fingerprint: Fingerprint(inv), Warnings: []string{"Only DSCP and bandwidth values in the selected rule change. Selectors and rule order are preserved. Review all affected attachments; OVN needs time to converge."}}
	p.ExpiresAt = p.CreatedAt.Add(10 * time.Minute)
	kind := "networkqoses"
	if r.Kind == "EgressQoS" {
		kind = "egressqoses"
	} else if r.Kind != "NetworkQoS" {
		return p, fmt.Errorf("unsupported QoS kind")
	}
	if len(inv.Errors) > 0 || inv.DiagnosticErrors[kind] != "" {
		return p, fmt.Errorf("QoS inventory is incomplete")
	}
	if r.UID == "" || r.DSCP < 0 || r.DSCP > 63 {
		return p, fmt.Errorf("resource UID and DSCP 0–63 are required")
	}
	for _, v := range []*int64{r.Rate, r.Burst} {
		if v != nil && (*v < 0 || *v > 4294967295) {
			return p, fmt.Errorf("bandwidth values must be 0–4294967295; zero removes a limit")
		}
	}
	if r.Kind == "EgressQoS" && (r.Rate != nil || r.Burst != nil) {
		return p, fmt.Errorf("EgressQoS supports DSCP marking only")
	}
	for _, u := range inv.Resources[kind] {
		if u.GetNamespace() != r.Namespace || u.GetName() != r.Name {
			continue
		}
		if string(u.GetUID()) != r.UID {
			return p, fmt.Errorf("QoS resource was replaced; refresh")
		}
		desired := u.DeepCopy()
		before, _, err := unstructured.NestedMap(desired.Object, "spec")
		if err != nil {
			return p, err
		}
		rules, _, err := unstructured.NestedSlice(desired.Object, "spec", "egress")
		if err != nil || r.Rule < 0 || r.Rule >= len(rules) {
			return p, fmt.Errorf("rule no longer exists")
		}
		rule, ok := rules[r.Rule].(map[string]any)
		if !ok {
			return p, fmt.Errorf("invalid QoS rule")
		}
		rule["dscp"] = r.DSCP
		if r.Rate != nil || r.Burst != nil {
			bw, _ := rule["bandwidth"].(map[string]any)
			if bw == nil {
				bw = map[string]any{}
			}
			for k, v := range map[string]*int64{"rate": r.Rate, "burst": r.Burst} {
				if v == nil {
					continue
				}
				if *v == 0 {
					delete(bw, k)
				} else {
					bw[k] = *v
				}
			}
			if bw["burst"] != nil && bw["rate"] == nil {
				return p, fmt.Errorf("burst requires a rate")
			}
			rule["bandwidth"] = bw
		}
		if err = unstructured.SetNestedSlice(desired.Object, rules, "spec", "egress"); err != nil {
			return p, err
		}
		p.QoSChange = &QoSChange{Kind: r.Kind, Namespace: r.Namespace, Name: r.Name, UID: r.UID, BeforeSpec: before}
		p.Objects = []unstructured.Unstructured{*desired}
		p.Summary = fmt.Sprintf("Update %s %s/%s rule %d", r.Kind, r.Namespace, r.Name, r.Rule+1)
		manifest := func(v *unstructured.Unstructured) string {
			b, _ := yaml.Marshal(map[string]any{"apiVersion": v.GetAPIVersion(), "kind": v.GetKind(), "metadata": map[string]any{"name": v.GetName(), "namespace": v.GetNamespace()}, "spec": v.Object["spec"]})
			return string(b)
		}
		p.Manifests = manifest(desired)
		p.BeforeManifest = manifest(&u)
		for _, entry := range qos.Analyze(model.Snapshot{Inventory: inv}).Policies {
			if entry.UID == r.UID {
				for _, e := range entry.Targets {
					p.Affected = append(p.Affected, e.Namespace+"/"+e.Pod+" · "+e.Network)
				}
				p.Warnings = append(p.Warnings, fmt.Sprintf("%d source attachments selected; destination classifiers still apply.", entry.TargetCount))
			}
		}
		return p, nil
	}
	return p, fmt.Errorf("QoS resource not found")
}
