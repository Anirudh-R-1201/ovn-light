// SPDX-License-Identifier: Apache-2.0
package ovn

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/trozet/ovn-light/internal/model"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func enrichAdminCauses(causes []model.PolicyCause, inv model.Inventory, metadataAt time.Time) {
	for j := range causes {
		c := &causes[j]
		resource := ""
		switch c.Type {
		case "AdminNetworkPolicy":
			resource = "adminnetworkpolicies"
		case "BaselineAdminNetworkPolicy":
			resource = "baselineadminnetworkpolicies"
		default:
			continue
		}
		a := &model.AdminPolicyEvidence{Kind: c.Type, Name: c.Name, Direction: c.Direction, RuleIndex: -1, Warnings: []string{}}
		c.Admin = a
		a.Explanation = "This administrative ACL denies the observed path. A NetworkPolicy allow cannot override an AdminNetworkPolicy Deny."
		if c.Type == "BaselineAdminNetworkPolicy" {
			a.Explanation = "This baseline administrative ACL denies the observed path. A matching NetworkPolicy can take precedence over baseline policy; review both directions and any higher-priority AdminNetworkPolicy first."
		}
		a.Warnings = append(a.Warnings, "ACL attribution does not recover masked pod identities or ports. The rule below is the current API version; cached datapath evidence can reflect an earlier version.")
		if !metadataAt.IsZero() {
			a.Warnings = append(a.Warnings, "ACL metadata collected "+metadataAt.UTC().Format(time.RFC3339))
		}
		found := false
		for _, p := range inv.Resources[resource] {
			if p.GetName() != c.Name {
				continue
			}
			found = true
			a.Subject, _, _ = unstructured.NestedMap(p.Object, "spec", "subject")
			if priority, ok, _ := unstructured.NestedInt64(p.Object, "spec", "priority"); ok {
				a.Priority = &priority
			}
			index, err := strconv.Atoi(c.Rule)
			if err != nil || index < 0 || c.Direction != "Ingress" && c.Direction != "Egress" {
				a.Warnings = append(a.Warnings, "The ACL did not identify a valid rule position.")
				break
			}
			rules, _, _ := unstructured.NestedSlice(p.Object, "spec", strings.ToLower(c.Direction))
			if index >= len(rules) {
				a.Warnings = append(a.Warnings, "The referenced rule position is absent from the current policy.")
				break
			}
			rule, ok := rules[index].(map[string]any)
			if !ok {
				break
			}
			a.RuleIndex = index
			a.Rule = rule
			a.RuleName = Str(rule["name"])
			if Str(rule["action"]) != "Deny" {
				a.Warnings = append(a.Warnings, fmt.Sprintf("Current rule action is %s, while cached ACL action is %s. Wait for convergence and collect fresh evidence.", Str(rule["action"]), c.Action))
			}
			break
		}
		if !found {
			a.Warnings = append(a.Warnings, "The referenced policy is absent or could not be read; only ACL evidence is available.")
		}
		if len(causes) > 1 {
			a.Warnings = append(a.Warnings, "Multiple denying ACL candidates were recovered; one uniquely responsible rule is not established.")
		}
	}
}
