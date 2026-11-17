// SPDX-License-Identifier: Apache-2.0
package ovn

import (
	"encoding/json"
	"github.com/trozet/ovn-light/internal/model"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"strings"
	"testing"
	"time"
)

func TestAdministrativeRuleEvidence(t *testing.T) {
	var u unstructured.Unstructured
	_ = json.Unmarshal([]byte(`{"metadata":{"name":"guard"},"spec":{"priority":7,"subject":{"namespaces":{}},"ingress":[{"name":"deny-private","action":"Deny","from":[{"namespaces":{}}]}]}}`), &u)
	for _, kind := range []string{"AdminNetworkPolicy", "BaselineAdminNetworkPolicy"} {
		key := "adminnetworkpolicies"
		if strings.HasPrefix(kind, "Baseline") {
			key = "baselineadminnetworkpolicies"
		}
		inv := model.Inventory{Resources: map[string][]unstructured.Unstructured{key: {u}}}
		causes := []model.PolicyCause{{Type: kind, Name: "guard", Direction: "Ingress", Rule: "0", Action: "drop"}}
		enrichAdminCauses(causes, inv, time.Now())
		a := causes[0].Admin
		if a == nil || a.RuleIndex != 0 || a.RuleName != "deny-private" || a.Priority == nil || *a.Priority != 7 || a.Rule["action"] != "Deny" {
			t.Fatalf("%+v", a)
		}
		causes[0].Rule = "99"
		enrichAdminCauses(causes, inv, time.Now())
		if causes[0].Admin.RuleIndex != -1 || causes[0].Admin.Rule != nil {
			t.Fatal("old ACL index attached unrelated current rule")
		}
		causes[0].Rule = "0"
		inv.Resources = nil
		enrichAdminCauses(causes, inv, time.Now())
		if !strings.Contains(strings.Join(causes[0].Admin.Warnings, " "), "absent") {
			t.Fatal("missing API concealed")
		}
	}
}
