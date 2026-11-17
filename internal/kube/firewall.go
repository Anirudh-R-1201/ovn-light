// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/trozet/ovn-light/internal/policy"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// PatchFirewall changes only the rule list. Atomic tests protect the reviewed
// UID and spec even if another writer races the inventory or admission dry-run.
func (c *Client) PatchFirewall(ctx context.Context, change *policy.FirewallChange, desired unstructured.Unstructured, dryRun bool) (*unstructured.Unstructured, error) {
	rules, _, err := unstructured.NestedSlice(desired.Object, "spec", "egress")
	if err != nil || change.Index < 0 || change.Index >= len(rules) {
		return nil, fmt.Errorf("invalid firewall insertion")
	}
	r := c.Dynamic.Resource(Resources["egressfirewalls"]).Namespace(change.Namespace)
	patch := []map[string]any{
		{"op": "test", "path": "/metadata/uid", "value": change.UID},
		{"op": "test", "path": "/spec", "value": change.BeforeSpec},
		{"op": "add", "path": fmt.Sprintf("/spec/egress/%d", change.Index), "value": rules[change.Index]},
	}
	b, err := json.Marshal(patch)
	if err != nil {
		return nil, err
	}
	opts := meta.PatchOptions{FieldManager: "ovn-light"}
	if dryRun {
		opts.DryRun = []string{meta.DryRunAll}
	}
	return r.Patch(ctx, change.Name, types.JSONPatchType, b, opts)
}

func (c *Client) RollbackFirewall(ctx context.Context, change *policy.FirewallChange, ref policy.ObjectRef) error {
	if ref.Kind != "EgressFirewall" || ref.Name != change.Name || ref.Namespace != change.Namespace || ref.UID != change.UID {
		return fmt.Errorf("firewall audit identity does not match")
	}
	r := c.Dynamic.Resource(Resources["egressfirewalls"]).Namespace(change.Namespace)
	current, err := r.Get(ctx, change.Name, meta.GetOptions{})
	if err != nil {
		return err
	}
	if string(current.GetUID()) != ref.UID || SpecHash(current) != ref.SpecHash {
		return fmt.Errorf("EgressFirewall %s/%s has changed; refusing to remove its rule", change.Namespace, change.Name)
	}
	patch := []map[string]any{
		{"op": "test", "path": "/metadata/uid", "value": ref.UID},
		{"op": "test", "path": "/metadata/resourceVersion", "value": current.GetResourceVersion()},
		{"op": "test", "path": "/spec", "value": current.Object["spec"]},
		{"op": "remove", "path": fmt.Sprintf("/spec/egress/%d", change.Index)},
	}
	b, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	_, err = r.Patch(ctx, change.Name, types.JSONPatchType, b, meta.PatchOptions{FieldManager: "ovn-light"})
	return err
}
