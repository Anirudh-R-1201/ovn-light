// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/trozet/ovn-light/internal/policy"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

func qosResource(kind string) (schema.GroupVersionResource, error) {
	switch kind {
	case "NetworkQoS":
		return DiagnosticResources["networkqoses"], nil
	case "EgressQoS":
		return DiagnosticResources["egressqoses"], nil
	}
	return schema.GroupVersionResource{}, fmt.Errorf("unsupported QoS kind")
}
func (c *Client) PatchQoS(ctx context.Context, change *policy.QoSChange, desired unstructured.Unstructured, dry bool) (*unstructured.Unstructured, error) {
	gvr, err := qosResource(change.Kind)
	if err != nil {
		return nil, err
	}
	if desired.GetKind() != change.Kind || desired.GetNamespace() != change.Namespace || desired.GetName() != change.Name || string(desired.GetUID()) != change.UID {
		return nil, fmt.Errorf("QoS audit identity does not match")
	}
	patch, _ := json.Marshal([]map[string]any{{"op": "test", "path": "/metadata/uid", "value": change.UID}, {"op": "test", "path": "/spec", "value": change.BeforeSpec}, {"op": "replace", "path": "/spec", "value": desired.Object["spec"]}})
	opts := meta.PatchOptions{FieldManager: "ovn-light"}
	if dry {
		opts.DryRun = []string{meta.DryRunAll}
	}
	return c.Dynamic.Resource(gvr).Namespace(change.Namespace).Patch(ctx, change.Name, types.JSONPatchType, patch, opts)
}
func (c *Client) RollbackQoS(ctx context.Context, change *policy.QoSChange, ref policy.ObjectRef) error {
	gvr, err := qosResource(change.Kind)
	if err != nil {
		return err
	}
	if ref.Kind != change.Kind || ref.Namespace != change.Namespace || ref.Name != change.Name || ref.UID != change.UID {
		return fmt.Errorf("QoS audit identity does not match")
	}
	resource := c.Dynamic.Resource(gvr).Namespace(ref.Namespace)
	current, err := resource.Get(ctx, ref.Name, meta.GetOptions{})
	if err != nil {
		return err
	}
	if string(current.GetUID()) != ref.UID || SpecHash(current) != ref.SpecHash {
		return fmt.Errorf("QoS resource changed; refusing to overwrite another update")
	}
	patch, _ := json.Marshal([]map[string]any{{"op": "test", "path": "/metadata/uid", "value": ref.UID}, {"op": "test", "path": "/metadata/resourceVersion", "value": current.GetResourceVersion()}, {"op": "test", "path": "/spec", "value": current.Object["spec"]}, {"op": "replace", "path": "/spec", "value": change.BeforeSpec}})
	_, err = resource.Patch(ctx, ref.Name, types.JSONPatchType, patch, meta.PatchOptions{FieldManager: "ovn-light"})
	return err
}
