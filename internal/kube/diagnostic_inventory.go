// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"context"
	"strings"

	"github.com/trozet/ovn-light/internal/model"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var DiagnosticResources = map[string]schema.GroupVersionResource{
	"networkqoses":        {Group: "k8s.ovn.org", Version: "v1alpha1", Resource: "networkqoses"},
	"egressqoses":         {Group: "k8s.ovn.org", Version: "v1", Resource: "egressqoses"},
	"egressips":           {Group: "k8s.ovn.org", Version: "v1", Resource: "egressips"},
	"routeadvertisements": {Group: "k8s.ovn.org", Version: "v1", Resource: "routeadvertisements"},
	"uplinks":             {Group: "k8s.ovn.org", Version: "v1alpha1", Resource: "uplinks"},
	"uplinkstates":        {Group: "k8s.ovn.org", Version: "v1alpha1", Resource: "uplinkstates"},
	"frrconfigurations":   {Group: "frrk8s.metallb.io", Version: "v1beta1", Resource: "frrconfigurations"},
	"bgpsessionstates":    {Group: "frrk8s.metallb.io", Version: "v1beta1", Resource: "bgpsessionstates"},
	"frrnodestates":       {Group: "frrk8s.metallb.io", Version: "v1beta1", Resource: "frrnodestates"},
}

func (c *Client) diagnosticInventory(ctx context.Context, inv *model.Inventory) {
	inv.DiagnosticErrors = map[string]string{}
	nodes, err := c.Core.CoreV1().Nodes().List(ctx, meta.ListOptions{})
	if err != nil {
		inv.DiagnosticErrors["nodes"] = shortError(err)
	} else {
		inv.Nodes = nodes.Items
	}
	for name, gvr := range DiagnosticResources {
		result, err := c.Dynamic.Resource(gvr).List(ctx, meta.ListOptions{})
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			inv.DiagnosticErrors[name] = shortError(err)
			continue
		}
		for j := range result.Items {
			redactRoutingResource(name, &result.Items[j])
		}
		inv.Resources[name] = result.Items
	}
}

// FRR passwords and arbitrary running/raw configuration are not needed to draw
// topology. Remove them before the inventory is persisted or exported.
func redactRoutingResource(kind string, u *unstructured.Unstructured) {
	if kind != "frrconfigurations" && kind != "frrnodestates" {
		return
	}
	u.SetManagedFields(nil)
	annotation := u.GetAnnotations()["k8s.ovn.org/route-advertisements"]
	u.SetAnnotations(nil)
	if kind == "frrconfigurations" && annotation != "" {
		u.SetAnnotations(map[string]string{"k8s.ovn.org/route-advertisements": annotation})
	}
	if kind == "frrnodestates" {
		unstructured.RemoveNestedField(u.Object, "status", "runningConfig")
		// Conversion errors can quote raw configuration, including credentials.
		for _, field := range []string{"lastConversionResult", "lastReloadResult"} {
			value, _, _ := unstructured.NestedString(u.Object, "status", field)
			if value != "" && !strings.EqualFold(value, "success") {
				_ = unstructured.SetNestedField(u.Object, "Failed; inspect FRR-k8s locally for details", "status", field)
			}
		}
		return
	}
	// Keep the controller's ownership annotation without retaining a last-applied
	// configuration, which can contain the original BGP password.
	unstructured.RemoveNestedField(u.Object, "spec", "raw")
	routers, _, _ := unstructured.NestedSlice(u.Object, "spec", "bgp", "routers")
	for _, r := range routers {
		router, ok := r.(map[string]any)
		if !ok {
			continue
		}
		neighbors, _ := router["neighbors"].([]any)
		for _, v := range neighbors {
			if n, ok := v.(map[string]any); ok {
				delete(n, "password")
				delete(n, "passwordSecret")
			}
		}
	}
	_ = unstructured.SetNestedSlice(u.Object, routers, "spec", "bgp", "routers")
}
