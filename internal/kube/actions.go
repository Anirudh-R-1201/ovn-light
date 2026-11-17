// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/trozet/ovn-light/internal/policy"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

func (c *Client) resource(o unstructured.Unstructured) (dynamic.ResourceInterface, error) {
	switch o.GetKind() {
	case "NetworkPolicy":
		return c.Dynamic.Resource(schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}).Namespace(o.GetNamespace()), nil
	case "MultiNetworkPolicy":
		return c.Dynamic.Resource(Resources["multi-networkpolicies"]).Namespace(o.GetNamespace()), nil
	case "ClusterNetworkConnect":
		return c.Dynamic.Resource(Resources["clusternetworkconnects"]), nil
	}
	return nil, fmt.Errorf("unsupported resource kind")
}
func (c *Client) Create(ctx context.Context, o unstructured.Unstructured, dryRun bool) (*unstructured.Unstructured, error) {
	r, e := c.resource(o)
	if e != nil {
		return nil, e
	}
	opts := meta.CreateOptions{FieldManager: "ovn-light"}
	if dryRun {
		opts.DryRun = []string{meta.DryRunAll}
	}
	return r.Create(ctx, o.DeepCopy(), opts)
}
func SpecHash(o *unstructured.Unstructured) string {
	var definition any = o.Object["spec"]
	// Retargeting policy-for changes the policy even when its spec is untouched.
	if o.GetKind() == "MultiNetworkPolicy" {
		definition = []any{definition, o.GetAnnotations()[policy.PolicyForAnnotation]}
	}
	b, _ := json.Marshal(definition)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
func (c *Client) Rollback(ctx context.Context, ref policy.ObjectRef, planID string) error {
	o := unstructured.Unstructured{}
	o.SetKind(ref.Kind)
	o.SetNamespace(ref.Namespace)
	r, e := c.resource(o)
	if e != nil {
		return e
	}
	current, e := r.Get(ctx, ref.Name, meta.GetOptions{})
	if e != nil {
		return e
	}
	if string(current.GetUID()) != ref.UID || current.GetAnnotations()["ovn-light.io/plan"] != planID || SpecHash(current) != ref.SpecHash {
		return fmt.Errorf("%s %s/%s has changed; refusing to delete it", ref.Kind, ref.Namespace, ref.Name)
	}
	uid := types.UID(ref.UID)
	rv := current.GetResourceVersion()
	return r.Delete(ctx, ref.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &uid, ResourceVersion: &rv}})
}

// Probe runs a fixed TCP connect command in the selected source pod. It neither
// installs tools nor creates another pod whose identity would differ.
func (c *Client) Probe(ctx context.Context, i policy.Intent) (string, error) {
	if i.AllPorts || i.Port < 1 || i.Port > 65535 {
		return "", fmt.Errorf("TCP verification requires one destination port between 1 and 65535")
	}
	if (i.Kind != "NetworkPolicy" && i.Kind != "EgressFirewall") || i.Protocol != "TCP" {
		return "", fmt.Errorf("active verification is available for TCP policy proposals; use application tests for other protocols and network connections")
	}
	p, e := c.Core.CoreV1().Pods(i.Source.Namespace).Get(ctx, i.Source.Pod, meta.GetOptions{})
	if e != nil {
		return "", e
	}
	if string(p.UID) != i.Source.UID || len(p.Spec.Containers) == 0 {
		return "", fmt.Errorf("source pod changed; choose the new pod in a fresh proposal")
	}
	if i.Kind == "NetworkPolicy" {
		d, e := c.Core.CoreV1().Pods(i.Destination.Namespace).Get(ctx, i.Destination.Pod, meta.GetOptions{})
		if e != nil {
			return "", e
		}
		if string(d.UID) != i.Destination.UID {
			return "", fmt.Errorf("destination pod changed")
		}
	}
	t := Target{p.Namespace, p.Name, p.Spec.Containers[0].Name}
	port := strconv.Itoa(i.Port)
	address := net.JoinHostPort(i.Destination.IP, port)
	commands := [][]string{{"python3", "-c", "import socket,sys; s=socket.create_connection((sys.argv[1],int(sys.argv[2])),5); s.close()", i.Destination.IP, port}, {"/agnhost", "connect", address, "--timeout=5s"}, {"nc", "-z", "-w", "5", i.Destination.IP, port}}
	for _, args := range commands {
		call, cancel := context.WithTimeout(ctx, 8*time.Second)
		_, err := c.Exec(call, t, args, nil)
		cancel()
		if err == nil {
			return "TCP connection established from the selected source pod to " + address + ". This verifies transport reachability, not application behavior.", nil
		}
		s := strings.ToLower(err.Error())
		if strings.Contains(s, "executable file not found") || strings.Contains(s, "no such file or directory") || strings.Contains(s, "executable not found") {
			continue
		}
		return "", err
	}
	return "", fmt.Errorf("the source container has none of python3, /agnhost or nc; run an application connectivity test instead")
}
