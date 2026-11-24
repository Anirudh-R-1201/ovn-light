// SPDX-License-Identifier: Apache-2.0
package ovn

import (
	"testing"

	"github.com/trozet/ovn-light/internal/datapath"
	"github.com/trozet/ovn-light/internal/model"
)

func TestSoftwareDatapathSampleUsesLocalTestPort(t *testing.T) {
	n := model.NodeSnapshot{Name: "a", Ports: "port 4: veth-test", Interfaces: []model.Row{{"name": "veth-test", "external_ids": map[string]any{"iface-id": "test_client", "iface-id-ver": "one"}}}}
	a := Attachment{Node: "a", LogicalPort: "test_client", Primary: true, Endpoint: model.Endpoint{Namespace: "ovn-light-tests", Network: "default", UID: "one", Labels: map[string]string{"ovn-light.io/run": "run-1"}}}
	raw := "ufid:abc,recirc_id(0),in_port(4),eth_type(0x0800),ipv4(src=10.2.0.3,dst=10.4.0.4,proto=6),packets:9,bytes:900,actions:2"
	sample := datapath.ReadSample(raw, n.Ports)
	paths, limited := sampleTestPaths(n, newTrafficIndex(model.Inventory{}, []Attachment{a}).testPorts[n.Name], sample.Paths, "disabled")
	if len(paths) != 1 || limited || paths[0].Stages[0].Raw != raw || paths[0].Stages[0].Status != "software" || !paths[0].Outbound {
		t.Fatalf("%+v", paths)
	}
	a.Endpoint.UID = "replacement"
	if paths, _ = sampleTestPaths(n, newTrafficIndex(model.Inventory{}, []Attachment{a}).testPorts[n.Name], sample.Paths, "disabled"); len(paths) > 0 {
		t.Fatal("port from previous pod matched")
	}
}
