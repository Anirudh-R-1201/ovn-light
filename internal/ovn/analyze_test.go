// SPDX-License-Identifier: Apache-2.0
package ovn_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trozet/ovn-light/internal/app"
	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
	"k8s.io/apimachinery/pkg/types"
)

func TestOverlappingUDNIPsDoNotCrossIdentity(t *testing.T) {
	s := app.Demo()
	other := s.Inventory.Pods[1].DeepCopy()
	other.Namespace = "analytics"
	other.Name = "overlap"
	other.UID = types.UID("overlap")
	other.Annotations["k8s.ovn.org/pod-networks"] = `{"analytics/data":{"ip_addresses":["10.244.0.12/24"],"role":"primary"}}`
	s.Inventory.Pods = append(s.Inventory.Pods, *other)
	for _, f := range ovn.Analyze(s, nil).Findings {
		if f.Destination.IP == "10.244.0.12" && f.Destination.Namespace != "payments" {
			t.Fatalf("IP lookup crossed networks: %+v", f)
		}
	}
}

func TestRealKINDDefaultDeny(t *testing.T) {
	b, e := os.ReadFile("../../testdata/kind-denied.json")
	if e != nil {
		t.Fatal(e)
	}
	var s model.Snapshot
	if e = json.Unmarshal(b, &s); e != nil {
		t.Fatal(e)
	}
	v := ovn.Analyze(s, nil)
	if len(v.Findings) != 1 {
		t.Fatalf("expected one drop path, got %+v", v.Findings)
	}
	f := v.Findings[0]
	if !strings.HasPrefix(f.Source.Pod, "client-") || !strings.HasPrefix(f.Destination.Pod, "server-") {
		t.Fatalf("lost workload identity: %+v", f)
	}
	if len(f.Steps) < 3 || len(f.Causes) != 1 || f.Causes[0].Type != "NetpolNamespace" {
		t.Fatalf("lost policy/path attribution: %+v", f)
	}
	if f.Destination.Port != 0 || f.CanRecommend {
		t.Fatal("wildcarded transport was incorrectly made precise")
	}
}

func TestEvidenceAndMaskedConnection(t *testing.T) {
	s := app.Demo()
	v := ovn.Analyze(s, nil)
	if len(v.Findings) != 2 {
		t.Fatal(v.Findings)
	}
	var precise, partial bool
	for _, f := range v.Findings {
		if f.Source.Pod == "" || f.Destination.Pod == "" || len(f.Causes) != 1 {
			t.Fatalf("attribution failed: %+v", f)
		}
		if f.Destination.Port == 8080 {
			precise = f.CanRecommend && f.Confidence == "connection"
		} else {
			partial = !f.CanRecommend && f.Confidence == "partial"
		}
	}
	if !precise || !partial {
		t.Fatal("masked traffic must not inherit an exact connection")
	}
}
func TestCounterResetAndDelta(t *testing.T) {
	old := app.Demo()
	now := old
	now.Nodes = append(now.Nodes[:0:0], old.Nodes...)
	now.Nodes[0].Flows = strings.ReplaceAll(old.Nodes[0].Flows, "packets:41", "packets:45")
	v := ovn.Analyze(now, &old)
	for _, f := range v.Findings {
		if f.Destination.Port == 8080 && (f.Delta == nil || *f.Delta != 4) {
			t.Fatal("missing delta", f)
		}
	}
	now.Nodes[0].Flows = strings.ReplaceAll(old.Nodes[0].Flows, "packets:41", "packets:1")
	v = ovn.Analyze(now, &old)
	for _, f := range v.Findings {
		if f.Destination.Port == 8080 && f.Delta != nil {
			t.Fatal("counter reset reported as valid delta")
		}
	}
}
func TestOVSDBTaggedValues(t *testing.T) {
	rows, e := ovn.DecodeTable(`{"headings":["_uuid","external_ids","datapath"],"data":[[["uuid","abc"],["map",[["iface-id","ns_pod"]]],["uuid","def"]]]}`)
	if e != nil || ovn.Str(rows[0]["_uuid"]) != "abc" || ovn.Map(rows[0]["external_ids"])["iface-id"] != "ns_pod" {
		t.Fatal(rows, e)
	}
}
