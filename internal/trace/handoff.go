// SPDX-License-Identifier: Apache-2.0
package trace

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
)

var macAssignment = regexp.MustCompile(`^eth\.(src|dst) = ([0-9a-fA-F:]+);$`)

// ContinueFlow follows a single unchanged IP tuple across an interconnect
// switch. Branches, NAT and generated packets need more state than this trace
// retains, so they stay an explicitly incomplete handoff.
func ContinueFlow(r Request, src ovn.Attachment, source Segment, remote model.NodeSnapshot) (string, error) {
	if r.Service != nil {
		return "", fmt.Errorf("Service NAT continuation across zones is not supported yet")
	}
	if source.Status != "handoff" || len(source.Stages) == 0 {
		return "", fmt.Errorf("no remote handoff")
	}
	last := source.Stages[len(source.Stages)-1]
	if last.Pipeline != "egress" || last.InPort == "" || last.OutPort == "" {
		return "", fmt.Errorf("remote switch ports were not retained")
	}
	input, err := binding(remote.Bindings, last.InPort)
	if err != nil {
		return "", err
	}
	output, err := binding(remote.Bindings, last.OutPort)
	if err != nil {
		return "", err
	}
	if ovn.Str(input["type"]) != "remote" || ovn.Str(output["type"]) != "patch" || ovn.Str(input["datapath"]) != ovn.Str(output["datapath"]) {
		return "", fmt.Errorf("handoff does not resolve to one interconnect switch in the destination zone")
	}
	smac, dmac := src.MAC, ""
	ttl := 64
	remoteOutputs := 0
	for _, m := range outputRE.FindAllStringSubmatch(source.Raw, -1) {
		if m[2] == "remote" {
			remoteOutputs++
		}
	}
	if remoteOutputs != 1 {
		return "", fmt.Errorf("multiple remote output branches cannot be continued as one packet")
	}
	for _, stage := range source.Stages {
		for _, action := range stage.Actions {
			for _, unsupported := range []string{"ct_dnat", "ct_snat", "ct_lb(", "ct_lb_mark(", "clone", "arp {", "nd_na", "tcp_reset", "ip4.src =", "ip4.dst =", "ip6.src =", "ip6.dst =", "tcp.src =", "tcp.dst =", "udp.src =", "udp.dst ="} {
				if strings.Contains(action, unsupported) {
					return "", fmt.Errorf("handoff contains NAT, packet generation or a tuple transformation")
				}
			}
			if action == "ip.ttl--;" {
				ttl--
			}
			if m := macAssignment.FindStringSubmatch(action); m != nil {
				mac, e := net.ParseMAC(m[2])
				if e != nil || len(mac) != 6 {
					return "", fmt.Errorf("invalid handoff MAC")
				}
				if m[1] == "src" {
					smac = mac.String()
				} else {
					dmac = mac.String()
				}
			}
		}
	}
	if dmac == "" || ttl < 1 {
		return "", fmt.Errorf("handoff MAC or remaining TTL could not be reconstructed")
	}
	flow := LogicalFlow(r, last.InPort, smac, dmac)
	return strings.Replace(flow, "ip.ttl == 64", "ip.ttl == "+strconv.Itoa(ttl), 1), nil
}
