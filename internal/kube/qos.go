// SPDX-License-Identifier: Apache-2.0
package kube

import (
	"fmt"
	"time"

	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/ovn"
)

func captureQoS(t nodeTargets, nbdb string, exec func(Target, ...string) (string, error)) model.QoSEvidence {
	q := model.QoSEvidence{At: time.Now().UTC()}
	table := func(target Target, args ...string) []model.Row {
		out, err := exec(target, args...)
		if err != nil {
			q.Errors = append(q.Errors, fmt.Sprintf("%s: %s", args[len(args)-1], shortError(err)))
			return nil
		}
		rows, err := ovn.DecodeTable(out)
		if err != nil {
			q.Errors = append(q.Errors, err.Error())
		}
		return rows
	}
	q.Rules = table(t.ovn, "ovn-nbctl", "--timeout=10", "--db="+nbdb, "--format=json", "--columns=_uuid,external_ids,priority,direction,match,action,bandwidth", "list", "QoS")
	q.Switches = table(t.ovn, "ovn-nbctl", "--timeout=10", "--db="+nbdb, "--format=json", "--columns=name,qos_rules", "list", "Logical_Switch")
	q.Queues = table(t.ovs, "ovs-vsctl", "--timeout=10", "--format=json", "--columns=_uuid,type,other_config", "list", "QoS")
	q.Ports = table(t.ovs, "ovs-vsctl", "--timeout=10", "--format=json", "--columns=name,interfaces,qos", "list", "Port")
	return q
}
