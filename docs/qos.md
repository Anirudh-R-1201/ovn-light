# QoS inspection and reviewed changes

The QoS page discovers `NetworkQoS` (`k8s.ovn.org/v1alpha1`), `EgressQoS`
(`k8s.ovn.org/v1`), and default-network pod bandwidth annotations. Missing APIs
and permission errors are shown separately from an empty policy list.

Filter by network, node, namespace or policy name. A policy shows its selectors,
source attachments, rules, controller status, and owned OVN NB QoS rows with
their logical-switch attachments. NetworkQoS supports the default network when
network selectors are omitted, and explicit NAD or CUDN selectors. An unresolved
selection never falls back to an IP-only match or to the default network.
Workloads sharing a source attachment are reported as potentially overlapping;
their destination classifiers and actual OVN priorities determine the result.

NetworkQoS later rules have higher precedence. EgressQoS earlier rules have higher
precedence and mark default-network traffic without setting a bandwidth limit.
Rates are kbps and bursts are kilobits. Pod bandwidth annotations use bit/s;
pod egress corresponds to OVS ingress policing and pod ingress to port QoS.

“Review value change” updates DSCP and, for NetworkQoS, rate/burst in one existing
rule. Zero removes a rate or burst. It cannot change selectors or rule order.
The proposal shows before/after manifests and selected source attachments, runs
Kubernetes admission dry-run, and expires after ten minutes. Apply atomically
tests UID and the reviewed spec. Rollback restores the old spec only if the
resource identity and applied spec still match. Changes are recorded in the
existing audit directory and Changes page. Demo/snapshot mode exports only.

The Trace page includes source-selected QoS policies as candidate context.
Inspect its logical QoS stages and classifiers for the requested packet.
Simulation does not exercise a real policer. The QoS page links to observed
traffic; those counters are not isolated by QoS rule and must not be interpreted
as meter-drop counters. Queue delay, policer drops and hardware meter statistics
are not collected. A flat throughput graph does not prove policing, and DSCP
marking does not prove downstream priority.

QoS tables are collected with the existing bounded node metadata cache. A row
observed in NB is configuration evidence, not proof of successful hardware
programming. Collection timestamps, stale data and incomplete evidence remain
visible. Responses page policies and cap displayed attachment/programming lists.

## KIND example

Enable the OVN feature with Helm `global.enableNetworkQos=true`, then apply
`examples/qos.yaml`. It creates an isolated namespace with a client, server,
NetworkQoS rate/marking rule, EgressQoS marking rule for the server, and pod
bandwidth annotations. It does not alter the original denied-traffic example.

The pinned OVN chart currently defines bandwidth with `format: int32` and a
`4294967295` maximum. Kubernetes rejects rules using those fields. The `qos` CI
lane calls `scripts/ci/fix-qos-schema.py` to change only those two formats to
`int64`, retaining the uint32 bounds. This workaround is confined to test setup;
the application never edits CRDs or enables OVN features.

The KIND QoS lane runs `scripts/e2e-qos.py`: discover both policy kinds, prepare
and apply a value change, wait for owned NB rules and switch attachments, test
ordinary TCP delivery, roll back, and confirm the original values. It also checks
pod bandwidth programming and rejects proposal reuse. It does not claim to test
DSCP on the wire or hardware rate enforcement.
