# OVN-Light implementation

OVN-Light observes existing OVS datapath flows without enabling sampling,
changing megaflows, or changing offload configuration. KIND runs a DaemonSet that reads each node's local sockets with the deployed
OVS and OVN tools. Each collector reconstructs paths and sends a compressed
summary to the central server. The standalone capture command can export raw
evidence through Kubernetes exec for offline analysis.

The reconstruction engine indexes recirculation stages, composes masked packet
constraints through supported actions, and keeps ambiguity explicit. Port
identity comes from datapath ports, OVS Interface metadata, OVN port bindings,
and Kubernetes network attachments. UFID translation caches and SB logical-flow
stage hints provide NB ACL ownership. Counters belong to datapath rules, not
automatically to every reconstructed path.

Policy plans are generated on the server, reviewed as manifests, and checked
against fresh inventory before application. NetworkPolicy proposals create scoped
allow policies. EgressFirewall proposals insert an IP/port exception into the
existing ordered firewall using guarded patches. Unsupported policy precedence,
ambiguous identities, cross-network peers, and unmodeled transformations must
not result in an automatic allow recommendation. Kubernetes admission dry-run
is separate from connectivity verification. The standalone deployment is an
authenticated administrator tool; it uses its configured Kubernetes identity.

Implementation checkpoints:

- [x] Datapath parser, masked constraints, recirculation reconstruction and tests
- [x] OVSDB snapshots, port/workload/network identity and ACL attribution
- [x] Live KIND collection, capability and partial-failure reporting
- [x] NetworkPolicy review/apply/rollback and explicit verification
- [x] Ordered EgressFirewall IP/port exceptions, atomic patching, verification and guarded rule rollback
- [x] UDN inventory and reviewed ClusterNetworkConnect creation
- [x] Web UI, snapshot/demo modes, manifests and documented KIND workflow
- [x] Network-filtered live node/pod topology, bounded traffic history and independent observation counters
- [x] Collection budgets, metadata/translation caches and collector cost metrics
- [x] Tests, live validation and recorded limitations

Hardware validation, secondary-interface verification,
ordered administrative-policy evaluation and an OpenShift operator remain
future work. See architecture.md for the boundaries of this first release.
