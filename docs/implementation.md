# OVN-Light implementation

OVN-Light observes existing OVS datapath flows without enabling sampling,
changing megaflows, or changing offload configuration. A Go service collects
read-only command output through the Kubernetes exec API in existing OVS/OVN
containers. This keeps its parser and deployment independent of a particular
OVS image. It also supports portable JSON snapshots and an explicit demo mode.

The reconstruction engine indexes recirculation stages, composes masked packet
constraints through supported actions, and keeps ambiguity explicit. Port
identity comes from datapath ports, OVS Interface metadata, OVN port bindings,
and Kubernetes network attachments. UFID translation caches and SB logical-flow
stage hints provide NB ACL ownership. Counters belong to datapath rules, not
automatically to every reconstructed path.

Policy plans are generated on the server, reviewed as manifests, and checked
against fresh inventory before application. They create narrowly scoped allow
policies rather than editing existing policies. Unsupported policy precedence,
ambiguous identities, cross-network peers, and unmodeled transformations must
not result in an automatic allow recommendation. Kubernetes admission dry-run
is separate from connectivity verification. The standalone deployment is an
authenticated administrator tool; it uses its configured Kubernetes identity.

Implementation checkpoints:

- [x] Datapath parser, masked constraints, recirculation reconstruction and tests
- [x] OVSDB snapshots, port/workload/network identity and ACL attribution
- [x] Live KIND collection, capability and partial-failure reporting
- [x] NetworkPolicy review/apply/rollback and explicit verification
- [x] UDN inventory and reviewed ClusterNetworkConnect creation
- [x] Web UI, snapshot/demo modes, manifests and documented KIND workflow
- [x] Tests, live validation and recorded limitations

Hardware validation, secondary-interface verification, cross-node path stitching,
ordered administrative-policy evaluation and an OpenShift operator remain
future work. See architecture.md for the boundaries of this first release.
