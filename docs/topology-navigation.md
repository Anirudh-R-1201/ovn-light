# Exploring large topologies

The traffic topology accepts exact node names, a comma-separated selection of
nodes, Kubernetes node label selectors, network, namespace, workload/name and
zone filters. Filtering happens before link limits. “Between selected nodes”
requires both endpoints to match the node scope; the neighbors mode requires
either endpoint. “Issues only” includes observed drops, cached drops and repeated
receipt gaps. “Hide paths” retains a bounded inventory/observation view.

Group by zone, node, namespace, workload or pod. Workload grouping uses the pod's
immediate controller owner, so Deployment pods appear under their ReplicaSet;
the dashboard does not infer Deployment ownership from a name. Groups remain
separate across network identities. Click groups to narrow the scope and drill
down. Clusters with more than 100 inspected nodes start grouped by zone.

Use the wheel/trackpad to zoom, drag the background to pan, or use the keyboard
and zoom buttons. Fit brings the visible graph into view. Reset restores the
camera. Refresh preserves positions of nodes already in the current scope;
filters reset the layout. Pause updates freezes the current observations.
Traffic labels appear on hover, keyboard focus or selection, with an option to
keep them visible. Partial observation cards remain separate from confirmed
pod links. Mobile uses a list of bounded paths.

Observed/cached drop and repeated-gap links take precedence over ordinary high
traffic when the link budget is exhausted. Hidden link, group and issue counts
make the display limit explicit. These are limits on retained observations, not
claims about all traffic in the cluster.

## Collection scale

Each DaemonSet collector reads its local OVS instance and uploads traffic
groups with separate source, receiver and drop counters. The central server
lists cluster inventory once per round. Set `--collection-node-selector` on
the server to limit which nodes receive collection requests. Set the
DaemonSet's node selector as well to limit pod placement.

The server accepts up to 64 MiB of decoded summaries per round and keeps
2,000 traffic identities across up to 60 frames in a ten-minute window.
The Collectors page shows gaps and per-node upload sizes.

`TestLargeTopologyScopeAndBudget` and `BenchmarkTopology2000Nodes` exercise a
synthetic 2,000-node inventory with 2,000 traffic identities. Live collection
has been verified on the two-node KIND demo. Cluster-wide inventory updates,
report ingestion and graph retention still need end-to-end capacity testing.
