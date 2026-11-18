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

The present live collector still executes commands through Kubernetes into the
existing OVN/OVS containers. It uses a fixed worker pool, defaults to three
concurrent node collections, and caches metadata for one minute. Status-only pod
updates no longer invalidate the cache. Relevant labels, attachment identity and
policy specs do invalidate it. `--collection-node-selector` can restrict datapath
inspection to selected nodes; the UI reports that reduced coverage. Inventory is
still cluster-wide and is listed each round.

Existing bounds remain: two-minute capture deadline, 24 MiB command output per
node, 64 MiB retained raw node snapshots, 32 MiB metadata cache, and 2,000 traffic
identities across up to 60 frames/ten minutes. Coverage and truncation are shown;
increasing browser zoom does not recover omitted observations.

`TestLargeTopologyScopeAndBudget` and `BenchmarkTopology2000Nodes` exercise a
synthetic 2,000-node inventory with 2,000 traffic identities. They validate graph
aggregation and bounds, not full collection at that cluster size. For continuous
full-cluster collection at that size, node-local collection, watched inventory,
compact uploads and partitioned aggregation are still required. The current
deployment is not a distributed collector and is not certified for 2,000 nodes.
