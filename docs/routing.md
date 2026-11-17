# Routing, uplinks and EgressIP

**Routing** joins RouteAdvertisements, their generated FRRConfigurations, BGP
session state, local advertised-route tables, node routes and uplinks. Filter by
network or node, or search for a peer, VRF or prefix. Select a peer to inspect
PodNetwork/EgressIP prefixes and select an uplink to inspect interfaces,
addresses, gateways and controller conditions.

The graph separates three kinds of evidence:

- **Configured**: a prefix is permitted by a neighbor's FRR configuration.
- **Locally advertised**: FRR returned it in that neighbor's advertised routes.
- **Not advertised**: it is missing from a complete, recent advertised-route
  table while the session is established. Configuration may still be converging.

An established session alone never confirms an advertisement. Local advertisement
also does not prove that the remote peer accepted or installed the prefix.
Unavailable or incomplete runtime queries leave configuration visible without
turning missing evidence into a withdrawal. BGP/BFD API states are labelled as
FRR-k8s reported state; direct FRR queries have their own collection timestamp.

A peer is associated with an uplink through an explicit peering interface or a
best route in the peer's VRF. ECMP can produce several candidate uplinks. The
lookup does not evaluate Linux policy routing, discover physical switch ports or
infer direct adjacency for multihop BGP. Default gateways use the actual
`physnet` bridge mapping; Uplink/UplinkState resources supply additional uplinks.
Interface statistics are cumulative shared totals, not per-network rates.

## EgressIP

**EgressIP** intersects namespace and pod selectors and displays primary network
attachments, requested addresses, assigned nodes and node readiness. The graph
shows each assigned path and checks for an exact OVN gateway-router SNAT
association. Multiple assignments remain separate; selectors cannot identify the
chosen egress node of an individual connection. The most recent observed move
is retained while this OVN-Light process runs, until the object is replaced or
removed. It is not a persistent failover audit.

Positive, exact datapath observations to external destinations can be inspected
on each path. Source and egress-node counters remain independent. Neither an
assignment nor a programmed SNAT proves external delivery. UDN host-stack NAT,
accelerated paths and masked tuples can leave the observation incomplete.

The first 200 assigned paths per EgressIP are retained, with a truncation notice;
the UI draws at most 40 at once. Filters narrow the retained paths. This initial
bound means very large EgressIP selections are not fully represented.

## Administrative policies

An ANP/BANP-attributed drop in **Issues → Inspect evidence** shows the policy,
direction, priority where applicable, rule position/name, subject and current
rule. OVN ACL external IDs provide the attribution. Cached flows and current
policy resources can describe different revisions, so the UI exposes that limit
and reports missing or changed rules. Ambiguous ACL matches remain ambiguous.

These integrations are diagnostic. They do not edit ANP/BANP. An ANP Deny cannot
be overridden by adding a NetworkPolicy; the ordinary allow button is suppressed
for these drops. BANP has lower precedence, but changing it still requires review
of higher-priority policy. Administrative policy guards apply to the default
network; primary UDN policies are not blocked by unrelated ANPs.

## Deployment

The normal deployment grants read access to the optional APIs. Their absence is
supported and shown in the view; RBAC or collection errors are distinguished from
an absent API. OVN-Kubernetes must have the corresponding feature enabled.

For direct FRR queries, install FRR-k8s and apply:

```sh
kubectl apply -f deploy/frr-reader.yaml
```

For OpenShift, adapt that Role/RoleBinding to the FRR namespace, commonly
`openshift-frr-k8s`. This allows the OVN-Light service account to execute fixed
read-only `vtysh` queries in the discovered `frr` container. Kubernetes exec RBAC
does not restrict command arguments; use the same administrator access model as
the existing OVS collector. Multiple FRR pods on one node leave runtime discovery
ambiguous. Raw/running configuration and BGP credentials are removed before
inventory is persisted or exported.

## Collection cost and validation

Opening or filtering a view performs no Kubernetes exec. Host/OVN/FRR diagnostics
are cached for one minute per node, including failures, and invalidated when a
collector pod changes. Each collection has a 28-command ceiling, checks a
20-second time budget between commands, and allows at most 16 peer/address-family
route queries. Existing 15-second command and 90-second node deadlines still
apply. Routing results over 1 MiB per command are omitted; aggregate reads stop
after the 4 MiB budget is reached. The cache is bounded to 16 MiB and shares the
existing 64 MiB snapshot limit. Truncation and query failures are visible.

The collector still polls Kubernetes inventory and executes centrally with bounded
concurrency. NAT associations are indexed once per collection and reused for pod
paths. This is suitable for initial deployments; large-cluster validation,
watch-based inventory and distributed collectors remain future work. Increasing
node or peer count can exceed collection budgets and leave partial coverage.

`GET /api/routing` requires the normal access token and accepts `network`, `node`,
`search`, `limit` (1–100), and `offset`. Pagination applies independently to each
resource group. It returns no mutations. Stale snapshots retain last-known data
and suppress current-health issues.

KIND CI includes separate `admin`, `egressip` and `routing` lanes. They exercise
real ANP/BANP enforcement, external EgressIP SNAT and node failover, FRR sessions,
PodNetwork/EgressIP prefix reception by an external FRR container, default uplink
association, optional API absence and peer failure. The pinned OVN image does
not include Uplink/UplinkState; their correlation and readiness are covered by
unit/browser fixtures until a suitable image is pinned. Unit tests cover
VRF/ECMP and IPv4/IPv6 route separation, incomplete/stale evidence, selectors,
network isolation, credential redaction and cached failures. Browser tests cover
the graph, filters, evidence details and mobile layout. Hardware/DPU uplinks and
production-scale behavior are not certified by KIND.
