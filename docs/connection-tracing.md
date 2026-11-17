# Connection tracing

The **Trace** page simulates a requested TCP or UDP packet using current OVN
configuration. It does not need a datapath cache entry or a previously observed
drop. Open it directly, or choose **Simulate this connection** from drop evidence
or topology details.

1. Choose the network, source pod attachment, destination pod, Service or IP, and
   destination port. Source port defaults to 49152.
2. Leave connection state at **New connection** to investigate an initial policy
   decision. Established and reply states are explicit assumptions; they do not
   read the connection's real conntrack entry.
3. Run **Simulate path**. Inspect the logical switch/router stages, matching deny
   ACL, and policy owner. Expand the full trace or optional source-node OVS trace
   for technical evidence.
4. For a predicted policy drop, **Review an allowance** opens the existing
   proposal workflow with the selected endpoints and port. Simulation does not
   authorize a change. Review selectors and affected workloads before applying.
5. Simulate again after the change, or explicitly run **Test real TCP connection**.
   DNS has a separate test from the source container. Results appear on the Trace
   page; tests are never run automatically by the simulation.

## What a result means

- **Predicted logical delivery**: the simulation reaches the destination logical
  port. This does not prove a physical packet arrives or an application listens.
- **Predicted drop**: OVN terminates the requested path with drop evidence. A
  namespace default-deny ACL identifies isolation, not a uniquely responsible
  NetworkPolicy. Administrative Deny rules are identified separately; a regular
  NetworkPolicy cannot override an AdminNetworkPolicy Deny.
- **Handoff / unresolved**: evidence stops at a remote zone, gateway, unsupported
  transformation or diagnostic. It is not presented as success.

Cross-node pod traces can continue across an interconnect switch when the switch
ports and unchanged IP tuple are recovered unambiguously. The receiver segment
assumes that the packet reaches that zone. It does not measure tunnel delivery.
Branches, NAT transformations and Service NAT continuation across zones remain
incomplete. External IP traces stop at the last available logical output; they
do not trace external routers or prove BGP reachability.

Pod attachment selection supports the network identities already discovered by
OVN-Light, including UDNs. Gateway MACs are resolved through the attachment's
switch/router bindings, keeping overlapping network addresses separate. Unsupported
or unavailable bindings produce an explicit error. Connected-network tracing is
not supported yet. KIND validation currently covers the cluster default network;
this feature has not been certified on hardware or every UDN topology.

## Services and DNS

Service VIP simulation currently supports the primary cluster default network.
The server reads EndpointSlices, checks Service ownership, pod UID, readiness,
address family and port mapping, and respects `internalTrafficPolicy: Local`.
It pins each logical trace to a chosen backend with `ovn-trace --lb-dst`.
By default the first eligible backend sorted by pod name is chosen; the option
to trace ready backends tests up to four. This selection does not predict live
load balancing, affinity or topology preferences. The optional OVS trace does
not pin the backend and is shown as independent evidence.

Headless and ExternalName Services require selecting a resolved pod or IP.
For UDN Service traffic, select the destination pod attachment until UDN VIP
and service-mirror handling are supported.

DNS tests infer the cluster DNS domain from the source pod's `/etc/resolv.conf`
for a selected Service; an explicit hostname can also be entered. They run an
available `getent`, `nslookup` or Python resolver in the source container. TCP
checks use the existing Python, agnhost or nc probe. No tools are installed.
These active tests use the pod's primary network and first container, require a
live server with writes enabled, and require `pods/exec` access in that namespace.
Service TCP checks connect to the VIP, so the live backend may differ from the
simulation. DNS success establishes name resolution, not service reachability.

## Execution and limits

Trace operations are requested individually and never run in the background.
One diagnostic runs at a time per OVN-Light instance. Simulation has a 90-second
deadline; individual exec calls have a 15-second deadline. Output is bounded to
32 MiB per simulation, with 2 MiB per trace and 16 MiB per metadata command.
Metadata is reused within that request, not collected for the entire cluster.
The normal datapath collection loop is unchanged.

`ovn-trace` uses fresh SB logical flows and NB ACL metadata. Each of up to 32
conntrack lookups receives the selected explicit state, avoiding the tool's
implicit established-connection default. The OVS command is `ofproto/trace`
without packet data, `--generate`, or `--execute`. It does not install a datapath
flow, inject packets, change OVS configuration or disable hardware offload.
Neither simulator validates the NIC's programmed state. Configuration can change
between the API, database and OVS reads; results are timestamped, not an atomic
cluster snapshot.

## API

All routes use the normal OVN-Light bearer authentication and origin checks.
Simulation is available on live read-only servers; active tests additionally
require writes enabled. Inputs are structured connection fields, never commands.

- `GET /api/trace/context`: canonical pod attachments and Services for selection.
- `POST /api/trace`: `source`, `destination` or `service` reference, `protocol`,
  `port`, optional `sourcePort`, `state` (`new`, `established`, `reply`), `ovs`,
  and `allBackends`. Pod endpoints must include namespace, pod, UID, network,
  IP and NAD when applicable. Service references include namespace, name and UID.
- `POST /api/trace/tcp`: same connection request; opens a new TCP connection.
- `POST /api/trace/dns`: `source` plus a Service reference or `name`.

A trace result includes per-backend outcomes, per-node stages, policy causes,
warnings and raw output. A real check returns `success`, `summary` and optional
output. An ordinary failed connection is a completed check with `success: false`;
invalid input or unavailable execution returns an API error.

References: [ovn-trace manual](https://www.ovn.org/support/dist-docs/ovn-trace.8.html)
and [OVS tracing](https://docs.openvswitch.org/en/stable/topics/tracing/).
