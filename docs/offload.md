# Hardware offload diagnostics

The Hardware Offload page shows cached datapath evidence by node, network,
workload and status. Persistent problems also appear under Issues. Inspect a
path to see each recirculation stage, the exact provider reason when exposed,
partial-offload packet deltas, and DOCA conntrack status by direction. Download
that evidence as JSON for troubleshooting. These actions do not change OVS,
clear counters, enable tracing, or restart services.

Use **Run traffic test** to choose a suite test and its endpoint nodes, then inspect the measurement and available per-node evidence. See [setup and result interpretation](traffic-tests.md).

## Collection

OVN-Light reuses `ovs-appctl -t ovs-vswitchd dpctl/dump-flows -m`. It preserves
`offloaded:yes`, `offloaded:partial`, `dp`, `partial_offload_packets`,
`partial_offload_bytes`, and `dp-offload-info`. Diagnostic suffixes are separated
from actions so they cannot hide a terminal drop.

Once per minute, each node's collector reads `Open_vSwitch.other_config` and
`ovs_version`. Disabled nodes need only this additional command. Enabled nodes
also discover supported commands using `list-commands`. When available, the
collector reads `dpctl/offload-stats-show` and the provider's PMD stats. DOCA nodes
also use `dpctl/dump-conntrack -m`; no tracing configuration is required. All
commands share the existing node deadline and output budget. Unsupported or
failed optional diagnostics do not invalidate the ordinary flow collection.

A CT dump is limited to 4 MiB retained output. Larger or failed dumps are
explicitly unavailable, including their partial output. Config and command lists
are bounded, provider/PMD summaries are limited to 128 KiB each, and the
additional diagnostic cache is limited to 16 MiB across nodes. The offload report
retains at most 4,000 paths with a 16 MiB evidence-text budget. These bounds cover
retained strings, not total Go heap usage. UI summaries omit raw stages; an
individual path request retrieves them. The API returns at most 100 paths.

Full flow and CT enumeration still costs work proportional to table size; the
output limit does not make OVS's enumeration constant-time. The KIND DaemonSet performs this scan locally. Filtered offload evidence travels
with the compressed report. Opening the offload page reads the latest report.

## Interpretation

- **Offload observed:** the observed path and applicable CT direction report
  hardware offload, with complete path evidence. This is not a measurement of
  end-to-end hardware forwarding or a guarantee that every packet stays in HW.
- **Partial offload:** observed stages mix hardware/software, a provider marks a
  stage partial, or partial-execution counters increased. These signals remain
  distinct in the stage inspector.
- **Software processing:** observed stages report software and there is ingress
  offload capability evidence. Capability comes from hardware/partial flows on
  that ingress port, representor/driver metadata, or a provider failure report.
- **Provider failure:** a non-hardware stage carries `dp-offload-info`. Historical
  error text on a currently hardware-offloaded rule does not create an issue.
- **Connection setup:** a rule matches new/SYN traffic, the matched TCP/SCTP CT
  entry is not established, or unidirectional UDP is awaiting return traffic
  without unidirectional offload enabled. These are excluded from fallback alerts.
- **Unknown:** configuration, capability, path, tuple, or CT evidence is missing,
  ambiguous, stale or incomplete. **Not evaluated** covers non-IP/control paths.

A path need not be fully reconstructed to expose a software stage or provider
failure. The inspector retains its coverage warning. A green path requires all
required evidence; missing CT information never implies CT offload.

Issues require at least three consecutive comparable intervals with increasing
software/partial counters, spanning `--offload-grace` (default 60 seconds,
allowed 30 seconds–10 minutes). Counters from recirculation stages are never
summed: ranking uses the largest stage delta, which can be shared by several
compatible paths. Initial samples, counter resets, changed matches/actions,
provider changes, incomplete flow dumps and collection gaps restart history.
CT-only failures additionally require repeated distinct diagnostic snapshots.
Inactive cached software rules do not create issues. Two minutes without a live
collection makes current health unknown; intervals above two minutes cannot
establish consecutive activity. History is in memory and resets on restart.

## DOCA conntrack

Correlation is local to the node/datapath and keyed by CT zone, protocol, and
exact source/destination addresses and ports. The original/reply tuples and their
reverse forms account for NAT. Masked tuples, missing zones and multiple matching
entries remain unknown; overlapping UDN address spaces are not joined by IP alone.

`orig_offloaded:yes` and `reply_offloaded:yes` are shown independently. A missing
reply flag alone does not prove a failure: a reply-direction path must be observed.
The inspector preserves reply-defer reasons exposed by newer DOCA versions.
Configuration that disables IPv6 CT or leaves global CT capacity zero prevents
an unsupported claim of CT failure. Per-device overrides require further review.

The generic TC/DPDK adapter reports datapath stage evidence. Their conntrack
implementation-specific offload flags are not currently decoded; paths requiring
that evidence remain unknown rather than claiming full offload. DOCA capability
is discovered per node; it is not inferred just from a DPDK datapath.

## API and validation

`GET /api/offload` accepts `node`, `network`, `status`, `search`, `limit` and `id`.
`status=issues` selects persistent issues. `id` includes raw stage/CT evidence;
`node` includes provider/PMD summaries. Authentication is identical to the other
APIs. Snapshot captures include raw offload evidence for offline analysis, but a
single snapshot cannot establish a persistent counter trend.

Go tests cover partial counters, mixed recirculations, setup suppression,
resets/recovery, capability gating, CT directions, NAT, zones, IPv6, stale and
malformed evidence, caching and API bounds. Browser tests exercise filtering,
CT/stage details, issue navigation and mobile layout. All KIND lanes verify that
software-only nodes report disabled without spurious offload issues. The demo
contains explicitly synthetic DOCA evidence. These checks do **not** certify TC
hardware or OVS DOCA on a NIC/DPU; that requires a hardware environment and real
traffic, including deliberate insertion failures and CT pressure.
