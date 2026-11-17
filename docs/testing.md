# Validation

The initial implementation was exercised in a dedicated two-node KIND cluster
named `ovn-light`, using Kubernetes v1.36.4, the locally cached OVN-Kubernetes
release-1.3 image at commit `251895cd534fcdc797a9fdbb7f289a95b63ea4af`, and its
matching release-1.3 Helm chart. The OVS image reports 3.6.2-1.fc43. UDN network
segmentation and ClusterNetworkConnect were enabled. OVN-Light required no
OVN-Kubernetes source edits.

## Checks

- `go test -race ./...` and `go vet ./...`.
- Parser, masks, recirculation compatibility, NAT uncertainty, shared-path
  behavior, resets, policy scope and administrative-policy guards.
- Auth/origin enforcement, strict request decoding, demo write protection,
  persisted plans and immutable API responses.
- A minimized **real** KIND capture in `testdata/kind-denied.json`: reconstructs
  three stages, resolves both pods and the default-deny ACL, and preserves the
  unknown transport port. Its destination is recovered from OpenFlow logical
  outport evidence rather than an invented exact IP match.
- Headless Chrome/Playwright: inspect evidence → generate scoped proposal;
  demo cannot apply; desktop and 390px mobile layout.
- The full live browser flow: token login → observed drop → reviewed proposal →
  acknowledgment → apply → successful TCP verification → rollback, with no
  browser JavaScript errors. Audit history survived deployment restarts.
- Real default-network deny → proposal → admission dry-run → apply → successful
  TCP connection from the original pod → guarded rollback.
- Primary UDN NetworkPolicy proposal → apply → successful TCP verification →
  rollback, using the primary attachment IP rather than `status.podIP`.
- Two primary Layer2 UDNs → reviewed ClusterNetworkConnect → controller
  `Accepted=True` → actual cross-UDN TCP connection → rollback.
- A secondary Layer2 OVN attachment through Multus v4.1.3: observed drop →
  inferred MultiNetworkPolicy and qualified NAD target → admission dry-run →
  apply → secondary TCP success while the same pod's primary connection remains
  denied → rollback → secondary TCP denied again.
- Browser checks for fixed network context, inferred policy type, displayed
  review scope, and secondary-policy apply/rollback. Manual connection reviews
  retain an explicit network picker; unresolved identity never defaults to CDN.
- Policy tests cover primary/secondary separation, shared-network NAD aliases,
  missing capabilities, ambiguous direction defaults, and stale or edited
  `policy-for` targets.

The live tests create only the resources in the example namespaces and the
generated policies/CNC. Applied allowances and CNCs were rolled back. The
example default-deny policies remain so the console can demonstrate the issue.

## Reproduce

For the default-network test, deploy OVN-Light and `examples/denied-traffic.yaml`,
start a port-forward, and run:

```sh
umask 077
kubectl --context kind-ovn -n ovn-light get secret ovn-light-auth \
  -o jsonpath='{.data.token}' | base64 -d > /tmp/ovn-light-token
python3 scripts/kind-smoke.py --token-file /tmp/ovn-light-token --context kind-ovn
rm /tmp/ovn-light-token
```

This script performs real writes in the disposable example namespace and rolls
back its generated policy. It requires kubectl for independent traffic checks
and confirms that denial returns after rollback. Do not point it at an unrelated
application. Both smoke wrappers use the same assertions as CI in `scripts/e2e.py`.

For UDN testing, apply `examples/user-defined-networks.yaml` after enabling OVN
network segmentation. Review client → server on `ovn-light-red/red`, TCP/8080.
The client is idle; run `/agnhost connect <primary-server-IP>:8080 --timeout=2s`
in it to generate a drop. Primary IPs are in `k8s.ovn.org/pod-networks`.
Use Networks → Connect networks for `ovn-light-red/red` and
`ovn-light-blue/blue`, using an unused connect subnet (the isolated test used
`100.100.0.0/16` with prefix 24). Test red/client → blue/server's primary IP
before rolling the CNC back.

## KIND prerequisites

For the secondary-network regression, install Multus and enable OVN
multi-network-policy enforcement, then apply `examples/secondary-network.yaml`.
With the port-forward and token file described above:

```sh
python3 scripts/secondary-smoke.py --token-file /tmp/ovn-light-token \
  --kubeconfig /path/to/kind.kubeconfig
```

This runs real traffic and briefly creates a MultiNetworkPolicy in the example
namespace. It verifies that the primary deny policy continues to block traffic,
then removes its secondary allowance. The built-in Verify button remains limited
to primary networks; secondary tests use the selected attachment's IP directly
in this isolated, non-overlapping test subnet.

A new KIND cluster for OVN needs `disableDefaultCNI: true` and
`kubeProxyMode: none`. Use the OVN-Kubernetes repository's supported KIND setup
for your version. If installing its Helm chart directly, match the chart to
the image and install external NAD, MultiNetworkPolicy and IPAMClaim CRDs when
those features are enabled. These prerequisites are separate from deploying
OVN-Light onto an already functioning cluster.

Hardware offload, OpenShift SCC integration, alternate OVN database layouts,
multi-cluster deployments and production scale are not validated by these tests.

## Continuous integration

The `KIND integration` workflow runs on pushes to `main`, pull requests and manual
dispatch. Each matrix job creates its own two-node KIND cluster with default CNI
and kube-proxy disabled, installs a matching OVN image/Helm chart and Multus,
builds this checkout, and deploys OVN-Light with its normal RBAC and audit PVC.
All jobs use ephemeral clusters and need no repository secrets.

| Lane | Assertions |
| --- | --- |
| `cdn` | Observed policy denial → inferred NetworkPolicy → admission dry-run → API apply → direct TCP and API Verify success → API rollback → denial restored |
| `udn` | The same policy lifecycle on a primary UDN; then ClusterNetworkConnect proposal/apply → Accepted status **and actual cross-UDN TCP success** → rollback restores network separation |
| `secondary` | Observed secondary drop → inferred MultiNetworkPolicy with exact NAD → API apply opens secondary TCP while primary stays denied → rollback restores secondary denial |
| `topology` | Cross-node denial → reviewed allowance → node-level source/receiver rates and resolved receiver pod identities → network filtering and counter deduplication → rollback restores denial |
| `egress` | Attributed external deny and rule index → dry-run leaves firewall unchanged → insert a host-IP TCP allowance before the deny → real external TCP and API Verify succeed → rollback restores denial and preserves firewall UID/rule order |

Every policy lane also checks that TCP/8081 stays denied, dry-run leaves cluster
state unchanged, and rollback preserves existing policies. EgressFirewall restores
the original rules instead of deleting the firewall. Its lane starts a disposable
Docker TCP listener on the KIND node network, outside Kubernetes pod and Service
address ranges; it does not depend on internet endpoint availability. Polls allow bounded controller convergence; failures to
run a probe are not treated as successful denial. The other workflow runs Go race
tests, vet, shell checks and headless Chromium proposal/network-scope tests.

Dependency versions are in `scripts/ci/versions.env`. The OVN image is pinned by
digest and its embedded commit is checked against the downloaded chart. KIND's
node image is also pinned by digest. CLI downloads have checksum verification;
GitHub actions use commit SHAs. Update the OVN chart revision and image together.

To run locally on Linux with Docker, Go, kubectl, KIND, Helm, curl, Python 3 and
OpenSSL installed:

```sh
export KUBECONFIG="$(mktemp -d)/kubeconfig"
export KIND_CLUSTER=ovn-light-ci-local
scripts/ci/create-cluster.sh "$KIND_CLUSTER"
scripts/deploy-kind.sh "$KIND_CLUSTER"
for lane in cdn udn secondary egress topology; do
  scripts/ci/test-lane.sh "$KIND_CLUSTER" "$lane" ".artifacts/$lane"
done
scripts/ci/diagnostics.sh "$KIND_CLUSTER" .artifacts/diagnostics
kind delete cluster --name "$KIND_CLUSTER"
```

Provisioning refuses an existing cluster name or kubeconfig. Local scripts never
delete your cluster automatically. `scripts/ci/install-tools.sh /path/to/bin`
installs the workflow's exact CLI versions for Linux amd64; put that directory on
PATH before provisioning if needed. The host must support the Open vSwitch kernel
module (`sudo modprobe openvswitch`). No hardware offload is enabled in these lanes.

CI always attempts diagnostic collection and cluster cleanup. Seven-day artifacts
contain pod/controller logs, events, and the API's topology and proposal state;
the upload excludes the sibling kubeconfig and temporary authentication token.

## Topology validation

`testdata/kind-topology.json` is a minimized real two-node capture. It exercises
named outputs, packet-length branches and masked sender destinations. Its
regression requires source-node activity and receiver pod identity while keeping
the sender's subnet-wide destination unresolved. Other tests cover independent
source/receiver totals, duplicate counters, shared-counter suppression, resets,
retention/cardinality limits, overlapping networks and collector gaps.

The browser smoke suite checks node links, pod drill-down, UDN filtering,
connection details, and mobile layout. Partial-path checks cover complementary
observations, multiple possible source pods, opposite directions, network
isolation, missing rate history, and keeping unresolved sources unselected in
policy review. The `topology` KIND lane generates real
cross-node traffic using `examples/topology.yaml`, applies an allowance through
the API, observes counters at both nodes, and restores denial through rollback.
A wildcarded receiver drop can require an explicit source choice in the proposal.
Neither the test nor the UI invents that source from a subnet match.

For a local aggregation benchmark:

```sh
go test ./internal/topology -run '^$' -bench BenchmarkTopology -benchmem
```

This measures aggregation of 2,000 synthetic traffic groups over 20 frames, not
large-cluster capture throughput or hardware-offload accuracy.

## Offload diagnostics

`make test` exercises DOCA partial counters, provider failures, CT/NAT/zone
correlation, setup suppression, consecutive activity, reset/recovery, bounded
retention and authenticated queries. `scripts/browser-smoke.cjs` includes
`scripts/browser-offload.cjs` for desktop/mobile filters, stage/CT evidence and
issue navigation. The synthetic demo supplies these cases without hardware.
Each KIND lane also checks `/api/offload`: nodes must report disabled and no
offload issues. Hardware behavior still requires a NIC/DPU test environment;
see [offload diagnostics](offload.md).

## Routing integration lanes

See [routing](routing.md) for the evidence model and runtime permissions. To run a
new disposable cluster with the same feature flags as CI:

```sh
export KUBECONFIG=/tmp/ovn-light-routing-test.kubeconfig
export LANE=routing # admin and egressip are also supported
scripts/ci/create-cluster.sh ovn-light-routing-test
scripts/deploy-kind.sh ovn-light-routing-test
scripts/ci/test-lane.sh ovn-light-routing-test "$LANE" /tmp/ovn-light-routing-artifacts
kind delete cluster --name ovn-light-routing-test
```

Do not point these fixtures at an existing user cluster. They create policy,
EgressIP and RouteAdvertisements resources and alter assignable-node labels.
The routing lane installs pinned FRR-k8s and uses an external Docker FRR peer.
The EgressIP reservation uses a running Docker container with its IPv4 address
removed, keeping the address allocated by Docker without responding to ARP.
Test cleanup removes its EgressIP and external containers; deleting the disposable
cluster removes the remaining Kubernetes fixtures. Snapshot artifacts have routing credentials stripped.
