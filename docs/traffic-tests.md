# Run a traffic flow test

Open **Hardware Offload → Run traffic test**, or open a traffic link in **Topology** and choose **Run traffic test**. Pick a test type, test case and source node. For a cross-node case, also pick the destination node. A topology link preselects its nodes. You can change either endpoint before clicking **Start test**. Follow running and completed tests in **Traffic test history** on Hardware Offload. The Issues page also shows the three most recent runs. Select a run to open its saved measurements and per-node evidence.

The two pods run in the `ovn-light-tests` namespace on the cluster default network. For a ClusterIP case, the runner also creates a temporary Service that selects only this run’s server. The result shows its virtual IP and the backend pod IP. Policies selecting application pods can differ from those selecting the test pods. The picker uses the test types from the [pinned upstream suite](https://github.com/ovn-kubernetes/kubernetes-traffic-flow-tests/tree/9f911a119c7f3008efca1fff9750985810a34603).

| Test type | What it measures | Available path |
| --- | --- | --- |
| iperf3 TCP | Receiver bytes and bitrate over 120 seconds at a 1 Mbit/s sender target | Pod IP or ClusterIP |
| iperf3 UDP | Receiver bytes, bitrate, packet loss and jitter under the same limit | Pod IP or ClusterIP |
| HTTP response | One request with a verified response body | Pod IP or ClusterIP, IPv4 |
| Simple TCP echo | Bytes echoed and verified over 10 seconds, up to 1 KiB per exchange | Pod IP or ClusterIP, IPv4 |
| Netperf TCP stream | Available TCP throughput during a 5-second stream | Pod IP or ClusterIP |
| Netperf TCP request/response | Completed transactions per second over 5 seconds | Pod IP or ClusterIP |
| RDMA write, read or send bandwidth | Bandwidth over 10 seconds for write/read or 1,000 iterations for send | Device-backed pods using pod IPs |

The default iperf **Connectivity check** targets 1 Mbit/s. A delivery verdict confirms that the selected endpoints exchanged data. To grade bandwidth, select **Throughput check** and enter a minimum in Gbit/s. For iperf you can independently set the sender rate in Mbit/s. The sender rate starts at 1 Mbit/s even when you enter a higher minimum. For example, a 1 Mbit/s sender can exercise a 0.0005 Gbit/s minimum on KIND. A 15 Gbit/s minimum requires a suitably provisioned link and sufficient offered traffic. The runner passes the minimum to the pinned TFT evaluator for the selected case and direction. The result includes the suite’s measured TX and RX values where available. A delivered transfer below threshold is recorded as a failed throughput check, with delivery and evaluator verdict shown separately. HTTP, echo and Netperf request/response do not produce bandwidth verdicts.

Each path supports same-node and different-node placement. The direct cases use `POD_TO_POD_SAME_NODE` and `POD_TO_POD_DIFF_NODE`. Service cases use their `POD_TO_CLUSTER_IP_TO_POD` counterparts. Netperf and RDMA use the available bandwidth. The Netperf runner binds a separate data socket and allows up to 30 seconds for measurement and socket shutdown. RDMA uses direct pod addresses. Only one test runs at a time.

## Install on an existing KIND demo

Use the demo kubeconfig. From the repository root:

```sh
python3 scripts/local-kind-budget.py limit ovn-light-demo
docker build -t ovn-light-tft:9f911a1-v3 runner/traffic-test
kind load docker-image --name ovn-light-demo ovn-light-tft:9f911a1-v3
kubectl --context kind-ovn-light-demo apply -f deploy/traffic-test.yaml
scripts/deploy-kind.sh ovn-light-demo
```

For other clusters, publish the runner image to an accessible registry and set `OVN_LIGHT_TRAFFIC_TEST_IMAGE` in the `ovn-light-traffic-test` ConfigMap before starting the OVN-Light Deployment. If your default OVN network obtains a VF through an extended Kubernetes resource, set `OVN_LIGHT_TRAFFIC_TEST_DEVICE_RESOURCE` to its resource name. Each endpoint requests one device. For RDMA, explicitly configure `OVN_LIGHT_TRAFFIC_TEST_RDMA_RESOURCE` with the RDMA-capable resource exposed on the default network. RDMA tests use that resource on both endpoints and require a working RDMA device, fabric and sufficient locked memory. The picker checks advertised capacity (two devices for the same-node case). The Kubernetes scheduler checks current availability. The runner uses the live server’s write-enabled mode. Removing the runner configuration and restarting OVN-Light disables new runs.

## How to read the result

The DaemonSet uses its usual collection interval. While temporary test pods exist, their nodes include a bounded set of cached OVS rules anchored to each pod’s local datapath port and UID. Open the software, partial-offload, hardware or unknown groups under each node to inspect raw matches, actions and counters. A shared match identifies a test pod port and compatible masked fields. Its counters can include other packets through that rule. The dashboard retains up to 32 distinct flow entries per node per run, including on software-only KIND. Raw lines are limited to 4 KiB. OVN-Light records test pod UIDs and the network, and matches exact pod endpoint tuples in either direction. For iperf it also checks the selected transport, source port 35201 and destination port 5201. For HTTP and echo it checks TCP and the test server port. A Service path can expose the backend tuple after address translation. A short test can finish between samples. For Netperf the collector matches TCP data port 35202 to 5202 and excludes the control socket on port 5201. RDMA has a separate data plane, so its results include the upstream measurement and node status without attributing the TCP control connection to RDMA data. Masked tuples and missing samples can leave a node inconclusive. No hardware evaluation is possible on software-only KIND nodes.

Expand a matched path for individual recirculation IDs, stage states, provider reasons and partial-packet counter deltas. DOCA entries show the zone, observed direction, original and reply offload flags, and any deferred-reply reason supplied by the provider. Deltas may cover shared stages. A persistent issue requires the collector’s usual activity and grace checks. A successful transfer can still contain software stages. If the collector identifies a matching denying ACL, its details accompany the traffic result. [Hardware offload evidence](offload.md)

One fixed Kubernetes Job serializes runs. The Go API accepts a test type, a case, node names and a network. Existing clients that omit the type and case run the original cross-node TCP test. The pinned Python adapter runs one pre-provisioned upstream case in a dedicated namespace. Its ServiceAccount can inspect nodes, create or exec into test pods, and create or read test Services in that namespace. The test pods run without an API token or host mounts. Resource limits and deadlines bound all three pods. The Job owns its endpoint pods and temporary Service. OVN-Light atomically saves the latest 30 runs in its data directory on the server PVC, imports the previous single-result format, and deletes the completed Job and its dependents. The Job TTL also covers interrupted cleanup. Evidence is collected while the server is running; a server interruption can leave gaps.
