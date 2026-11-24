# Cross-node TCP test

Choose **Run traffic test** in Hardware Offload or in the detail view of a topology link. Select the source and destination nodes and click **Start TCP test**. The dialog shows the current or most recent run. You can close and reopen it while traffic is running.

The test runs the upstream `POD_TO_POD_DIFF_NODE` case with `iperf-tcp`. It creates two temporary pods in `ovn-light-tests` on the selected nodes. One data stream uses TCP source port 35201 and destination port 5201, with a 1 Mbit/s sender target for 120 seconds. The result includes the bytes and bitrate measured by the receiver. Startup and collection add time. This profile uses the cluster default network. Policies selecting application pods can differ from those selecting the test pods. [Pinned upstream test](https://github.com/ovn-kubernetes/kubernetes-traffic-flow-tests/tree/9f911a119c7f3008efca1fff9750985810a34603)

## Install on an existing KIND demo

Use the demo kubeconfig. From the repository root:

```sh
python3 scripts/local-kind-budget.py limit ovn-light-demo
docker build -t ovn-light-tft:9f911a1-v1 runner/traffic-test
kind load docker-image --name ovn-light-demo ovn-light-tft:9f911a1-v1
kubectl --context kind-ovn-light-demo apply -f deploy/traffic-test.yaml
scripts/deploy-kind.sh ovn-light-demo
```

For other clusters, publish the runner image to an accessible registry and set `OVN_LIGHT_TRAFFIC_TEST_IMAGE` in the `ovn-light-traffic-test` ConfigMap before starting the OVN-Light Deployment. If your default OVN network obtains a VF through an extended Kubernetes resource, set `OVN_LIGHT_TRAFFIC_TEST_DEVICE_RESOURCE` to its resource name. Each endpoint requests one device. The runner uses the live server’s write-enabled mode. Removing the runner configuration and restarting OVN-Light disables new runs.

## How to read the result

The DaemonSet uses its usual collection interval. OVN-Light records test pod UIDs and the network, and matches the TCP data tuple in either direction on the two selected nodes. The iperf control connection uses a different source port. Masked tuples and missing samples can leave a node inconclusive. No hardware evaluation is possible on software-only KIND nodes.

Expand a matched path for individual recirculation IDs, stage states, provider reasons and partial-packet counter deltas. DOCA entries show the zone, observed direction, original and reply offload flags, and any deferred-reply reason supplied by the provider. Deltas may cover shared stages. A persistent issue requires the collector’s usual activity and grace checks. A successful transfer can still contain software stages. If the collector identifies a matching denying ACL, its details accompany the traffic result. [Hardware offload evidence](offload.md)

One fixed Kubernetes Job serializes runs. The Go API accepts two node names and a network. The pinned Python adapter runs one pre-provisioned upstream case in a dedicated namespace. Its ServiceAccount can inspect node readiness and create or exec into test pods in that namespace. The test pods run without an API token or host mounts. Resource limits and deadlines bound all three pods. The Job owns its endpoint pods. OVN-Light saves the most recent result in its data directory and deletes the completed Job and its dependents. The Job TTL also covers interrupted cleanup. Evidence is collected while the server is running; a server interruption can leave gaps.
