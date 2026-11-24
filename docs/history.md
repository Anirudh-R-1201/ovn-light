# Traffic history with Loki

Open **History**, choose **Yesterday** and **Drops**, and enter a policy name, pod name or IP. Yesterday covers the previous calendar day in the browser’s local time. The network filter accepts an exact network ID, including one that has since been deleted. Choose **Custom range** to narrow a busy interval. The GUI shows the newest 100 matches.

Each record contains the observation time, node, network, known endpoints, transport and counter evidence. Expand a drop to see the denying ACL UUID, action, match and policy metadata available during that collection. A named administrative or EgressFirewall ACL can identify a policy and rule. A namespace default-deny ACL identifies isolation in a direction. OVN-Light saves up to 24 policies that selected the affected pod on that attachment. Multiple selecting policies can jointly isolate the pod. Later changes to Kubernetes objects do not rewrite archived evidence.

Positive deltas describe activity between two counter reads. A populated first read is labeled as a cached baseline because the packets might predate that collection. Shared counters can appear in multiple observations and cannot be summed as separate connections. A conditional output counter measures input to its branch. Expired flows, masked fields, missing reports and hardware counters outside OVS limit what can be recovered. History begins when recording is enabled.

## Enable on the existing two-node KIND demo

Deploy the current OVN-Light build using the normal demo procedure. With its namespace in place, run the following from this repository using the demo kubeconfig.

```sh
kubectl --context kind-ovn-light-demo apply -f deploy/loki-kind.yaml
kubectl --context kind-ovn-light-demo -n ovn-light rollout status deployment/ovn-light-loki
kubectl --context kind-ovn-light-demo -n ovn-light rollout restart deployment/ovn-light
kubectl --context kind-ovn-light-demo -n ovn-light rollout status deployment/ovn-light
```

The manifest configures one single-process Loki pod with a 256 MiB memory limit, one query worker, a 1 GiB volume request and 72-hour retention. The cluster’s default StorageClass provisions the volume. Records survive a Loki pod restart. Removing the KIND node can destroy local storage. The demo uses an internal HTTP service with ingress restricted to OVN-Light server pods in the same namespace. A server rollout may require restarting your dashboard port-forward.

## Use an existing Loki endpoint

The live server reads these environment variables at startup. The Kubernetes Deployment imports the optional `ovn-light-history` ConfigMap in the `ovn-light` namespace. Set the variables there and restart the server Deployment to pick them up.

| Variable | Meaning |
| --- | --- |
| `OVN_LIGHT_LOKI_URL` | Base URL of the Loki service or gateway. Leave unset to disable export and querying. |
| `OVN_LIGHT_LOKI_CLUSTER` | Required with the URL. Choose a unique, stable name per cluster. |
| `OVN_LIGHT_LOKI_TENANT` | Optional tenant sent in `X-Scope-OrgID` for writes and queries. |
| `OVN_LIGHT_LOKI_TOKEN_FILE` | Optional mounted file containing a Loki bearer token. Requires HTTPS. |
| `OVN_LIGHT_LOKI_CA_FILE` | Optional mounted PEM trust bundle for a private CA. Uses system trust when omitted. |

For a secured gateway, mount credentials from a Kubernetes Secret into the server container and grant the token access to push and query the chosen tenant. Browser sessions use the existing OVN-Light login. Retention and durability are configured on the Loki server. To stop recording, remove the URL from the ConfigMap and restart OVN-Light. Existing Loki data remains subject to its retention policy.

## Collection and query limits

Node collectors use their existing reporting path. After analyzing each round, the central server queues gzip-compressed JSON for Loki’s push API. Three stream labels identify job, cluster and verdict. Pod names, IPs, network IDs, rule names and ACL UUIDs are searchable fields in the stored JSON. The archive contains counter evidence and workload metadata. Raw packet payloads and full datapath dumps are excluded. [Loki HTTP API](https://grafana.com/docs/loki/latest/reference/loki-http-api/)

Each round allows up to 1 MiB of record text with a 16 KiB limit per record. Four batches can wait behind the active writer. A full queue, oversized records or a failed export after bounded retries can leave gaps. History reports export omissions since server startup. The queue is in memory and pending data can be lost on shutdown. An empty search alone cannot establish that traffic flowed or that a policy allowed it.

The authenticated `GET /api/history` accepts RFC 3339 `start` and `end`, optional `verdict` (`drop` or `forward`), an exact `network`, case-sensitive literal `search` and a `limit` of 1–200. Filters run in Loki before the result limit. A query spans at most seven days and each server handles up to two concurrent history queries.

To exercise previous-day lookup against a dedicated test Loki, run `OVN_LIGHT_TEST_LOKI_URL=http://127.0.0.1:3100 go test -count=1 -run TestLokiYesterday ./internal/history` with its service port forwarded. The test writes to a separate cluster label and flushes the test instance so the query reads previous-day chunks.
