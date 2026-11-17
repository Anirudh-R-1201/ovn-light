#!/usr/bin/env bash
# Collect only test topology and logs; never upload Secrets or kubeconfigs.
set -uo pipefail
cluster="${1:?Usage: diagnostics.sh cluster-name artifact-directory}"
artifacts="${2:?Missing artifact directory}"
mkdir -p "$artifacts"
context="kind-$cluster"
kubectl --context "$context" --request-timeout=15s get nodes -o wide >"$artifacts/nodes.txt" 2>&1
kubectl --context "$context" --request-timeout=15s get pods -A -o wide >"$artifacts/pods.txt" 2>&1
kubectl --context "$context" --request-timeout=15s get events -A --sort-by=.lastTimestamp >"$artifacts/events.txt" 2>&1
for ns in ovn-kubernetes ovn-light ovn-light-demo ovn-light-red ovn-light-blue ovn-light-secondary ovn-light-egress kube-system; do
  while read -r pod; do
    [[ -n "$pod" ]] || continue
    kubectl --context "$context" --request-timeout=20s -n "$ns" logs "$pod" --all-containers --prefix --tail=300 >"$artifacts/$ns-${pod#pod/}.log" 2>&1
  done < <(kubectl --context "$context" --request-timeout=15s -n "$ns" get pods -o name 2>/dev/null)
done
exit 0
