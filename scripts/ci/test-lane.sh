#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
cluster="${1:?Usage: test-lane.sh cluster-name cdn|udn|secondary artifact-directory}"
lane="${2:?Missing lane}"
artifacts="${3:?Missing artifact directory}"
context="kind-$cluster"
mkdir -p "$artifacts"
case "$lane" in
  cdn) fixture=denied-traffic; namespaces=(ovn-light-demo) ;;
  udn) fixture=user-defined-networks; namespaces=(ovn-light-red ovn-light-blue) ;;
  secondary) fixture=secondary-network; namespaces=(ovn-light-secondary) ;;
  *) echo "Unknown lane: $lane" >&2; exit 1 ;;
esac
kubectl --context "$context" apply -f "examples/$fixture.yaml"
for ns in "${namespaces[@]}"; do
  # Deployments may not have created their pods when kubectl apply returns.
  for _attempt in {1..60}; do
    if [[ -n "$(kubectl --context "$context" -n "$ns" get pods -o name)" ]]; then break; fi
    sleep 1
  done
  kubectl --context "$context" -n "$ns" wait pods --all --for=condition=Ready --timeout=180s
done
token_file="$(mktemp)"
forward_pid=''
cleanup() {
  [[ -z "$forward_pid" ]] || kill "$forward_pid" 2>/dev/null || true
  rm -f "$token_file"
}
trap cleanup EXIT
kubectl --context "$context" -n ovn-light get secret ovn-light-auth -o jsonpath='{.data.token}' | base64 -d >"$token_file"
# Let the OS pick a free localhost port, including when several lanes run locally.
kubectl --context "$context" -n ovn-light port-forward service/ovn-light :8080 >"$artifacts/port-forward.log" 2>&1 &
forward_pid=$!
port=''
for _attempt in {1..60}; do
  port="$(sed -n 's/.*127\.0\.0\.1:\([0-9]*\) ->.*/\1/p' "$artifacts/port-forward.log" | head -1)"
  if [[ -n "$port" ]] && curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null; then break; fi
  kill -0 "$forward_pid"
  sleep 1
done
[[ -n "$port" ]]
python3 scripts/e2e.py --lane "$lane" --url "http://127.0.0.1:$port" \
  --token-file "$token_file" --context "$context" --artifacts "$artifacts"
