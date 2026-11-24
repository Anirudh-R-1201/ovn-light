#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
cluster="${1:?Usage: test-lane.sh cluster-name lane artifact-directory}"
lane="${2:?Missing lane}"
artifacts="${3:?Missing artifact directory}"
case "$lane" in
  admin|egressip|routing|history) exec scripts/ci/test-infra.sh "$cluster" "$lane" "$artifacts" ;;
esac
context="kind-$cluster"
mkdir -p "$artifacts"
token_file=''
forward_pid=''
external_container=''
extra_args=()
cleanup() {
  [[ -z "$forward_pid" ]] || kill "$forward_pid" 2>/dev/null || true
  [[ -z "$token_file" ]] || rm -f "$token_file"
  [[ -z "$external_container" ]] || docker rm -f "$external_container" >/dev/null
}
trap cleanup EXIT
case "$lane" in
  qos) fixture=qos; namespaces=(ovn-light-qos) ;;
  topology) fixture=topology; namespaces=(ovn-light-topology) ;;
  cdn) fixture=denied-traffic; namespaces=(ovn-light-demo) ;;
  udn) fixture=user-defined-networks; namespaces=(ovn-light-red ovn-light-blue) ;;
  secondary) fixture=secondary-network; namespaces=(ovn-light-secondary) ;;
  egress)
    fixture=egress-firewall; namespaces=(ovn-light-egress)
    external_container="$(docker run -d --name "$cluster-egress-target" --network kind registry.k8s.io/e2e-test-images/agnhost:2.45 netexec --http-port=8080 --udp-port=-1)"
    external_ip="$(docker inspect "$external_container" --format '{{.NetworkSettings.Networks.kind.IPAddress}}')"
    for _attempt in {1..30}; do
      if docker exec "$external_container" /agnhost connect 127.0.0.1:8080 --timeout=1s; then break; fi
      sleep 1
    done
    extra_args=(--external-ip "$external_ip")
    ;;
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
if [[ "$lane" == qos ]]; then
  python3 scripts/e2e-qos.py --url "http://127.0.0.1:$port" --token-file "$token_file" --context "$context" --artifacts "$artifacts"
  exit 0
fi
python3 scripts/e2e.py --lane "$lane" --url "http://127.0.0.1:$port" \
  --token-file "$token_file" --context "$context" --artifacts "$artifacts" "${extra_args[@]}"
