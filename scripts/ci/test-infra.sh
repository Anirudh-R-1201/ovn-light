#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/ci/versions.env
cluster="${1:?Missing cluster}"
lane="${2:?Missing lane}"
artifacts="${3:?Missing artifact directory}"
context="kind-$cluster"
mkdir -p "$artifacts"
work_dir="$(mktemp -d)"
forward_pid=''
containers=()
cleanup() {
  if [[ -n "${egress_ip:-}" ]]; then
    kubectl --context "$context" --request-timeout=15s delete egressip ovn-light-egress --ignore-not-found --wait=true >/dev/null || true
  fi
  [[ -z "$forward_pid" ]] || kill "$forward_pid" 2>/dev/null || true
  for container in "${containers[@]}"; do docker rm -f "$container" >/dev/null || true; done
  rm -rf "$work_dir"
}
trap cleanup EXIT
extra=()
if [[ "$lane" == egressip || "$lane" == routing ]]; then
  # Docker retains this allocated address while the running container has no IP.
  # This prevents other local KIND tests from allocating our EgressIP.
  reserve="$cluster-eip-reserve"
  containers+=("$reserve")
  docker run -d --name "$reserve" --network kind --cap-add NET_ADMIN --entrypoint /bin/sh registry.k8s.io/e2e-test-images/agnhost:2.45 -c 'ip -4 addr flush dev eth0; sleep 3600' >/dev/null
  egress_ip="$(docker inspect "$reserve" --format '{{.NetworkSettings.Networks.kind.IPAddress}}')"
  listener="$cluster-infra-listener"
  containers+=("$listener")
  docker run -d --name "$listener" --network kind registry.k8s.io/e2e-test-images/agnhost:2.45 netexec --http-port=8080 --udp-port=-1 >/dev/null
  external_ip="$(docker inspect "$listener" --format '{{.NetworkSettings.Networks.kind.IPAddress}}')"
  extra+=(--egress-ip "$egress_ip" --external-ip "$external_ip")
fi
if [[ "$lane" == routing ]]; then
  kubectl --context "$context" -n frr-k8s-system rollout status daemonset/frr-k8s-daemon --timeout=180s
  kubectl --context "$context" apply -f deploy/frr-reader.yaml
  mkdir -p "$work_dir/peer"
  mapfile -t node_ips < <(kubectl --context "$context" get nodes -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}')
  {
    echo 'frr defaults traditional'
    echo 'hostname ovn-light-test-peer'
    echo 'router bgp 64513'
    echo ' bgp router-id 192.0.2.1'
    echo ' no bgp ebgp-requires-policy'
    for ip in "${node_ips[@]}"; do echo " neighbor $ip remote-as 64512"; done
  } >"$work_dir/peer/frr.conf"
  printf 'zebra=yes\nbgpd=yes\nvtysh_enable=yes\n' >"$work_dir/peer/daemons"
  peer="$cluster-bgp-peer"
  containers+=("$peer")
  docker run -d --name "$peer" --network kind --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    -v "$work_dir/peer:/test-input:ro,Z" --entrypoint /bin/sh "$FRR_IMAGE" -c \
    'set -e; cp /test-input/frr.conf /test-input/daemons /etc/frr/; touch /etc/frr/vtysh.conf; chown frr:frr /etc/frr/frr.conf /etc/frr/daemons /etc/frr/vtysh.conf; exec /usr/lib/frr/docker-start' >/dev/null
  peer_ip="$(docker inspect "$peer" --format '{{.NetworkSettings.Networks.kind.IPAddress}}')"
  extra+=(--peer-ip "$peer_ip" --peer-container "$peer")
fi
kubectl --context "$context" -n ovn-light get secret ovn-light-auth -o jsonpath='{.data.token}' | base64 -d >"$work_dir/token"
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
python3 scripts/e2e-infra.py --lane "$lane" --url "http://127.0.0.1:$port" --token-file "$work_dir/token" \
  --context "$context" --artifacts "$artifacts" "${extra[@]}"
