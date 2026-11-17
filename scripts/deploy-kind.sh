#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cluster="${1:-ovn}"
image="${IMAGE:-ovn-light:dev}"
context="kind-${cluster}"
# KUBECONFIG is respected; the script never changes the selected context.
kubectl --context "$context" get namespace ovn-kubernetes >/dev/null
make image IMAGE="$image"
kind load docker-image --name "$cluster" "$image"
kubectl --context "$context" create namespace ovn-light --dry-run=client -o yaml | kubectl --context "$context" apply -f -
if ! kubectl --context "$context" -n ovn-light get secret ovn-light-auth >/dev/null 2>&1; then
  token_file="$(mktemp)"
  trap 'rm -f "$token_file"' EXIT
  openssl rand -hex 32 >"$token_file"
  kubectl --context "$context" -n ovn-light create secret generic ovn-light-auth --from-file=token="$token_file"
fi
kubectl --context "$context" apply -f deploy/ovn-light.yaml
kubectl --context "$context" -n ovn-light set image deployment/ovn-light "ovn-light=$image"
kubectl --context "$context" -n ovn-light rollout restart deployment/ovn-light
kubectl --context "$context" -n ovn-light rollout status deployment/ovn-light --timeout=180s
cat <<EOF
OVN-Light is deployed.
Open a tunnel:
  kubectl --context $context -n ovn-light port-forward service/ovn-light 8080:8080
Retrieve the login token:
  kubectl --context $context -n ovn-light get secret ovn-light-auth -o jsonpath='{.data.token}' | base64 -d
Visit http://localhost:8080
Create the optional denied-traffic example:
  kubectl --context $context apply -f examples/denied-traffic.yaml
EOF
