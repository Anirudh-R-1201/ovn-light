#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cluster="${1:-ovn}"
image="${IMAGE:-ovn-light:dev}"
context="kind-${cluster}"
python3 scripts/local-kind-budget.py limit "$cluster"
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
  export GOMAXPROCS=2
  export GOFLAGS="${GOFLAGS:-} -p=2"
fi
# KUBECONFIG is respected; the script never changes the selected context.
kubectl --context "$context" get namespace ovn-kubernetes >/dev/null
make image IMAGE="$image"
kind load docker-image --name "$cluster" "$image"
kubectl --context "$context" create namespace ovn-light --dry-run=client -o yaml | kubectl --context "$context" apply -f -
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
k=(kubectl --context "$context" -n ovn-light)
if ! "${k[@]}" get secret ovn-light-collector-tls >/dev/null 2>&1; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj '/CN=ovn-light.ovn-light.svc' \
    -addext 'subjectAltName=DNS:ovn-light.ovn-light.svc' -keyout "$tmp/key" -out "$tmp/cert" 2>/dev/null
  "${k[@]}" create secret tls ovn-light-collector-tls --key="$tmp/key" --cert="$tmp/cert"
fi
"${k[@]}" get secret ovn-light-collector-tls -o jsonpath='{.data.tls\.crt}' | base64 -d > "$tmp/ca"
"${k[@]}" create configmap ovn-light-collector-ca --from-file=tls.crt="$tmp/ca" --dry-run=client -o yaml | "${k[@]}" apply -f -
if ! kubectl --context "$context" -n ovn-light get secret ovn-light-auth >/dev/null 2>&1; then
  token_file="$tmp/token"
  openssl rand -hex 32 >"$token_file"
  kubectl --context "$context" -n ovn-light create secret generic ovn-light-auth --from-file=token="$token_file"
fi
# Run the collector with the OVS tools already deployed on these nodes.
tools_image="$(kubectl --context "$context" -n ovn-kubernetes get pods -o jsonpath='{.items[*].spec.containers[?(@.name=="ovnkube-controller")].image}' | awk '{print $1}')"
[[ -n "$tools_image" ]]
cp deploy/ovn-light.yaml "$tmp/"
image_id="$(docker image inspect --format '{{.Id}}' "$image")"
cat > "$tmp/kustomization.yaml" <<EOF
resources:
- ovn-light.yaml
- agent.yaml
images:
- name: ovn-light
  newName: ${image%:*}
  newTag: "${image##*:}"
patches:
- target: {kind: "Deployment|DaemonSet"}
  patch: |-
    - op: add
      path: /spec/template/metadata/annotations
      value: {ovn-light.io/build: "$image_id"}
EOF
awk -v img="$tools_image" '$1 == "image:" && $2 ~ /^ovn-light-ci-ovn:/ {sub($2, img)} {print}' deploy/agent.yaml > "$tmp/agent.yaml"
kubectl --context "$context" apply -k "$tmp"
"${k[@]}" rollout status daemonset/ovn-light-agent --timeout=180s
"${k[@]}" rollout status deployment/ovn-light --timeout=180s
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
