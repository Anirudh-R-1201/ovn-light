#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/ci/versions.env
cluster="${1:?Usage: create-cluster.sh cluster-name}"
: "${KUBECONFIG:?Set KUBECONFIG to a dedicated test file}"
mapfile -t clusters < <(kind get clusters)
if [[ -e "$KUBECONFIG" ]] || [[ " ${clusters[*]} " == *" $cluster "* ]]; then
  echo "Refusing to reuse an existing cluster or kubeconfig: $cluster" >&2
  exit 1
fi
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
curl -fsSL --retry 3 "https://codeload.github.com/ovn-kubernetes/ovn-kubernetes/tar.gz/$OVN_REVISION" -o "$work_dir/ovn.tar.gz"
tar -xzf "$work_dir/ovn.tar.gz" -C "$work_dir" --strip-components=1 "ovn-kubernetes-$OVN_REVISION/helm"
docker pull "$OVN_IMAGE"
image_info="$(docker run --rm --entrypoint cat "$OVN_IMAGE" /root/git_info)"
[[ "$image_info" == *"commit: $OVN_REVISION"* ]]
# The chart joins repository and tag with a colon. Load the digest under a local
# tag so the chart uses the exact verified image without changing its templates.
ovn_tag="ovn-light-ci-ovn:$OVN_REVISION"
docker tag "$OVN_IMAGE" "$ovn_tag"
kind create cluster --name "$cluster" --image "$KIND_IMAGE" --config scripts/ci/kind.yaml --kubeconfig "$KUBECONFIG"
kind load docker-image --name "$cluster" "$ovn_tag"
context="kind-$cluster"
kubectl --context "$context" apply -f "https://raw.githubusercontent.com/k8snetworkplumbingwg/multi-networkpolicy/$MULTI_POLICY_VERSION/scheme.yml"
kubectl --context "$context" apply -f "https://raw.githubusercontent.com/k8snetworkplumbingwg/ipamclaims/$IPAMCLAIM_VERSION/artifacts/k8s.cni.cncf.io_ipamclaims.yaml"
curl -fsSL --retry 3 "https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/$MULTUS_VERSION/deployments/multus-daemonset.yml" -o "$work_dir/multus.yaml"
sed -i -e "s|multus-cni:snapshot|multus-cni:$MULTUS_VERSION|g" -e 's|memory: "50Mi"|memory: "200Mi"|g' "$work_dir/multus.yaml"
docker pull "ghcr.io/k8snetworkplumbingwg/multus-cni:$MULTUS_VERSION"
kind load docker-image --name "$cluster" "ghcr.io/k8snetworkplumbingwg/multus-cni:$MULTUS_VERSION"
kubectl --context "$context" apply -f "$work_dir/multus.yaml"
kubectl --context "$context" wait --for=condition=Established --timeout=60s crd/network-attachment-definitions.k8s.cni.cncf.io crd/multi-networkpolicies.k8s.cni.cncf.io crd/ipamclaims.k8s.cni.cncf.io
api_ip="$(kubectl --context "$context" get node "$cluster-control-plane" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
chart="$work_dir/helm/ovn-kubernetes"
helm --kube-context "$context" upgrade --install ovn-kubernetes "$chart" --namespace ovn-kubernetes --create-namespace \
  -f "$chart/values-single-node-zone.yaml" \
  --set "k8sAPIServer=https://$api_ip:6443" \
  --set global.image.repository=ovn-light-ci-ovn --set "global.image.tag=$OVN_REVISION" \
  --set global.image.pullPolicy=IfNotPresent --set global.enableOvnKubeIdentity=false \
  --set global.enableMultiNetwork=true --set global.enableNetworkSegmentation=true \
  --set global.enableNetworkConnect=true --wait --timeout=8m
kubectl --context "$context" wait --for=condition=Ready nodes --all --timeout=180s
kubectl --context "$context" -n kube-system rollout status daemonset/kube-multus-ds --timeout=180s
kubectl --context "$context" -n kube-system rollout status deployment/coredns --timeout=180s
docker pull registry.k8s.io/e2e-test-images/agnhost:2.45
kind load docker-image --name "$cluster" registry.k8s.io/e2e-test-images/agnhost:2.45
