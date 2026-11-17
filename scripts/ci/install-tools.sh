#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/ci/versions.env
tools_dir="${1:?Usage: install-tools.sh /path/to/bin}"
mkdir -p "$tools_dir"
tools_dir="$(realpath "$tools_dir")"
download_dir="$(mktemp -d)"
trap 'rm -rf "$download_dir"' EXIT
cd "$download_dir"
curl -fsSL --retry 3 "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-linux-amd64" -o kind-linux-amd64
curl -fsSL --retry 3 "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-linux-amd64.sha256sum" -o kind.sha256
sha256sum --check kind.sha256
install -m 755 kind-linux-amd64 "$tools_dir/kind"
curl -fsSL --retry 3 "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl" -o kubectl
curl -fsSL --retry 3 "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl.sha256" -o kubectl.sha256
printf '%s  kubectl\n' "$(cat kubectl.sha256)" | sha256sum --check
install -m 755 kubectl "$tools_dir/kubectl"
curl -fsSL --retry 3 "https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz" -o helm.tar.gz
curl -fsSL --retry 3 "https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz.sha256sum" -o helm.sha256
printf '%s  helm.tar.gz\n' "$(cut -d ' ' -f 1 helm.sha256)" | sha256sum --check
tar -xzf helm.tar.gz
install -m 755 linux-amd64/helm "$tools_dir/helm"
