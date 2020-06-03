#!/usr/bin/env bash
set -euo pipefail

golangci_lint_version="1.23.8"
golangci_lint_sha256="unknown" # set in platform block below

goarch=amd64 # it's 2020
goos="unknown"

if [[ "$OSTYPE" == "linux-gnu" ]]; then
  goos="linux"
  golangci_lint_sha256="9c95f7860cdddff92ba7eb0d765267bb0c868e8a991100b75f4caa8818f92f96"
elif [[ "$OSTYPE" == "darwin"* ]]; then
  goos="darwin"
  golangci_lint_sha256="de309a84af016cc751528361bfa4403a011850ad073585f500ed463b35e66daf"
fi

srcdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." >/dev/null 2>&1 && pwd )"

if [ -f "$srcdir/bin/golangci-lint-${golangci_lint_version}" ]; then
    echo "--> Already downloaded"
    exit 0
fi

workdir=$(mktemp -d)

function cleanup {
  rm -rf "$workdir"
}
trap cleanup EXIT

echo "--> Downloading"
curl -sLo "$workdir/download.tgz" "https://github.com/golangci/golangci-lint/releases/download/v${golangci_lint_version}/golangci-lint-${golangci_lint_version}-${goos}-${goarch}.tar.gz"

echo "--> Unpacking"
cd "$workdir"
tar -zxf "$workdir/download.tgz"
mv golangci-lint*/golangci-lint .

echo "--> Verifying"
echo "$golangci_lint_sha256 *golangci-lint" | shasum -a 256 -c -

mkdir -p "$srcdir/bin"
mv golangci-lint "$srcdir/bin/golangci-lint-${golangci_lint_version}"
echo "--> Fetched bin/golangci-lint-${golangci_lint_version}"
