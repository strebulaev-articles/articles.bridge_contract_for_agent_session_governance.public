#!/usr/bin/env bash
# Run the TLA+ Proof Manager (Docker image tlapm-spike, see Dockerfile.tlapm
# in this directory) on a module of this directory or its parent.
# Usage: run-tlapm.sh MODULE.tla [tlapm args...]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
mod=${1:?module}; shift
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
cp "$here"/*.tla "$here"/../BridgeContract.tla "$work"/
docker run --rm --user "$(id -u):$(id -g)" -v "$work":/w -w /w tlapm-spike tlapm "$@" "$mod"
