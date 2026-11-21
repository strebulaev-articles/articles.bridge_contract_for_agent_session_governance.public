#!/usr/bin/env bash
# Run Apalache (Docker) on a module of this directory.
# The image is pinned by digest (Apalache 0.63.0); override with APALACHE_IMAGE.
# Usage: run-apalache.sh MODULE.tla apalache-args...   (e.g. check --init=Inv ...)
# The image runs as an internal user, so work in a world-writable copy.
set -euo pipefail
here=${APALACHE_SRC:-$(cd "$(dirname "$0")" && pwd)}
mod=${1:?module}; shift
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
cp "$here"/*.tla "$here"/*.cfg "$work"/ 2>/dev/null || cp "$here"/*.tla "$work"/
chmod -R a+rwX "$work"
docker run --rm -v "$work":/var/apalache ${APALACHE_IMAGE:-ghcr.io/apalache-mc/apalache@sha256:9ae9b33e01a36c610f2caabc48c10794ad295b0feedebf60dc9f366e1c573199} "$1" "${@:2}" "$mod"
