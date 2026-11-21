#!/usr/bin/env bash
# Derive BridgeContractTP.tla (the model as TLAPS reads it) from BridgeContract.tla.
# Three mechanical changes, nothing else: the module is renamed; TLC is replaced
# by TLAPS and the record merge `@@` (opaque to TLAPS) is defined here with the
# same meaning as in the TLC module; `Permutations` (symmetry, TLC only) goes.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
src=$here/../BridgeContract.tla
sed -e 's/^-* MODULE BridgeContract -*$/---- MODULE BridgeContractTP ----/' \
    -e 's/^EXTENDS Naturals, Integers, FiniteSets, TLC$/EXTENDS Naturals, Integers, FiniteSets, TLAPS\n\n\\* The TLC module'"'"'s f @@ g: g'"'"'s pairs where f has none (defined here, TLAPS has no TLC).\nf @@ g == [x \\in (DOMAIN f) \\cup (DOMAIN g) |-> IF x \\in DOMAIN f THEN f[x] ELSE g[x]]/' \
    -e '/^SessionSym == Permutations(Sessions)$/d' \
    "$src" > "$here/BridgeContractTP.tla"
