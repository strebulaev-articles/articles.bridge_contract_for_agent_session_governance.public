#!/usr/bin/env bash
# Mutation sanity check of the inductive step: each mutant must be rejected.
# Usage: apalache-mutants.sh LOGDIR
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
log=$(realpath -m "${1:?log dir}"); mkdir -p "$log"
run() { # name, sed expression
  d=$(mktemp -d); cp "$here/BridgeSlice.tla" "$d/"; sed -i "$2" "$d/BridgeSlice.tla"
  if cmp -s "$here/BridgeSlice.tla" "$d/BridgeSlice.tla"; then echo "$1: SED DID NOT APPLY" | tee -a "$log/mutants.txt"; return; fi
  APALACHE_SRC=$d "$here/run-apalache.sh" BridgeSlice.tla check --cinit=CInit \
     --init=IndInit --next=Next --inv=Inv --length=1 > "$log/mutant-$1.log" 2>&1
  echo "$1: $(grep -E 'EXITCODE|The outcome' "$log/mutant-$1.log" | tr '\n' ' ')" | tee -a "$log/mutants.txt"
  rm -rf "$d" 2>/dev/null || true
}
: > "$log/mutants.txt"
# a revoked key is accepted at re-attach
run revoked-accepted 's/authentic == known \/\\ key \\notin r.rev/authentic == known/'
# a nonce is not marked spent on join
run nonce-not-spent '0,/!.nu = @ \\cup {claimed}, !.uf = ufn/s//!.uf = ufn/'
# the challenge ignores the live-nonce limit
run no-book-limit 's/    \/\\ Cardinality(LiveSet(ss)) < LiveLimit/    \/\\ TRUE/'
# the attacker may register a key of its own
run adv-key-registered 's/\\E c, d \\in Clients : AddClient(c, d)/\\E c \\in Clients, d \\in Clients \\cup AdvKeys : AddClient(c, d)/;s/^    \/\\ d \\in Clients$/    \/\\ TRUE/'
# a re-attach does not stop the detach timer
run det-timer-kept 's/!.recorded = FALSE, !.detLeft = NoTimer,/!.recorded = FALSE,/'
# a hard revocation leaves the key connected
run hard-stays-connected 's/!.n = @ + 2, !.rev = rv, !.hard = hd, !.C = @ \\ {c}/!.n = @ + 2, !.rev = rv, !.hard = hd/'
