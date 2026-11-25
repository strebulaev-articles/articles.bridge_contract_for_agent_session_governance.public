#!/usr/bin/env bash
# Inductive check of BridgeFull.tla: base case, inductive step, non-vacuity.
# Usage: apalache-full.sh LOGDIR [INV]   (INV defaults to Inv)
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
log=$(realpath -m "${1:?log dir}"); mkdir -p "$log"
inv=${2:-Inv}
go() { # name, apalache args...
  name=$1; shift
  start=$(date +%s)
  "$here/run-apalache.sh" BridgeFull.tla check --cinit=CInit "$@" > "$log/$name.log" 2>&1
  echo "$name ($inv): $(grep -E 'The outcome' "$log/$name.log" | sed 's/ *I@.*//') $(grep EXITCODE "$log/$name.log") $(( $(date +%s) - start )) s" | tee -a "$log/summary.txt"
}
go base --init=Init --next=Next --inv="$inv" --length=0
go step --init=IndInit --next=Next --inv="$inv" --length=1
# the witness must be violated at length 0 (an Active resuming session with a pending escalation exists)
go witness --init=IndInit --next=Next --inv=Witness --length=0
# the attacker witnesses must be violated at length 1 (the attacker's moves are
# enabled: a replayed signature authenticates and is refused; a request that
# does not authenticate is counted)
go witness-adv --init=IndInit --next=Next --inv=WitnessAdv --length=1
go witness-fail --init=IndInit --next=Next --inv=WitnessFail --length=1
# acceptance and the direct path must be reachable too: both violated at length 1
go witness-accept --init=IndInit --next=Next --inv=WitnessAccept --length=1
go witness-direct --init=IndInit --next=Next --inv=WitnessDirect --length=1
