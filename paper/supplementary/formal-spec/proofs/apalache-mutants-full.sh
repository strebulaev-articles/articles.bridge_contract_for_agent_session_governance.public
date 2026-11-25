#!/usr/bin/env bash
# Mutation sanity check of the inductive step of BridgeFull.tla: each mutant
# must be rejected (outcome Error). A mutant that is not rejected is a survivor.
# Usage: apalache-mutants-full.sh LOGDIR [NAME-REGEX]
# DRY=1 checks only that every sed expression changes the module (no Docker).
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
log=$(realpath -m "${1:?log dir}"); mkdir -p "$log"
only=${2:-.}
snap=$(mktemp -d); cp "${APALACHE_SRC:-$here}/BridgeFull.tla" "$snap/"
run() { # name, sed expression
  [[ $1 =~ $only ]] || return 0
  d=$(mktemp -d); cp "$snap/BridgeFull.tla" "$d/"; sed -i "$2" "$d/BridgeFull.tla"
  if cmp -s "$snap/BridgeFull.tla" "$d/BridgeFull.tla"; then echo "$1: SED DID NOT APPLY" | tee -a "$log/mutants.txt"; return; fi
  if [ "${DRY:-}" = 1 ]; then echo "$1: applies" | tee -a "$log/mutants.txt"; rm -rf "$d"; return; fi
  start=$(date +%s)
  APALACHE_SRC=$d "$here/run-apalache.sh" BridgeFull.tla check --cinit=CInit \
     --init=IndInit --next=Next --inv=Inv --length=1 > "$log/mutant-$1.log" 2>&1
  echo "$1: $(grep -E 'The outcome' "$log/mutant-$1.log" | sed 's/ *I@.*//') $(grep EXITCODE "$log/mutant-$1.log") $(( $(date +%s) - start )) s" | tee -a "$log/mutants.txt"
  rm -rf "$d" 2>/dev/null || true
}
# --- key lifecycle, attacker, nonce book, timers (from the slice) ---
run revoked-accepted 's/authentic == known \/\\ key \\notin r.rev/authentic == known/'
run nonce-not-spent '0,/!.nu = @ \\cup {claimed}, !.uf = ufn/s//!.uf = ufn/'
run no-book-limit 's/    \/\\ Cardinality(LiveSet(ss)) < LiveLimit/    \/\\ TRUE/'
run adv-key-registered 's/\\E c, d \\in Clients : AddClient(c, d)/\\E c \\in Clients, d \\in Clients \\cup AdvKeys : AddClient(c, d)/;s/^    \/\\ d \\in Clients$/    \/\\ TRUE/'
run det-timer-kept 's/!.recorded = FALSE, !.detLeft = NoTimer,/!.recorded = FALSE,/'
run hard-stays-connected 's/!.n = @ + 2, !.rev = rv, !.hard = hd, !.C = @ \\ {c}/!.n = @ + 2, !.rev = rv, !.hard = hd/'
# --- the nonce is bound to a key id at issue; replay ---
run bound-ignores-good 's/bound == issued \/\\ r.nk\[claimed\] = key \/\\ r.ng\[claimed\]/bound == issued \/\\ r.nk[claimed] = key/'
run bound-ignores-key 's/bound == issued \/\\ r.nk\[claimed\] = key \/\\ r.ng\[claimed\]/bound == issued \/\\ r.ng[claimed]/'
run good-for-unregistered 's/!.ng\[ss.nid + 1\] = (kid \\in ss.K \\ ss.rev)/!.ng[ss.nid + 1] = TRUE/'
run addclient-revives '/^AddClient(c, d) ==/,/last/s/!.K = @ \\cup {d}\]/!.K = @ \\cup {d}, !.ng = [i \\in 1..MaxNonce |-> ss.ng[i] \\\/ ss.nk[i] = d]]/'
run addkey-revives '/^OperatorAddKey(d) ==/,/last/s/!.K = @ \\cup {d}\]/!.K = @ \\cup {d}, !.ng = [i \\in 1..MaxNonce |-> ss.ng[i] \\\/ ss.nk[i] = d]]/'
run refused-keeps-nonce 's/spent == r.nu \\cup (IF known THEN {claimed} ELSE {})/spent == r.nu/'
run challenge-evicts 's/!.nid = @ + 1, !.nb\[ss.nid + 1\] = TNonce,/!.nid = @ + 1, !.nb[ss.nid + 1] = TNonce, !.nu = @ \\cup LiveSet(ss),/'
run challenge-dead-for-unregistered 's/!.nb\[ss.nid + 1\] = TNonce,/!.nb[ss.nid + 1] = IF kid \\in ss.K THEN TNonce ELSE 0,/'
run soft-no-abandon 's/IN IF r.att = "Res" \/\\ r.rk = c$/IN IF r.att = "Res" \/\\ r.rk = c \/\\ why = "compromise"/'
run hard-no-abandon 's/IN IF r.att = "Res" \/\\ r.rk = c$/IN IF r.att = "Res" \/\\ r.rk = c \/\\ why = "rotation"/'
# --- key exhaustion, escalation, timers, termination ---
run add-key-unexhausted '0,/^    \/\\ ss.life = "Active" \/\\ \(~ss.quar \/\\ \)\?ExhR(ss)$/s//    \/\\ ss.life = "Active"/'
run human-timer-kept 's/!.hum = "None", !.humLeft = NoTimer\(\]\|,\)/!.hum = "None"\1/'
run escalate-exhausted '/^Escalate ==/{n;s/Active/Live/}'
run end-without-cause 's/!.life = "Terminated", !.endWhy = why,/!.life = "Terminated",/'
run end-keeps-queue 's/!.queue = {}, !.held = {},$/!.held = {},/'
run end-keeps-timers 's/!.detLeft = NoTimer, !.humLeft = NoTimer,$/!.humLeft = NoTimer,/'
run early-timeout 's/LET d == ss.att = "Det" \/\\ (ss.detLeft = 0 \\\/ ss.totLeft = 0)/LET d == ss.att = "Det"/'
run total-runs-always 's/!.totLeft = IF ss.att = "Det" \/\\ @ > 0/!.totLeft = IF @ > 0/'
run restart-no-record 's/!.rk = "none", !.uf = 0, !.recorded = TRUE, !.n = @ + 3/!.rk = "none", !.uf = 0, !.n = @ + 3/'
run disconnect-no-record '0,/!.detLeft = TDetach, !.recorded = TRUE\]/s//!.detLeft = TDetach]/'
run restart-clears-spent 's/!.rk = "none", !.uf = 0, !.recorded = TRUE/!.rk = "none", !.nu = {}, !.uf = 0, !.recorded = TRUE/'
# --- tool queue, approval, drain, forward, direct calls, scope ---
run drain-ignores-scope 's/\/\\ Need(k) \\in r.scope}/\/\\ TRUE}/'
run drain-ignores-answer 's/\/\\ r.ans\[k\] = "ok"$/\/\\ TRUE/'
run drain-ignores-expiry 's/ok == {k \\in proc : r.callLeft\[k\] > 0/ok == {k \\in proc : TRUE/'
run approval-renewed 's/IF k \\in ss.queue \\ ss.held \/\\ ss.appr\[k\] = NoTimer/IF k \\in ss.queue \\ ss.held/'
run expire-keeps-approval 's/!.callLeft\[k\] = NoTimer, !.appr\[k\] = NoTimer, !.ans\[k\] = "none"\]/!.callLeft[k] = NoTimer, !.ans[k] = "none"]/'
run direct-forwards-out-of-scope 's/LET inscope == Need(k) \\in ss.scope IN/LET inscope == TRUE IN/'
run direct-refusal-unrecorded 's/ELSE ss. = \[ss EXCEPT !.n = @ + 1\]$/ELSE ss'"'"' = ss/'
run forward-after-ack 's/ \/\\ k \\notin ss.dlv \/\\ k \\notin ss.sent/ \/\\ k \\notin ss.sent/'
run forward-undrained '/^Forward(k) ==/{n;s/k \\in ss.drained \/\\ //}'
run forward-while-pending '/^Forward(k) ==/,/^    \/\\ last/{/ss.hum = "None"/d}'
run narrow-widens 's/Active \/\\ ns \\subseteq ss.scope \/\\ ns \/= ss.scope/Active \/\\ ns \/= ss.scope/'
run extend-accepted '/^Extend(ns) ==/,/last/s/!.n = @ + 1\]/!.n = @ + 1, !.scope = ns]/'
run narrow-no-version 's/!.scope = ns, !.ver = @ + 1\]/!.scope = ns]/'
run queue-over-limit '0,/IF Cardinality(ss.queue) < QMax$/s//IF TRUE/'
run drained-stays-queued 's/!.queue = wait,$/!.queue = r.queue,/'
run allowlist-ignored 's/ELSE \/\\ Need(k) \\in Allow$/ELSE \/\\ TRUE/'
run deliver-unforwarded 's/Active \/\\ k \\in ss.fwd \/\\ k \\in ss.drained/Active \/\\ k \\in ss.drained/'
# --- corruption, quarantine, recovery faults ---
run corrupt-resume-accepted 's/    \/\\ IF ss.corrupt$/    \/\\ IF FALSE/'
run quarantine-ticks '0,/IF ss.life = "Terminated" \\\/ ss.quar THEN ss. = ss/s//IF ss.life = "Terminated" THEN ss'"'"' = ss/'
run live-ignores-quarantine 's/^Live == ss.life = "Active" \/\\ ~ss.quar/Live == ss.life = "Active"/'
run corrupt-after-end 's/AllowFaults \/\\ Active \/\\ ~ss.corrupt/AllowFaults \/\\ ~ss.corrupt/'
