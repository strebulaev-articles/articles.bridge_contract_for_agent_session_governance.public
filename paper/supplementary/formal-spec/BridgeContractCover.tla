---- MODULE BridgeContractCover ----
\* Reachability probes for the cells of the product machine, used by
\* tlc_coverage.py. Each Probe_* invariant is violated exactly when some
\* session is in that cell, so a violation shows the cell is reached.
EXTENDS BridgeContract

In(s, a, h) == ss[s].life = "Active" /\ ~ss[s].quar /\ ss[s].att = a /\ ss[s].hum = h

Probe_AttNone == \A s \in Sessions : ~In(s, "Att", "None")
Probe_AttPend == \A s \in Sessions : ~In(s, "Att", "Pend")
Probe_DetNone == \A s \in Sessions : ~In(s, "Det", "None")
Probe_DetPend == \A s \in Sessions : ~In(s, "Det", "Pend")
Probe_ResNone == \A s \in Sessions : ~In(s, "Res", "None")
Probe_ResPend == \A s \in Sessions : ~In(s, "Res", "Pend")
Probe_Terminated == \A s \in Sessions : ss[s].life # "Terminated"
Probe_Quarantined == \A s \in Sessions : ~ss[s].quar
\* key_exhausted is a side predicate, not a cell; it is probed like one.
Probe_KeyExhausted == \A s \in Sessions : ~(Live(s) /\ ExhR(ss[s]))
====
