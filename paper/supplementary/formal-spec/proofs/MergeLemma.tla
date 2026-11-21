------------------------------ MODULE MergeLemma ------------------------------
(***************************************************************************)
(* TLAPS spike: can the record merge used by Step (f @@ g in the TLC       *)
(* module, opaque to TLAPS) be reasoned about once it is defined?          *)
(***************************************************************************)
EXTENDS Naturals, TLAPS

Merge(f, g) == [x \in (DOMAIN f) \cup (DOMAIN g) |-> IF x \in DOMAIN f THEN f[x] ELSE g[x]]

CONSTANT Perms, Fields

\* The shape of Step: ([n |-> r.n + k] merged with u) merged with r.
LEMMA StepKeeps ==
  ASSUME NEW r, NEW k \in Nat, NEW u,
         r = [x \in Fields |-> r[x]], "n" \in Fields, r["n"] \in Nat,
         "scope" \in Fields, r["scope"] \subseteq Perms,
         DOMAIN u \subseteq Fields,
         "scope" \in DOMAIN u => u["scope"] \subseteq Perms
  PROVE  LET r2 == Merge(Merge([n |-> r["n"] + k], u), r)
         IN  /\ DOMAIN r2 = Fields
             /\ r2["scope"] \subseteq Perms
             /\ r2["n"] \in Nat
PROOF
  <1> DEFINE m1 == Merge([n |-> r["n"] + k], u)
  <1> DEFINE r2 == Merge(m1, r)
  <1>1. DOMAIN m1 = {"n"} \cup DOMAIN u
    BY DEF Merge
  <1>2. DOMAIN r2 = Fields
    BY <1>1 DEF Merge
  <1>3. r2["scope"] \subseteq Perms
    BY <1>1, <1>2 DEF Merge
  <1>4. r2["n"] \in Nat
    BY <1>1, <1>2 DEF Merge
  <1> QED BY <1>2, <1>3, <1>4

=============================================================================
