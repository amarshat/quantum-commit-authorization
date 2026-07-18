# State-management completeness v0.2 (QCA 3 milestone M1)

The dual of paper 1's binding-completeness. [AA.md](AA.md) Lemma 3 asks *what
fields an authorization must bind* so that no reveal-time choice reintroduces
theft. This document asks the successor question for the message-bound
hash-signature account of [SPEC-HASHSIG.md](SPEC-HASHSIG.md): *what state the
signer must maintain, and what an adversary can do to corrupt it.* A
message-bound one-time signature removes the mempool *retargeting* race of the
bearer design (NO-REBIND), but it relocates the security-critical event a second
time, off-chain and one step earlier: a one-time key is catastrophic to sign
twice, and the event "a second signature was produced" is causally prior to, and
invisible to, any on-chain transition.

This is milestone M1: resolve the four open questions of the build plan before
any contract code, define the forcing adversary and the completeness obligation,
and mark exactly which result is proved here versus deferred to the formal model
(M6) and the simulator (M4). It is scoping and analysis; the honest limits and
what M4 must still measure are §10.

**v0.2 changelog (M1 red-team boundary).** Folded formal-verifier, pq-cryptographer,
and mev-adversary. The unconditional safety result survived every attack; the
"priced DoS" framing did not, and is restated as a bounded, mostly-unpriced
residual (§6). The central new content is the impossibility (R1, now proved as a
dichotomy) and the MEV-coupling residual (§4 Q4). Changes are annotated inline.

Notation follows [GAME.md](GAME.md); the crypto is [SPEC-HASHSIG.md](SPEC-HASHSIG.md).

## 1. The forcing adversary

[GAME.md](GAME.md)'s adversary manipulates *transaction inclusion* to open a
theft window on a public secret. The forcing adversary is the same adversary one
layer earlier: it manipulates inclusion (and the wallet's view of it) to *force a
second signature on a one-time key*, or failing that, to *force fresh-key
consumption or liveness delay*. It inherits every GAME.md capability and adds:

- **Reorg(r)**, up to a depth `r` below finality. Honest note, corrected from
  v0.1 (mev finding 1): a depth-1 strand is *not* an expensive event the adversary
  pays for each time. Since the Capella honest-reorg-of-late-blocks rule, a
  proposer with roughly `beta >= 0.2` can reorg a late or weakly-attested block at
  or below zero cost, and MEV-Boost timing games make late blocks common. So the
  reorg channel is close to free for a modest-share proposer, which is exactly why
  the "priced" claim of v0.1 is dropped (§6).
- **Censor-to-window**: withhold an op past its signed `validUntil`
  ([SPEC-HASHSIG.md](SPEC-HASHSIG.md) now binds one; v0.1 did not, so this channel
  was ill-defined, formal F4 / mev F6).
- **Device-partition**: delay or corrupt sync between the owner's devices, or the
  owner's *view of the chain nonce* through a malicious RPC (a sharpened form,
  mev finding 7).
- **Fee-spike**: drive a cost axis above a signed ceiling, forcing a re-sign;
  cheaper on the L2 pubdata/blob axis than on L1 basefee.

Win condition by payoff, not label:

- **Forgery** (catastrophic): two signatures on one leaf, publicly observable,
  then a grind of a signature on an *arbitrary* action. WOTS two-signature forgery
  is ~2^43-46 keccak, classical.
- **Leaf-exhaustion / liveness** (the residual): force fresh-leaf consumption or
  finality-wait delay without ever obtaining a forgery.

The thesis, proved in outline below and measured in M4: under D1-D5 the first
outcome is *unreachable by any inclusion-layer move* (safety is unconditional),
and the residual is bounded but, on the reorg and ordering axes, mostly *not
priced* (and, on MEV-sensitive actions, can be adversary-profitable).

## 2. The key-state machine

Per leaf `i`, tracking the on-chain nullifier and the wallet's local durable
state, because the two can disagree, and the *way* they disagree is the whole
analysis. Two retraction edges, and only one of them is benign:

```
                 wallet reserves i          releases sig over intent
   FRESH ───────────────────────► RESERVED ───────────────────────► SIGNED(public)
   (local free, chain unset)      (local consumed, chain unset)     (local consumed, sig public)
                                        ▲                                  │
                         RESTORE edge   │ (stale-backup / crash rolls       ├── included ─► INCLUDED(chain nullified)
                         deletes local  │  local state back to FRESH,       │                     │ finality
                         consumed bit ──┘  MALIGN: permits a 2nd SIGNED)     │                     ▼
                                                                            │                    FINAL
                                                                            ▼ reorg ≥ inclusion depth
                                                              STRANDED (chain unset, local still consumed, sig public)
```

- **The REORG edge (benign).** Rolls the *chain* back to unset (STRANDED); the
  *local* consumed bit is untouched. The wallet never re-signs leaf `i`; it either
  rebroadcasts the existing signature or advances to a fresh leaf (§4 Q1). No
  second signature on `i`.
- **The RESTORE edge (malign; added in v0.2, formal F3).** A stale-backup restore
  or a crash inside the write-ahead window rolls the *local* consumed bit back to
  FRESH, which permits a *second* `SIGNED(i, ·)` over a different digest. This is
  the *only* edge that produces the forgery precondition (two signatures on one
  leaf). v0.1 drew the reorg edge and omitted this one, which would have made R2
  provable vacuously (the model had no edge reaching the forgery state). The
  restore rate is bounded by `r_max` (FORS few-time absorbs it) and is not an
  adversary capability under D4 (the adversary cannot make a device restore a
  stale backup).

The critical asymmetry: the local consumed bit survives the *reorg* edge but not
the *restore* edge. Safety therefore depends on write-ahead durability (D2)
against restore, not on anything the chain does.

## 3. ONCE-exec vs ONCE-sign vs ONCE-public: the split that organizes everything

Three invariants v1 conflated under "ONCE" (formal F8 added the third):

- **ONCE-exec**: at most one *execution* per leaf per canonical chain.
  On-chain-enforceable; enforced by the permanent nullifier (no reorg) and nonce
  monotonicity within a key (across a reorg; Lemma S1).
- **ONCE-sign**: at most one *signature* ever *produced* per leaf. Off-chain, a
  sufficient proxy for safety that D2 maintains.
- **ONCE-public** (the tight safety target): at most one signature per leaf ever
  becomes *observable by the adversary*. Forgery needs two *public* signatures,
  so a wallet that computes two but broadcasts neither is still safe. ONCE-sign
  implies ONCE-public; ONCE-public is what the forgery actually violates.

Every result here is one observation: **the contract enforces ONCE-exec but not
ONCE-public, and the gap is where the forcing adversary lives.** The nullifier
caps executions at one; it does nothing to cap public signatures. The design
makes ONCE-public hold off-chain (D2), makes its residual violations
non-catastrophic (D5 FORS few-time), and the forcing adversary's inability to
open the gap is the safety theorem.

### R1 (centerpiece): ONCE-public is unenforceable on-chain, as a dichotomy

**Claim.** No predicate evaluable by the account contract can prevent a second
*public* signature on a one-time leaf without either failing to bind the
signature, or gating only execution while the forgery material still forms, or
reintroducing a censorship/liveness race.

*Proof (dichotomy; replaces v0.1's triviality, formal F1).* Suppose an on-chain
mechanism `M` claims to enforce at-most-one-signature. `M` observes only included
transactions. Consider what `M` can gate:

1. *`M` gates signature production directly.* Impossible: producing `sig =
   Sign(sk_i, digest)` needs only `sk_i` and a chosen digest, emits no
   transaction, and can precede or entirely avoid submission (a signature made on
   a partitioned device or a stale-backup restore, broadcast later or never). `M`
   never sees the event it must gate. The contract *can* detect two signatures once
   both are submitted, but detection is *post-catastrophe*: both are already
   public, which is the forgery material. (v0.1 wrongly said "indistinguishable";
   the point is too-late, not indistinguishable.)
2. *`M` binds the message on-chain first (a per-leaf on-chain reservation of the
   message).* Then `M` is commit-reveal: the message is public before the
   signature lands, and [GAME.md](GAME.md) Theorem 1's ordering race returns. `M`
   has not enforced ONCE-sign; it has re-imported the race message-binding exists
   to remove.
3. *`M` gates execution per fresh on-chain challenge (VDF/beacon/staking-slash).*
   Then two signatures over `H(intent, c)` and `H(intent, c')` are still a WOTS
   two-signature forgery; `M` gated executions, not signatures, and the forgery
   material forms regardless. Making the challenge non-reissuable to stop this
   bricks the leaf on a single censored op, a liveness race.

So any `M` lands in (1) cannot-observe, (2) commit-reveal-with-a-race, or (3)
execution-gating-without-signature-prevention (or its liveness-race patch). None
enforces ONCE-public. ∎

This is the analog *in spirit* of paper 1's secrecy premise (an unenforceable
off-chain premise that downgrades a mechanism to a priced residual), but it is a
*new* impossibility with no exact paper-1 twin, and it is stated as the dichotomy,
not as the premise. It is the analysis's central impossibility (Theorem 1).

## 4. The four M1 questions, resolved (with red-team folds)

### Q1. Reorg single-execution (D3 soundness). CONFIRMED, with two corrections.

**Correction A (mev finding 2): rebroadcast, do not burn a leaf, when the intent
is unchanged.** A strand of `op_X` (leaf `i`, nonce key `K`, sequence `s`) does
*not* require a fresh leaf. `op_X`'s signature is already public; after the reorg,
`(K, s)` is valid again and the nullifier is unset, so *rebroadcasting the
existing `op_X`* lands the intended action with no second signature (D2 intact).
Advancing to a fresh leaf `i+1` here burns a scarce leaf for no safety reason and,
because a strand is near-free for the adversary (§1), yields a better-than-1:1
griefing ratio. So the normative wallet rule (reconciling Q1 with Q2) is:
**on a strand or non-inclusion with unchanged intent, rebroadcast the stored
signed op; advance to a fresh leaf only when the intent must change.** The wallet
persists released signatures precisely so it can rebroadcast, which also defeats a
bundler that privately withholds `op_X` (the wallet re-lands it publicly, GAME.md
Theorem 3's re-broadcast precondition).

**When the intent must change**, both `op_X` (stale) and the fresh-leaf `op_X'`
exist, and Lemma S1 governs.

### Lemma S1 (reorg single-execution)

If the intent-changing retry binds the same nonce **key** `K` (and the
chain-current sequence), then of `{op_X on leaf i, op_X' on leaf i+1}` at most one
executes, and no leaf is signed twice.

*Proof.* Both bind key `K`. The per-key sequence is strictly monotone (EntryPoint
`NonceManager`, zkSync `NonceHolder`, base counter): whichever lands first
advances the sequence, and the other fails its nonce check. Distinct leaves, one
signature each, so no forgery material. ∎

**Correction B (formal F2): the 4337 nonce is 2D, and monotonicity is per-key
only.** The v0.1 claim named exactly one failure mode (a local counter). There is
a second, on the primary 4337/zkSync target: if the retry takes a *fresh nonce
key* `K'` (a standard 4337 parallelism pattern, and technically a valid
"chain-current nonce"), then `op_X` at `(K, s)` and `op_X'` at `(K', 0)` are in
independent lanes and *both* execute, a double-spend of the owner's action (or, if
the intent changed, two distinct owner actions when one was wanted). So the
normative rule is stronger than v0.1 stated: the retry MUST reuse the same nonce
**key**, not merely a monotone sequence, and the 2D nonce must not be described as
globally monotone. (Same-key pipelining, signing sequence `s+1` before `s` is
final, is robust: the stranded op and its replacement share `(K, ·)` and
serialize.)

**Three mechanisms, three threats:** WOTS one-timeness + D2 stop *forgery*;
per-key nonce monotonicity stops *reorg double-execution*; the permanent nullifier
stops *post-final re-execution* (a restored wallet re-signing an already-final
leaf executes nothing, because the nullifier survived finality).

**Sim (M4):** add a per-key `Nonce(key, seq)` fact, a reorg-depth event, and a
`nonceKeyPolicy` counter flagging cross-key retries as double-execution; count
"leaf signed twice" (0 under D2) and "both ops executed" (0 under same-key,
positive under the cross-key or local-counter bug). The engine already has the
block loop and builder model; this is a `ReorgModel` plus counters.

### Q2. The finality discipline is off-chain. CONFIRMED (lean-off-chain was right).

The account **cannot** read a finalized anchor in 4337 validation and does not
need to: OP-011 bans `block.number`/`block.timestamp`, the EVM exposes no finality
predicate (EIP-4788 gives the parent beacon *root*, not a finality flag, and
reading a shared contract violates STO-010). So D3(ii) is a wallet discipline:
rebroadcast the stored op if the intent is unchanged (Q1 Correction A; no re-sign,
no wait); produce a signature on a fresh leaf only after the previous attempt is
final-or-dead, and only when the intent must change. The one on-chain lever is
`notBefore`/`validUntil` (EntryPoint wall-clock, now both signed). Sim expresses
this as `retry_delay in {0 (eager), finality_depth (disciplined)}`.

The reshaping observation, unchanged and reinforced: **the finality wait does not
prevent forgery.** Under correct D2 the wallet never re-signs a leaf regardless of
reorg count; the finality wait only trims the fresh-leaf consumption rate and the
restore-accident probability. The load-bearing anti-forgery defense is D2 (local
monotone write-ahead) + WOTS one-timeness + per-key nonce monotonicity. This is
the analysis's load-bearing fact and its honest limit at once (§10).

### Q3. `r_max` is accident-bounded; FIPS-205-256 suffices; default is FORS.

The forcing adversary cannot drive a leaf to two signatures under D2 (Q1, R1), so
`r_max` is set by off-chain restore accidents, realistically `r_max = 2`. Per
[SPEC-HASHSIG.md](SPEC-HASHSIG.md): the recommended default is FORS few-time
`r_max = 2` (WOTS's hard `r_max = 1` does not cover a realistic single accident,
formal F6); custom deep FORS is unnecessary (FIPS-205-256 meets the standalone
`k(a - log2 r_max) >= 256` up to `r_max = 4`); and `>= 256` is the **128-bit
quantum** target (Grover halves the subset-resilience search), not 256 classical.
Honest cost: latency win, gas parity only on the WOTS expert option, gas loss on
the FORS default.

### Q4. The downgrade result is stronger than the q-budget on safety; weaker on pricing than v0.1 hoped.

Ephemeral Keys assumes `r <= q` operationally and never models a forcing
adversary. Our contribution *about* that margin, after the red-team fold:

1. **Safety: the reuse count `r` is bounded below the accident floor by an
   adversary that has no signature-producing move** (R1's dichotomy). This is the
   strong, defensible half: no inclusion-layer trick (reorg, equivocation,
   two-tip, censorship, timing, device-partition) reopens the D2 gate, verified
   from every consensus angle by the mev and formal reviews. It decouples `q` from
   the adversary: `q` need only cover the restore tail, not a worst-case attack.
2. **The ONCE-public impossibility (R1) reframes `q`** from a tunable margin to
   the priced residual of a provably unenforceable invariant.
3. **The residual attack is bounded but mostly *not priced*** (the demotion; §6).

So the result does not reduce to the q-budget; it explains and bounds it. Honest
caveat: piece (1) is close to trivial *given* D2, and the pricing of piece (3)
does not hold on the reorg and ordering axes (§6). The substantive content is the
impossibility (1)/(2) and the MEV-coupling residual (below).

**The MEV-coupling (mev findings 3-4).** After an intent-changing strand, `op_X`
(stale) and `op_X'` (corrected) are both live, non-cancellable bearer instruments
binding key `K`. There is no cancel primitive. An adversarial builder that profits
from the *stale* action simply lands `op_X` and drops `op_X'`: the correction is
denied at single-block-bribe cost, and the attack is *net-negative* for the
adversary whenever `op_X` is MEV-sensitive (GAME.md §4's MEV-on-own-action,
sharpened because the state layer manufactures a second victim-signed op the
adversary gets to select). Prior hash-signature accounts (Ephemeral Keys, Kohaku)
do not model this channel; it is the residual most worth measuring in M4.

## 5. The invariant table and fact structure (for the formal model, M6)

Facts: `!Root(r)`, `!Leaf(i, pk)`, `Reserved(i)` (local, monotone under reorg,
retractable under restore), `Signed(i, digest)`, `Nullified(i)` (chain,
retractable by reorg), `Nonce(key, seq)` (chain, monotone per key), `InMempool`,
`Public(sig)`. Two retraction edges: the **reorg edge** deletes `Nullified` and
lowers `Nonce` for a key but preserves `Reserved`/`Signed`; the **restore edge**
(formal F3) deletes `Reserved(i)`/`Signed(i, ·)` and permits a fresh `Signed`,
rate-bounded by `r_max`.

| # | Invariant / premise | Enforced by | Survives reorg? | Survives restore? |
|---|---|---|---|---|
| I1 | `Signed(i,·)` only after `Reserved(i)` | D2 write-ahead | yes | no (the malign edge) |
| P2 | at most one `Public(sig)` per leaf (premise, ONCE-public) | D2 fail-closed | yes | no, bounded by `r_max` |
| I3 | `Nullified(i)` permanent once FINAL | permanent nullifier | N/A below finality | yes |
| I4 | at most one execution per `Nonce(key, seq)` (per key) | per-key monotonicity | yes | yes |
| I5 | executed action = signed intent | NO-REBIND + read-back + `R` | yes | yes |
| I6 | disjoint leaf ranges per device | D4 KDF domains, distinct `deviceId` | yes | yes |
| I7 | recovery preserves the nullifier set | rotation rule | yes | yes |
| I8 | `Nonce(key)` never rolls back below an already-FINAL op | finality | below finality only | yes |

P2 is a *premise*, not a contract invariant (formal F7): the contract cannot
enforce it (R1). I4 is per-key, not scalar (formal F2). The two central queries:
`reachable(execute(m*) ∧ ¬Signed(·, m*))` is empty (no forgery; needs `R`
for I5's injectivity), and `Signed(i, m1) ∧ Signed(i, m2) ∧ m1 ≠ m2` is reachable
*only via the restore edge* (bounded by `r_max`), never via a reorg or any
adversary move. Computational: WOTS one-time EUF-CMA and FORS `k`-time degradation
under keccak-as-RO, which symbolic Tamarin cannot carry and the hand-proof owns.

## 6. R2: safety unconditional, residual bounded but mostly unpriced

v0.1 stated R2 as "forced forgery downgrades to a *priced* leaf-exhaustion DoS."
The review broke the pricing (mev findings 1-4). Restated as two separate claims:

**R2a (safety, unconditional).** Under D2 + D4, against the full forcing adversary
(reorgs below finality, censorship to `validUntil`, device partition, fee-spike),
the probability of a forged *arbitrary* action is negligible, with **no dependence
on any adversary cost floor**. *Proof.* Forgery needs two public signatures on one
leaf (WOTS one-time EUF-CMA; FORS `k`-time). By R1's dichotomy no on-chain
mechanism and no inclusion-layer adversary move produces a signature; the only
source above one signature is the restore edge, bounded by `r_max` and not an
adversary capability under D4. So the adversary is confined to inclusion
manipulation, which never yields a second signature. ∎ This half survived every
consensus-layer attack in the M1 review; it is the unconditional part of the result.

**R2b (residual, bounded, mostly unpriced).** The residual is a fresh-leaf
consumption / liveness cost, *bounded* (per-device leaf supply `2^d`, and the
finality duration for delay) but **not priced** on the reorg and ordering axes: a
depth-1 strand is near-free for a `beta >= 0.2` proposer (mev finding 1), and the
op-selection channel is a single-block bribe that is net-negative on MEV-sensitive
actions (mev finding 3). The censorship axis *is* priced for an attentive
fee-escalating victim (`q = 1`, GAME.md Remark 8a) but only produces a *leaf
consumption* if `validUntil` lapses; otherwise it is liveness delay. The `2^d`
bound is honest but weak: the operational DoS bites at the *first* forced episode
(a liquidation defense or break-glass denied once), not at exhaustion, so `2^d`
describes when the tree dies, not the harm. With Q1's rebroadcast-don't-burn rule,
reorg strands cost *zero* leaves and only liveness delay, so the relevant measured
quantity (M4) is the delay distribution, not an exhaustion count.

R2b is the paper-1 result shape (theft downgraded to a bounded, mostly-priced
DoS) but weaker on pricing; the M4 measurement, not the theorem, is what decides
whether it is interesting (§10).

## 7. State-management completeness (the obligation, defined)

A message-bound hash-signature account is *state-management complete* against a
forcing adversary if, for every channel by which the adversary can attempt to
force a second *public* signature on a one-time key, some defense reduces the
outcome to an ONCE-exec-preserving liveness/exhaustion residual with no reachable
forgery. Binding-completeness (paper 1) is completeness over the *fields the
signature binds*; this is completeness over the *channels that corrupt the
signer's key state*. One forcing adversary attacks inclusion at both layers
(ordering, key-state); completeness at each is the obligation and the trilogy's
spine.

## 8. The forcing-channel taxonomy (M5 deliverable, previewed)

Each row: channel, defense, attack if absent, and the *honest* residual (v0.2
corrected several mislabels).

| channel | defense | attack if absent | residual |
|---|---|---|---|
| fee-bump past ceiling (L1) | D1 ceiling binding | every bump forces re-sign | in-ceiling bumps free |
| fee-bump past ceiling (L2 pubdata/blob) | D1 + `maxPubdataCeil` | volatile blob fee forces re-sign | soft ceiling; priced re-sign (mev F5) |
| `maxPvgCeil` theft-vs-forcing squeeze | bind PVG ceiling | loose=drain, tight=forced re-sign | structural tension, wallet must choose (mev F5) |
| reorg resurrection | permanent nullifier + Lemma S1 per-key nonce | stranded op + retry both execute | single-exec; reorg near-free, not priced (mev F1) |
| op-selection under shared nonce | (none; inherent) | adversary lands stale op_X, drops correction | single-block bribe, net-negative on MEV (mev F3) |
| bundler withhold + late release | public rebroadcast of stored op | forced leaf burn, ~0 cost | liveness delay under Q1 rule (mev F4) |
| RBF / replacement | D2 fresh-leaf-only-on-intent-change | replacement re-signs same leaf | rebroadcast stored op, no reuse |
| crash / stale-restore | D2 fail-closed + D5 FORS few-time | re-sign consumed leaf → forgery | absorbed to `r_max`, ONCE-exec |
| multi-device concurrency | D4 disjoint KDF ranges, distinct `deviceId` | two devices sign same index → forgery | disjoint by construction |
| nonce-view equivocation (malicious RPC) | read chain nonce from trusted source | feed stale nonce → forced burn / double-exec | trust assumption, new row (mev F7) |
| epoch rotation | permanent hash-keyed nullifier | epoch bitmap resets → resurrection | no bitmap, no resurrection |
| bootstrap front-run | CREATE2 salt = f(root,…) | attacker deploys same address, own root | address binds root |
| intent-digest steering / rebind | secret-keyed `R` | steer FORS indices / collision-rebind | closed by `R` (pq F1) |

M2 builds a PoC test per row (attack fires with the defense removed, closed with
it present); M4 measures the residual column.

## 9. Proved here vs deferred

Proved in outline (M1): R1 as a dichotomy (ONCE-public unenforceable), R2a
(unconditional forgery-impossibility), Lemma S1 with the per-key correction, the
three-way ONCE split, the Q2 off-chain-finality determination, the Q3 parameter
selection. Deferred: the computational forgery bound and R2a in full (M6 Tamarin
with the restore edge + hand-proof); the r/delay/exhaustion distributions and the
finality-latency cost (M4). Recovery is out of M1 scope (formal F9): guardian
root-choice reintroduces the 2^85 axis and the recovery tree's own ONCE-public
discipline is unspecified.

## 10. Honest limits, and what M4 must measure

- **The load-bearing defense is D2 (local monotone write-ahead), not the finality
  discipline D3.** Forgery-impossibility (R2a) follows from D2 + WOTS one-timeness
  + per-key nonce monotonicity, and the finality wait only trims the residual rate.
  D2 is paper 1's write-ahead rule applied to a hash-signature leaf, and every
  contract-side ingredient (hash-keyed nullifier, ceiling binding, nonce
  discipline) is inherited from papers 1-2. The genuinely new content is R1's
  impossibility (proved as the dichotomy, §3) and the MEV-coupling residual
  (§4 Q4), not a new on-chain mechanism.
- **The residual (R2b) is bounded but mostly unpriced.** On the reorg and ordering
  axes it is not priced (a depth-1 strand is near-free for a `beta >= 0.2`
  proposer; op-selection is a single-block bribe, net-negative on MEV-sensitive
  actions); the finality-discipline cost reduces to a wait of roughly one finality
  duration. Whether the residual is a materially interesting cost is an empirical
  question, not a theorem: it is what the M4 simulator must answer.
- **M4 is not built yet.** The forcing-adversary sim needs a reorg edge, a per-key
  nonce, and the restore edge (none of which the current single-leaf `qca-sim`
  has), and must report the r distribution (0 forced forgeries expected), the
  fresh-leaf-consumption / delay distribution under the rebroadcast-don't-burn rule,
  and the MEV-coupling channel's cost on MEV-sensitive actions.
- Recovery is out of scope (§9): a guardian-influenced root reintroduces the 2^85
  adversary-chosen-root axis, and the recovery tree's own ONCE-public discipline is
  unspecified here.
