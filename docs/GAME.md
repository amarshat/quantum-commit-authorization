# The authorization game v0.2

A formal model of the reveal race. [THREAT_MODEL.md](THREAT_MODEL.md) argues
qualitatively that commit-reveal converts a quantum key break into a bounded
censorship race; this document states that claim as a security game with
explicit parameters, proves the bounds the design relies on, and marks
exactly which assumptions each bound consumes. The adversarial simulation
(tooling/qca-sim) measures the same game under the relaxations the proofs do
not cover, and cross-checks every closed-form bound here. Notation follows
[SPEC.md](SPEC.md).

Everything here is per canonical chain, inheriting the reorg caveats of ONCE
and NO-RESURRECT from the spec.

This version (v0.2) folds an adversarial review that found a denial-of-
service the v0.1 model missed entirely: burn-griefing (Section 6). The fix
(age-gating burn) changed the contract and rewrote the recovery theorem, and
surfaced the honest headline of the whole document, an impossibility:
**race-free recovery from a leaked leaf does not exist** (Section 7).

## 1. Parameters

| symbol | meaning |
|---|---|
| `a` | `minCommitAge`, in blocks |
| `T` | `commitTTL`, in blocks |
| `β` | fraction of block production the adversary controls or can bribe per block |
| `q` | probability an honest-built block includes a pending eligible victim transaction |
| `r` | maximum reorg depth the adversary can cause |

## 2. Chain model

Discrete blocks `n = 1, 2, ...`. Each block is built by the adversary with
probability `β`, independently across blocks (the i.i.d. builder lottery).
The adversary chooses the full contents of its own blocks, including
excluding and ordering any transaction. An honest block includes each
pending, eligible, fee-sufficient transaction independently with probability
`q`, and when two mutually exclusive eligible transactions are both pending
in an honest block, their relative order is the builder's choice (modeled in
Section 5). A victim who fee-escalates has `q = 1`; an unattended near-
basefee transaction has `q < 1`. Transactions in the public mempool are
visible to the adversary before inclusion, including full calldata.

**Timing convention.** Within a block the adversary observes the mempool
*before* proposing, but a transaction broadcast during block `n` is first
*eligible for inclusion* in block `n + 1`. So when the victim broadcasts a
reveal observed by the adversary during block `n_1`, both that reveal and any
transaction the adversary derives from it are first includable in `n_1 + 1`.
This is what makes "the adversary's copied transaction cannot land before
`n_1 + 1`" rigorous rather than assumed; it is used throughout Sections 4-6.

The i.i.d. assumption is the model's main simplification. Real builder
markets are concentrated and autocorrelated (the same builder wins runs of
consecutive blocks), which makes censorship cheaper than independence
predicts. The bounds below are the clean-model baseline; the simulator re-
measures them under a Markov builder model whose steady-state share is still
`β` but whose runs are tunable, and confirms that autocorrelation raises
adversary success at equal share.

Fees are ignored in the game itself and return in the economic remark
(Section 8): a censoring adversary must also outbid the victim in every
honest block, which prices the attack.

## 3. Players, oracles, and the leaf state machine

The challenger runs the honest wallet: one account contract with parameters
`(a, T)`, an honest owner V holding the seed. The quantum adversary A gets:

- **Break(pk)**: the classical key behind any observed public key (Shor).
  This is why no property below may rest on the ECDSA envelope.
- **Observe**: the full mempool, in real time.
- **Submit**: arbitrary transactions from arbitrary funded addresses (commit
  and burn are permissionless; nothing authenticates a submitter).
- **Build**: the per-block coin of Section 2; ordering and censorship power
  inside A-built blocks.
- **Reorg(k)**, `k <= r`: replace the last `k` blocks. Used in the leaked-
  leaf analysis; the main race theorem assumes the victim follows the spec's
  operational rule (reveal only against a final commit), which makes `r`
  irrelevant to it by construction.

A cannot invert or find second preimages for keccak256 (Grover leaves
~2^128), and cannot forge Merkle membership. The game adds no cryptographic
assumptions to the spec's list, only scheduling ones. In particular A cannot
predict a secret before its reveal, so A cannot pre-age any commitment (for
theft or for burn) that binds a secret it has not yet seen; this fact is
load-bearing for both Theorem 1 and the burn-griefing fix.

The state machine the game is played on, per leaf (post burn-griefing fix,
so both reveal and burn require an aged commitment):

```
FRESH ──commit c_act─→ COMMITTED ──broadcast reveal─→ EXPOSED
   │                       │                             │
   │                       │ (TTL lapse, no broadcast)   ├─ reveal lands ─→ CONSUMED
   │                       └─→ FRESH (commitment dead,   │
   │                            secret never shown)      └─ commit reorged out,
   │                                                        or TTL lapse after
   │ commit c_burn (aged) + burn                            broadcast ─→ LEAKED-LIVE
   └──────────────────────────────────────┐
                                           ▼
LEAKED-LIVE ──V:  commit c_burn, age a, burn──→ BURNED    (symmetric race, Thm 2)
LEAKED-LIVE ──A:  commit c_theft, age a, reveal──→ CONSUMED (stolen)
```

- **EXPOSED** is entered at broadcast, not inclusion: the secret is public
  the moment the reveal transaction is in the mempool. This is the spec's
  secrecy premise ending, on schedule.
- **LEAKED-LIVE** is the dangerous state: secret public, leaf still usable,
  and, crucially, *nobody holds an aged commitment for it* (the victim's was
  reorged out or expired). It is reachable exactly two ways: the opened
  commitment ceased to exist (reorged out) or ceased to be valid (TTL lapse
  with the reveal unincluded).
- **CONSUMED** and **BURNED** are terminal (ONCE, NO-RESURRECT). Rotation
  maps a leaf of the old tree to unusable *provided that leaf is not also in
  the new tree*; see Section 9 (the categorical v0.1 claim was wrong).

The wallet-side write-ahead rule (record "leaf exposed" before broadcast)
exists because the EXPOSED → LEAKED-LIVE transitions are invisible to a
chain scanner; that is an implementation obligation, not a game move.

## 4. The theft game AUTH-RACE(a, T, β, q)

Setup: challenger deploys the account, V commits `c_V` for action `act_V` on
leaf `i` at block `n_0`, waits until `c_V` is final and aged, and broadcasts
the reveal `ρ_V` at block `n_1 >= n_0 + a` (so `ρ_V` is eligible in `n_1+1`).
A sees `ρ_V` during `n_1`, learning `secret_i`.

**Payoff, not label.** A's move is any set of transactions. Define A's
outcome by its payoff, not by whether the executed action differs from
`act_V`:

- **Theft**: a reveal opening a commitment on leaf `i` for an action A
  chose executes. A profits by the value it redirects.
- **MEV on the victim's own action**: because a reveal is a submitter-
  independent bearer instrument (SPEC known-limitations; THREAT_MODEL
  non-cancellable bearer reveal), A can instead include `ρ_V` itself at an
  A-chosen block and intra-block position. If `act_V` is MEV-sensitive (a
  swap, a liquidation, an auction bid) A can sandwich or backrun it and
  profit *while executing the victim's own action*. Theorem 1 bounds theft;
  it does **not** bound this channel, which is why the win condition is
  stated by payoff. MEV extraction on `act_V` is out of scope for the theft
  bound and is treated as a separate, always-available adversary capability
  the design does not claim to stop for MEV-sensitive actions (the
  mitigation is private self-submission, Section 7).

### Theorem 1 (theft race bound)

For the theft channel, in AUTH-RACE with `q = 1`:

```
β^(a+1)  <=  P(A steals)  <=  β^a
```

*Proof.* A's theft requires executing a reveal `ρ_A` whose commitment `c_A`
is at least `a` blocks old (reveal age check). By the timing convention `c_A`
cannot land before `n_1 + 1`; honest builders include it there as ordinary
spam, so `n_1 + 1` is achievable and, since any later landing only lengthens
the window A must survive, optimal. Building `n_1` to place `c_A` a block
earlier does not help: it still costs A one controlled block and shifts
`ρ_A`'s eligibility in lockstep. So `ρ_A` is first eligible at `n_1 + 1 + a`.

`ρ_V` is eligible in every block from `n_1 + 1`. With `q = 1`, any honest
block in `[n_1 + 1, n_1 + a]` includes `ρ_V`, consuming the leaf (ONCE) and
reverting `ρ_A` on `LeafAlreadyUsed`. So A must build all `a` blocks
`n_1+1 .. n_1+a`, probability `β^a`: the upper bound, a necessary condition.

The bounds differ only at block `n_1 + a + 1`, the first where both reveals
are eligible. If A builds it (further factor `β`, total `β^(a+1)`) A orders
`ρ_A` first and steals; this is a sufficient condition, the lower bound. If
it is honest, both are pending and the builder's ordering decides; the
protocol does not control intra-block order, so the game leaves the tie to
Section 5. Assigning the tie to A gives the upper bound, to V the lower. ∎

`T` does not appear: the victim's TTL constrains her own commitment, not the
attacker's fresh one. `T` bounds a different quantity (how long a griefing or
leaked-leaf window stays open per attacker commitment) and returns in Section
6 and 8.

### Corollary 1a (passive victim)

With honest-block inclusion probability `q < 1`, replacing "any honest block
includes `ρ_V`" by an independent `q` per honest block gives

```
P(A steals) <= (β + (1 - β)(1 - q))^a
```

At `q = 1` the bracket is `β` and the bound is `β^a` (Theorem 1). At `q = 0`
the bracket is `1` and the bound is `1`: an unattended reveal is protected
only by the builder lottery, and P(A steals) → 1. Worked values, both at
`β = 0.5, a = 4`: at `q = 1`, `0.5^4 = 6.25%`; at `q = 0`, `100%`. (v0.1
mislabeled the 6.25% figure as the `q = 0` case; it is the `q = 1` case.)

## 5. The tie block, and why it is measured not proved

Theorem 1's gap between `β^a` and `β^(a+1)` is exactly the disposition of the
one honest block where victim and attacker reveals are both eligible. Under a
priority-fee auction the winner is whoever bids more, which couples to the
value at stake and the victim's fee policy. The simulator models the tie with
a parameter (`TieRule`) whose two settings reproduce the two bracket edges
exactly (a cross-check the test suite asserts), and is where an empirical
auction model will slot in. No closed-form claim is made about the tie; the
document brackets it and measures inside.

## 6. Burn-griefing, and the fix

**The v0.1 hole.** The original `burn(leafIndex, secret, proof)` had no age
gate: membership plus unused, nothing else. Its inputs are a strict subset of
a reveal's calldata. So the instant `ρ_V` is in the public mempool, any
observer reconstructs `burn(...)` and submits it. If the burn is ordered
before `ρ_V`, the leaf is nullified and `ρ_V` reverts `LeafAlreadyUsed`. No
funds move, but the action is denied and V must restart the whole two-phase
flow on a fresh leaf, where A repeats it.

Quantify against this same model, `q = 1`. Denial needs the burn to win a
single block against `ρ_V`, so it succeeds with probability `β` (A builds
`n_1+1`) versus theft's `β^a`. For `β = 0.5, a = 4`: **50% denial per
attempt** versus 6.25% theft, and it needs *no censorship window at all*.
Worse, rotation is a revealed action (SPEC), so the break-glass response to
seed compromise is itself burn-griefable: recovery can be denied
indefinitely at `β` per attempt. The v0.1 Lemma 4 ("every adversarial action
except the races has cost-to-attacker exceeding cost-imposed") was simply
false; the state machine even drew the `EXPOSED → BURNED` transition that the
game theory never let A take.

**The fix (implemented).** Burn now opens its own aged, unexpired
commitment, exactly like reveal, domain-separated by `TAG_BURN`:

```
c_burn = H(TAG_COMMIT, chainid, account, TAG_BURN, leafIndex, secret)
```

Since A only learns `secret_i` when `ρ_V` is broadcast, and cannot pre-age a
commitment binding a secret it has not seen (Section 3), A's copied burn is
not immediately eligible; it must age `a` blocks while V's already-aged
`ρ_V` is eligible now. So on a healthy EXPOSED leaf the griefing burn is
demoted to the same `β^a` censorship race as theft (Theorem 1 applies to the
burn as an attack transaction just as it does to `ρ_A`). The one-block denial
is closed.

### Lemma 4' (griefing costs, corrected)

After the fix, on a healthy EXPOSED or COMMITTED leaf (V holds a valid aged
commitment), any attacker transaction that would nullify or steal the leaf
requires an aged commitment and is bounded by Theorem 1 at `β^a`. Commit and
burn commitments each cost their submitter one storage write and impose no
verification cost on others (single-key lookup), and first-write-wins means
neither can reset or displace a victim's commitment. The residual griefing
surface is the LEAKED-LIVE path of Section 7 (force expiry, then race), whose
cost is Section 8's censorship budget over the window, and MEV on `act_V`
(Section 4), which age-gating does not touch. No sub-`β^a` denial of a
healthy leaf survives the fix. ∎

## 7. Recovery is a race, and race-free recovery is impossible

### Theorem 2 (burn recovery is symmetric)

Suppose leaf `i` is LEAKED-LIVE: secret public, leaf live, and no party holds
an aged commitment (V's was reorged out or expired). Both V (to burn) and A
(to steal) must now commit and age `a` blocks; both commitments land in the
next block. From block-1+a onward the two eligible transactions race with no
head start for either side. Hence, with `q = 1`,

```
β  <=  P(A steals)  <=  1
```

the lower edge when V wins every ordering tie (A steals only by building the
first eligible block), the upper when A wins every tie. *Proof:* identical
window structure to Theorem 1 but with V's aging advantage removed, so the
protective exponent collapses from `a` to a single first-eligible-block
race. The simulator reproduces both edges (`β` and ~`1`) exactly. ∎

Burn still helps: without it, a LEAKED-LIVE leaf is lost with probability → 1
(A commits and takes it; honest builders even include the theft reveal, since
it is valid and fee-sufficient, and nothing races it). Burn converts certain
loss into a coin flip V influences with fees. But it is strictly weaker than
the `β^a` theft bound, and that gap is the price of having closed burn-
griefing.

### Theorem 2' (impossibility of race-free recovery)

No modification of the contract can give the honest holder a race-free
nullification of a leaked leaf without simultaneously giving it to an
attacker. *Proof.* In LEAKED-LIVE the only distinguishing knowledge between V
and A is possession of `secret_i`, which by definition both have. Any on-
chain predicate that admits V's nullification therefore admits A's, and any
predicate that gates it (an aged commitment, a fee, a delay) gates both
symmetrically. Hence recovery is at best the symmetric race of Theorem 2. The
v0.1 "race-free burn" achieved race-freeness only by being open to A too,
which is exactly the burn-griefing DoS. ∎

This is the document's headline result, and it is a positive contribution
framed as an impossibility: in this class of scheme you may have race-free
recovery or DoS-resistance, never both, so a correct design must choose DoS-
resistance (age-gated burn) and treat leaked-leaf recovery as a race to be
avoided, not won. The operational consequence is the spec's rule: do not
enter LEAKED-LIVE, i.e. do not broadcast a reveal until its commit is final.

### Theorem 3 (relay capitulation, with its precondition)

If `ρ_V` is disclosed to any party P before public broadcast (relayer,
bundler, private order flow) **and V is passive for at least `a` blocks after
the handoff**, P steals the leaf with probability 1: P holds the only copy of
`ρ_V`, commits `c_P`, ages `a` blocks while withholding `ρ_V`, and reveals.
The passivity precondition is necessary and was missing in v0.1: V generated
`secret_i` and can reconstruct and publicly broadcast `ρ_V` at any time, so
an attentive V who detects non-inclusion and re-broadcasts before `c_P` ages
(within `a` blocks) turns P's theft back into the Theorem 1 race. The
conclusion is unchanged: self-submit, or relay only through a party trusted
with the account's funds. ∎

## 8. The trilemma, and the economic remark

Sections 4-7 combine into one operational statement, which is the real
takeaway and was scattered across the documents in v0.1:

> A public-mempool reveal is both theft-raceable (`β^a`, Theorem 1) and, on
> the LEAKED-LIVE path, recovery-raceable (`β`-to-`1`, Theorem 2); private
> self-submission avoids both by never exposing the secret to a racing
> adversary, but reintroduces Theorem 3's relay-capitulation trust the moment
> the private channel is a third party. There is no configuration that is
> simultaneously public, race-free, and trustless.

### Remark 8a (censorship is priced; not a theorem)

For A to "win" an honest block in any of these windows it must displace the
victim's escalated transaction, i.e. outbid or bribe at her priority fee.
A rational victim bidding a fraction of the value at stake makes A's expected
cost grow with the window while success shrinks geometrically in the head-
start case (Theorem 1) and stays a single-block bribe in the recovery case
(Theorem 2). This is a qualitative remark, deliberately not labeled a
theorem: it has no formalized bid or builder-response model. The simulator
owns the quantitative version, joining censorship attempts to the benchmark
report's basefee break-even distribution. (v0.1 called this a corollary; it
was never one.)

## 9. What is proved vs measured, and honest limits

Proved, under i.i.d. builders and the stated `q`: the theft race bound
(Theorem 1) and its exponent, the passive-victim degradation (1a), the burn-
griefing fix demotion to `β^a` (Lemma 4'), the symmetric recovery race
(Theorem 2), recovery-race impossibility (2'), relay capitulation with its
precondition (Theorem 3).

Measured by qca-sim, each relaxing one assumption:

1. The tie block under real priority-fee auctions (Section 5): the `β^a` vs
   `β^(a+1)` gap, and the `β` vs `1` recovery gap.
2. Autocorrelated, concentrated builders vs the i.i.d. coin: empirical
   `P(steal)` over `(a, β)`, which is what sizing `minCommitAge` needs.
3. Fee-spike interaction: joint distribution of censorship and basefee moves
   between commit and reveal (the benchmark's break-even multiple `m` as a
   distribution, not a bound).
4. Reorg-path frequencies: how often EXPOSED → LEAKED-LIVE occurs at
   realistic reorg rates, and end-to-end loss with vs without the burn
   response (the Theorem 2 coin-flip in aggregate).
5. Commit- and burn-spam economics at scale (Lemma 4' constants under real
   gas and state-growth pricing).

Honest limits of the model:

- Blocks are the time unit; intra-block frontrunning is compressed into
  Section 5. PBS, relay games, and inclusion lists are folded into the single
  `β`, a deliberate flattening the simulator re-inflates via the Markov
  model. An AFT/FC reviewer should accept `β` as a baseline *given* the
  theorems do not overclaim, which after this revision they do not.
- `q` treats fee sufficiency as exogenous; really `q` is a function of the
  victim's fee policy and congestion (money). Remark 8a gestures at the
  coupling; the simulator owns it.
- The game analyzes one leaf. Cross-leaf strategies (grief one leaf to force
  rotation, then race the rotation flow) do **not** all reduce to the single-
  leaf game: the rotation leaf is deniable by the Section 6 mechanism, which
  before the fix was `β` and after it is `β^a`, so the reduction that v0.1
  asserted understated the pre-fix adversary. Post-fix the reduction holds;
  it remains a simulator scenario, not a proof.
- Rotation makes an old-tree leaf unusable only if that leaf is absent from
  the new tree. The commitment binds `(chainid, account, actionHash,
  leafIndex, secret)` but **not** the root, so a non-consumed leaf present in
  both trees keeps a valid commitment across rotation. Disjointness is a
  tooling obligation (`index_offset`), not a contract guarantee; NO-RESURRECT
  across rotation is conditional on it. (v0.1 stated this categorically and
  was wrong.)
- Finality is assumed for `c_V` in Theorem 1 by operational rule. Theorem 2
  is exactly the analysis of that rule being violated or unavailable.
