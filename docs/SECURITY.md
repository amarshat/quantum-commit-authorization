# Security findings

Findings from adversarial review, each with an empirical proof-of-concept that
was then kept as a regression test, and the fix folded into the protocol. This
is the single index; the deeper treatment lives in the normative docs linked per
finding. Ordered most recent first.

The pattern here is deliberate: a finding is not considered real until a test
demonstrates it against the actual contract, and not considered closed until the
same test (flipped) passes against the fix.

## F-2026-02 Base account: gas-starvation leaf burn (griefing, high)

**Where.** `contracts/src/CommitRevealAccount.sol`, `reveal`.

**What.** The reveal consumed the leaf and cleared the commitment *before* the
external call, and deliberately swallowed a failed call (reverting would roll the
nullifier back and hand the leaf to whoever saw the calldata). With no bound on
the gas forwarded to the action, anyone who copied a pending reveal's public
calldata could front-run it under a constrained outer gas limit: membership
passed, the leaf was consumed, the action ran out of gas under the EIP-150
63/64 rule and returned false, and the outer transaction still succeeded. The
victim's leaf was permanently burned and the action never ran, for the cost of
one attacker transaction, against the victim's *own* aged commitment, with no
fresh commitment and no censorship. That is cheaper than the threat model's
stated denial path (post and age a competing commitment) and is a distinct
vector from the burn-griefing of [GAME.md](GAME.md) Section 6.

**Fix.** Bind a `callGasLimit` into the commitment; before consuming the leaf,
require that gas remains to forward it under EIP-150; forward exactly that
budget. A starved copy now reverts before any state change, so the leaf
survives; only a caller forwarding the committed budget consumes it. Commitment
preimage and reveal signature both gain the field (paper-1's format changes; see
[SPEC.md](SPEC.md) Commit/Reveal). Propagated to the Rust tooling, golden
vectors, and gas benchmarks.

**Tests.** `contracts/test/PoCGasStarvation.t.sol`:
`test_starvedCopyRevertsAndLeafSurvives` (the attack now reverts, leaf intact)
and `test_honestRevealWithCommittedBudgetStillExecutes` (the committed budget
still executes the action).

## F-2026-01 ERC-4337 account: preVerificationGas deposit drain (theft, high)

**Where.** `contracts/src/QCAAccount4337.sol`, `validateUserOp`.

**What.** The account bound `maxFeePerGas` and `callGasLimit` into the commitment
but not `preVerificationGas`. In ERC-4337 v0.8 `preVerificationGas` is a flat,
bundler-chosen quantity the EntryPoint adds to the gas billed to the account and
pays to the beneficiary, with no protocol ceiling; the account does not read
`userOpHash`, so inflating it does not disturb the commitment recompute. A
malicious bundler inflated it, passed validation, and drained the account's
deposit as profit. The committed fee cap bounds the *price* per gas but not the
*number* of units, so it did not close this. This is exactly the field
[AA.md](AA.md) Lemma 3 predicts in the abstract; the enumeration there had
missed it.

**Measured.** With everything else fixed, raising `preVerificationGas` from 100k
to 5M drained an extra 4,900,000 gas worth of deposit, exactly
`(5,000,000 - 100,000) x gasPrice`, straight to the beneficiary, and the op
still validated and executed.

**Fix.** Bind a `maxPvgCeil` into the commitment and reject any UserOp whose
`preVerificationGas` exceeds it. The cost envelope a bundler can impose is now
bounded on all three axes: fee ceiling, call-gas floor, preVerificationGas
ceiling. See [AA.md](AA.md) "What the commitment binds" and Lemma 3.

**Test.** `contracts/test/QCAAccount4337.t.sol`:
`test_bundlerCannotInflatePreVerificationGasToDrainDeposit` (over-ceiling op
reverts in validation, leaf not consumed, action not executed).
