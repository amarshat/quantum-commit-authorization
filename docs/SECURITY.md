# Security findings

Findings from adversarial review, each with an empirical proof-of-concept that
was then kept as a regression test, and the fix folded into the protocol. This
is the single index; the deeper treatment lives in the normative docs linked per
finding. Ordered most recent first.

The pattern here is deliberate: a finding is not considered real until a test
demonstrates it against the actual contract, and not considered closed until the
same test (flipped) passes against the fix.

F-2026-03 through F-2026-06 are one red-team pass on the zkSync Era native-AA
account (`contracts-zksync/src/QCAAccountZkSync.sol`). They share a root cause: a
type-`0x71` transaction has no signature over its fields, so binding-completeness
([AA.md](AA.md) Lemma 3) is on the account, and native AA exposes strictly more
sequencer-malleable value-moving fields than the L1 4337 UserOp the first cut was
ported from. See [AA-ZKSYNC.md](AA-ZKSYNC.md) Section 3.

## F-2026-03 zkSync account: unbound paymaster ERC20 seizure (theft, critical)

**Where.** `contracts-zksync/src/QCAAccountZkSync.sol`, `_authorize` /
`prepareForPaymaster`.

**What.** The commitment bound the action and a partial gas envelope but nothing
about `paymaster` / `paymasterInput`, and `prepareForPaymaster` (called by the
bootloader) ran `transaction.processPaymasterInput()` unconditionally. On the
`approvalBased` flow that library call executes `IERC20(token).approve(paymaster,
minAllowance)` in the account's own context, with `token`, `minAllowance`, and
`paymaster` all taken from unauthenticated transaction fields. An attacker copies
any of the account's public reveals, keeps every committed field byte-identical so
validation still passes, and appends `paymaster = self` +
`approvalBased(anyToken, max)`; the account grants an unlimited allowance and every
ERC20 it holds is drained. The victim's own action still runs and the leaf is
consumed once, so it looks like an ordinary reveal. It does not even need the
reveal aged: `prepareForPaymaster` runs before the execution-phase aging check.

**Fix.** This account is never sponsored, so `_authorize` rejects any nonzero
`transaction.paymaster` (and any `factoryDeps`). Validation runs before
`prepareForPaymaster`, so the transaction is rejected before the approval can fire.

**Test.** `contracts-zksync/test/QCAAccountZkSync.t.sol`: `test_paymasterRejected`.

## F-2026-04 zkSync account: unbound gas quantity full-balance drain (theft, high)

**Where.** `contracts-zksync/src/QCAAccountZkSync.sol`, `_authorize`.

**What.** The account capped `maxFeePerGas` (price per gas) but not the *quantity*
of gas: `gasLimit` had no ceiling and `gasPerPubdataByteLimit` (the pubdata-gas
rate) was unbound. A sequencer re-crafts any reveal with `gasLimit = balance /
maxFeeCap` and `gasPerPubdataByteLimit` at the ceiling, prices pubdata at that
rate, refunds nothing, and takes the account's entire ETH balance to the operator.
Unlike the withhold-and-age theft this is unconditional and one-shot: no aging, no
competing commitment. This is the EraVM analog of F-2026-01 (`preVerificationGas`).

**Fix.** Bind `maxGasCeil` and `maxPubdataCeil` into the commitment and reject a
transaction whose `gasLimit` or `gasPerPubdataByteLimit` exceeds them; reject
nonempty `factoryDeps` (pubdata for published bytecode). Fee price, gas quantity,
and pubdata rate are now all bounded.

**Tests.** `test_gasLimitCeilingRejectsInflation`,
`test_pubdataCeilingRejectsInflation`, `test_factoryDepsRejected`.

## F-2026-05 zkSync account: F-2026-02 gas-starvation not ported (griefing, medium)

**Where.** `contracts-zksync/src/QCAAccountZkSync.sol`, `_execute`.

**What.** The base account's F-2026-02 fix was never carried to EraVM. `_execute`
nullified the leaf and then forwarded *all* remaining gas to the action with no
committed budget and no pre-check, so a copy starved of outer gas consumed the
leaf while the action OOG'd and returned false. `callGasFloor` bound the whole-tx
`gasLimit`, not the gas delivered to the inner call, so it guarded the wrong
quantity.

**Fix.** Bind an exact `callGasLimit`; in `_execute`, require
`gasleft() >= callGasLimit + callGasLimit/63 + 40_000` *before* the nullifier
write, then forward `{gas: callGasLimit}`. A starved copy reverts before mutating
state, so the leaf survives.

**Test.** `test_starvedCallDoesNotBurnLeaf`.

## F-2026-06 zkSync account: cross-environment leaf replay (theft, high)

**Where.** All three accounts (base, 4337, zkSync); a deployment invariant, not a
single-contract bug.

**What.** `H(TAG_LEAF, secret)` is byte-identical across the base, 4337, and
zkSync accounts, and each account keeps its own `usedLeaves` set. So one seed
feeding one Merkle tree deployed to more than one account (the natural "wallet
everywhere" setup) is unsafe: a secret revealed on one account opens that same
leaf on every other account holding the same root, once per account. You cannot
share a nullifier set across contracts, so this is not fixable inside one
contract.

**Fix.** The normative rule is **one Merkle tree per account** ([SPEC.md](SPEC.md),
Deployment invariant): never build more than one account from the same
`(seed, tree)`; give each a distinct `index_offset` range so their leaf sets are
disjoint. As defense in depth the zkSync commitment binds an environment domain
tag (`TAG_ENV_ZKSYNC`) so its commitment format is separated from the base and
4337 formats by design, not merely by field arity.

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
