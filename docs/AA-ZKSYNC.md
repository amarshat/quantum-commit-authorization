# Commit-reveal on zkSync Era native account abstraction v0.1

[AA.md](AA.md) proves that on Ethereum L1 no account has an ECDSA-free
authorization-and-inclusion path: ERC-4337 only relocates the envelope from the
owner to a bundler. The one architecture that removes it, native account
abstraction, is not on L1 but is live on some L2s. This document is the L2
existence proof: the commit-reveal account built as a zkSync Era native-AA
account (`contracts-zksync/src/QCAAccountZkSync.sol`), where the account's
authorization path has no elliptic-curve assumption and no ECDSA envelope. It
also states the price of getting there, which is the real contribution, in two
parts. First, native AA does not make the account safer than the L1 4337
version; it moves the front-running risk of the aging window onto whoever builds
the block, which on zkSync Era today is a single sequencer with no honest relay
to switch to (a monopoly relay), and the only fallback is a coarse, operator-
defeatable L1 priority-queue force-include. That is a sharper form of the base
scheme's relay-capitulation theorem than the 4337 case, though not the trivially
"strongest possible" one. Second, and less obvious, the zero-ECDSA move
*enlarges the binding-completeness burden*: an ECDSA signature covers the whole
transaction hash for free, but a commit-reveal account must enumerate every
consequential field explicitly, and a native-AA transaction exposes strictly
more sequencer-malleable value-moving fields than an L1 4337 UserOp (paymaster,
pubdata rate, factoryDeps, an uncapped gas quantity). Getting that enumeration
wrong is a full-balance theft, not the front-running race the paper concedes;
Section 3 and [SECURITY.md](SECURITY.md) record the fields and the fixes.

## 1. Zero ECDSA, for real

A zkSync transaction of type `0x71` from a smart account is validated only by
that account's `validateTransaction`, which must return the magic value
`ACCOUNT_VALIDATION_SUCCESS_MAGIC` (`= IAccount.validateTransaction.selector`).
There is no protocol-level secp256k1 check; the `signature` field is opaque
bytes the account interprets as it likes, and ours carries the reveal material
(leaf index, secret, Merkle proof, and the committed gas-envelope bounds), not a
signature. So the account authorizes with hash preimages end to end, no ECDSA
anywhere in its authorization or in the L2 inclusion path.

Residual ECDSA lives in separate trust domains, and the paper must name them
rather than imply they are gone: the operator's batch and proof submission to
Ethereum L1 (settlement) is an ordinary ECDSA transaction; the censorship escape
hatch (force-inclusion via the L1 priority queue) is an ECDSA L1 transaction
that also republishes the reveal in Ethereum's public mempool; and a default
zkSync EOA is the `DefaultAccount` system contract, which does verify secp256k1,
which is exactly what our custom account replaces.

## 2. Design: aging moves to execution

zkSync's validation rules keep the 4337 forbidden-opcode set relevant, so
`validateTransaction` may not read `block.timestamp` or `block.number`, and
unlike 4337 there is no EntryPoint to hand a `validAfter` range to. So the
account splits the base scheme's reveal across the two native-AA phases:

- **validateTransaction** does the time-independent work: it increments the
  nonce (via the `NonceHolder` system contract), verifies Merkle membership,
  enforces the full native-AA envelope binding (Section 3: reject any paymaster
  and any `factoryDeps`; `maxFeePerGas <= maxFeeCap`; `gasLimit <= maxGasCeil`;
  `gasPerPubdataByteLimit <= maxPubdataCeil`; and the exact-budget `callGasLimit`,
  all bound into the commitment), and checks that a matching commitment exists.
  It returns the magic value.
- **executeTransaction** does the time-dependent work: it re-derives the
  commitment, reads its post timestamp, and enforces `minCommitAge` and
  `commitTTL` against `block.timestamp`. The leaf is nullified strictly after
  the aging check and before the external call.

That nullification order is a deliberate correctness point. On zkSync a reverted
`executeTransaction` still includes the transaction and still charges fees, and
validation-phase state writes persist. If the leaf were nullified in validation
(as on L1, where the EntryPoint's `validAfter` gate rejects a too-young reveal
before execution), then on zkSync a too-young reveal would be included, pass
validation, revert on aging in execution, and yet leave the leaf consumed, a
free griefing burn. Nullifying after the aging check in execution instead means
a premature reveal reverts without consuming the leaf (it leaks the secret,
recoverable via `burn`, exactly as in the base scheme), while an aged reveal
consumes the leaf even if the action itself reverts. The forge test
`test_tooYoungRevertsWithoutBurningLeaf` pins this.

This is a genuine regression from 4337, and the paper should not call it "exactly
as in the base scheme." On L1 4337 the EntryPoint's `validAfter` gate rejects a
too-young UserOp in simulation, so a premature reveal never lands on-chain and
its secret is never published. Here validation is time-blind, so a sequencer that
sees a not-yet-aged reveal can force-include it purely to publish the secret,
resetting the aging race to "the attacker now knows the secret" at will. The leaf
survives (correctly), but the secret is public, so a too-young reveal is a
public-secret event and `minCommitAge` guidance must treat it as one.

Aging is wall-clock here, as on L1 4337, but the timestamp lever is worse on
zkSync and the paper must say so. On L1 the proposer rotates block to block, so
the party that could back-date a commit is usually not the one that forward-dates
the reveal. On zkSync a single sequencer sets every L2 block timestamp across the
whole withhold-and-age window, so the same party that front-runs also holds the
clock the aging check reads, bounded only by the L2-vs-L1 batch-timestamp
constraint. `minCommitAge` in seconds must carry a margin above that full drift
bound, not just above block time.

## 3. The sequencer is the relay, and this is the result

zkSync Era runs a **private mempool behind a single sequencer**. There is no
public peer-to-peer L2 mempool. A user submits the reveal transaction to the
sequencer's RPC, and that one party sees the secret and the Merkle proof before
inclusion, with full ordering and inclusion discretion.

**The front-running side (the cost).** A party that privately sees the reveal can
open its own commitment binding a competing action to the leaf, withhold the
victim's reveal (it controls inclusion), age its own commitment, and reveal for
theft. Against a *passive* victim this is theft with probability 1, which is the
base scheme's relay-capitulation theorem (GAME.md Theorem 3) instantiated. The
precise sense in which zkSync is worse than 4337 is not "no fallback," it is a
**monopoly relay**: in 4337 the effective censoring share is the fraction of
usable bundlers that collude and a victim can switch bundlers or self-bundle, so
the relay share is below 1; on zkSync Era there is exactly one sequencer and no
honest relay to switch to, so the relay share is 1. Both give probability-1 theft
against a passive victim; the difference lives entirely in the fallback.

And there is a fallback, so the doc must not claim otherwise: zkSync Era's L1
priority queue (`BridgeHub.requestL2TransactionDirect`) lets an attentive victim
force-include the reveal, wrapped as a call to `executeTransactionFromOutside`.
It is a *coarse* fallback. There is no protocol-enforced inclusion deadline; absent
a `TransactionFilterer` the sequencer cannot selectively drop one priority op, so
to keep withholding for the full `minCommitAge` it must halt the entire priority
queue for everyone, a chain-wide, publicly visible liveness action rather than a
silent theft; but the operator *can* deploy a `TransactionFilterer` and censor the
victim's force-include selectively with no delay, and can also let an attacker
FIFO-stuff the queue to push the reveal past `commitTTL`. (There is no Exodus-mode
escape hatch on Era; the priority-expiration mechanism that search surfaces is
zkSync Lite, not Era.) So the honest verdict: theft is probability 1 against a
passive victim and a monopoly relay, and an attentive victim's only recourse is a
coarse, operator-defeatable L1 force-include. That is a raw trust assumption in
the sequencer and a first-class limitation.

**The private-mempool side (the gain, and the paper leaves it on the table if it
omits this).** The same private mempool that makes the sequencer all-powerful also
narrows the front-running set to *exactly one party*. Every adversary that is not
the sequencer, a competing MEV searcher, a burn-griefer, and specifically a
CRQC-equipped attacker, sees the reveal only once it is already included on-chain,
at which point the leaf is consumed and the secret is worthless. So the entire
GAME.md public-mempool attack surface (the `beta^a` theft race, burn-griefing, MEV
sandwiching of the reveal) collapses against everyone except the one sequencer you
must now trust. Relative to the L1 base scheme, where the reveal is exposed to the
whole mempool, native AA on a private-mempool L2 closes the mempool-theft window
against all parties but one. That isolation is what makes "trust the sequencer" a
clean, single open problem rather than a diffuse risk.

**Binding-completeness on EraVM (the second result, and the real engineering
content).** A type-`0x71` transaction carries no signature over its fields, so the
sequencer can set every field the account does not itself check. An ECDSA account
gets completeness for free; a commit-reveal account must enumerate. The first cut
of this account ported the L1 4337 envelope (a fee cap and a call-gas bound) and
missed the fields native AA adds, exactly the class of miss that left
`preVerificationGas` open on 4337 (SECURITY.md F-2026-01). A red-team pass found
four:

1. **Paymaster (full ERC20 theft).** `prepareForPaymaster` runs
   `processPaymasterInput` unconditionally, and on the `approvalBased` flow that
   makes the account execute `IERC20(token).approve(paymaster, max)` with
   `token`/`paymaster` attacker-chosen. An attacker copies any of the account's
   public reveals, keeps every committed field byte-identical so validation still
   passes, and appends `paymaster = self`, draining every ERC20 the account holds.
   This account is never sponsored, so validation now rejects any nonzero
   paymaster (`test_paymasterRejected`).
2. **Gas quantity (full ETH drain).** The fee cap bounds price per gas, not the
   number of gas units. `gasLimit` had no ceiling and `gasPerpubdataByteLimit`
   (the pubdata-gas rate) was unbound, so a sequencer sets `gasLimit = balance /
   maxFeeCap`, prices pubdata at the ceiling, refunds nothing, and takes the
   account's whole ETH balance, unconditionally and with no aging. Both are now
   bound as committed ceilings (`test_gasLimitCeilingRejectsInflation`,
   `test_pubdataCeilingRejectsInflation`); `factoryDeps` (pubdata for published
   bytecode) is rejected outright (`test_factoryDepsRejected`). These are the
   EraVM analogs of the 4337 `preVerificationGas` drain.
3. **Forced leaf burn.** The base account's F-2026-02 fix (check the committed
   call budget is available *before* nullifying, then forward exactly that budget)
   was not ported: `_execute` nullified then forwarded all remaining gas, so a
   copy starved of outer gas burned the leaf with no action. Now the account binds
   an exact `callGasLimit`, guards `gasleft()` before the nullifier write, and
   forwards `{gas: callGasLimit}` (`test_starvedCallDoesNotBurnLeaf`).
4. **Cross-environment replay.** `H(TAG_LEAF, secret)` is byte-identical across
   the base, 4337, and zkSync accounts, so one seed feeding one tree deployed to
   several accounts is unsafe: a secret revealed on one account opens that leaf on
   every other account holding the same root, since nullifier sets are per-
   contract. This is not fixable inside one contract (you cannot share a nullifier
   set across contracts). The normative rule is **one tree per account** (SPEC.md);
   as defense in depth the zkSync commitment now binds an environment domain tag
   (`TAG_ENV_ZKSYNC`) so its format is separated by design, not by field arity.

With those closed, the gas-envelope binding does close the over-charge, paymaster,
and starvation surfaces; what it cannot do is make the sequencer include the
victim's reveal. That residual is the trust assumption above, not a binding gap.

Sequencer decentralization (multi-node/consensus block production, based-rollup
ordering, staking) changes the picture but is not a strict improvement. Based
sequencing removes the monopoly relay (the relay share drops below 1, no single
party can withhold-and-age with certainty), but it does so by moving ordering to
the L1 public mempool, which re-exposes the reveal to every observer and reinstates
the full public-mempool surface this L2 construction just closed. So it trades
sequencer-monopoly theft for the classic `beta^a` public-mempool race. Closing the
window *without* re-publicizing the reveal looks to need encrypted mempools or
threshold ordering. That is a clean open problem, and it is the paper's
forward-looking contribution.

## 4. Status and measurement

The account compiles for EraVM (zksolc 1.5.15) and its authorization logic
passes forge tests on the zkSync VM (the execute path, the aging-in-execute leaf
preservation, and the two gas-envelope bindings). Those tests do not run the
bootloader, so the full validation path (nonce increment via the `NonceHolder`
system contract) is exercised separately, end to end on anvil-zksync, by
`contracts-zksync/bench/measure_zksync.sh`. That harness deploys the account via
`createAccount`, funds it, posts a commit, advances chain time past
`minCommitAge`, and sends the reveal as a real type-`0x71` transaction whose
`customSignature` carries the reveal material. Every reveal returns status 1, so
the zero-ECDSA path validates and executes on a real node, not just in a unit
test. Receipts are committed in `bench/results/qca-zksync-receipts.json`.

One build requirement fell out of this and is worth recording, because the unit
tests hide it: the `NonceHolder` call in validation goes through
`SystemContractsCaller`, which only compiles to a real EraVM system call when the
project is built with eravm extensions on (`enable_eravm_extensions = true` in
`foundry.toml`). Without it the trampoline is emitted as a plain call to an empty
address and validation halts with "no function selector available." The forge
`--zksync` VM never runs that path, so the flag is invisible until a live node
executes validation.

Gas is not comparable to the L1 numbers and must not be presented as if it were:
zkSync meters an ergs-derived charge that folds in the pubdata cost of the
transaction's state diff, at a floating pubdata-to-gas rate. So the receipt
`gasUsed` here (depth-16 authorization-only reveal ~158.7K, +1 ETH action
~175.4K, commit ~130.5K, growing ~840 per tree level) is reported for scaling and
as the existence proof, not as a like-for-like cost against L1.

The one meaningful in-platform comparison is against the ECDSA account it
replaces. A zkSync EOA is the `DefaultAccount` system contract, which verifies
secp256k1 in its own validation, so a plain signed transfer is the cost of an
ECDSA account authorizing the same action: 118.7K (0-value) and 126.8K (1 ETH) in
these runs. Two ratios, and the paper must quote both. The single reveal is 1.34x
and 1.38x those. But authorizing one action with commit-reveal is fundamentally
*two* transactions, the commit and the reveal, so the true per-authorization cost
against ECDSA's one transaction is about **2.4x** (commit + reveal). Leading with
the 1.3x reveal-only number and burying the commit would overstate the result.

Both ratios are a floor, not a mainnet figure: anvil-zksync prices pubdata at a
fixed low `gasPerPubdata` (168 here), and the reveal publishes an extra nullifier
state diff that a plain transfer does not, so on mainnet, where `gasPerPubdata`
floats up with the L1 basefee, the multiple rises. The exact reproduction of these
digits is likewise a property of the emulator's fixed fee model, not a chain
constant. So the bounded-and-honest claim is: authorization with no ECDSA anywhere
on the path costs a small constant multiple of an ordinary signed transaction on a
live native-AA platform, and the exact multiple is a function of L1 pubdata price.
Still separable for a later pass: splitting the charge into execution gas versus
pubdata bytes and an end-to-end ETH cost at a stated `gasPerPubdata`, and a real
Era Sepolia deployment to replace the emulator's fixed rate. See
`bench/results/RESULTS.md`.

One platform caveat to date-stamp: native EraVM account abstraction is on a
deprecation path (ZKsync OS, the go-forward VM, is EVM-based and uses ERC-4337).
The existence proof stands for zkSync Era as of this writing; Starknet is a more
durable native-AA platform for a follow-up.
