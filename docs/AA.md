# Commit-reveal under account abstraction v0.2

[SPEC.md](SPEC.md) authorizes an account by hash-based commit-reveal instead of
a signature, and [GAME.md](GAME.md) proves that authorization degrades a
quantum key break to a bounded censorship race. Both have one stated gap: on
today's Ethereum the reveal transaction is carried in an ECDSA-signed envelope
(the sender and gas payer is an ECDSA EOA), which a quantum adversary can
break. This document asks whether native account abstraction closes that gap,
and answers precisely: it does not, and cannot, on post-Pectra L1 mainnet. What
it does do is relocate the ECDSA envelope from the owner's EOA to a bundler's,
and in doing so it exposes the revealed secret to that bundler. The value of
this document is (1) a theorem that no account on current L1 mainnet has an
ECDSA-free authorization path (native AA removes it, and is already live on some
L2s), and (2) a precise account of what that bundler can do: with the action,
the fee ceiling, and the call-gas floor all bound into the commitment, a
bundler that sees the reveal only in the public mempool is limited to
censorship; but the default single-bundler path, where the reveal is handed to
one bundler privately, is relay capitulation, i.e. deterministic theft, exactly
the base scheme's Theorem 3. Survivability is real but conditional, and this
document states the conditions rather than assuming them.

## 1. The four inclusion paths

An account authorized by commit-reveal must still get its reveal included in a
block. On post-Pectra L1 mainnet (mid-2026) every path to inclusion terminates
in an ECDSA-signed transaction:

1. **EIP-7702 (delegated EOA).** The account is an EOA that has set its code to
   commit-reveal logic. But the 7702 authorization tuple is a secp256k1
   signature by the EOA key, the key remains authoritative for the account's
   whole life, and it can submit a fresh authorization at any time to
   re-delegate or clear the delegation. A quantum adversary who recovers the
   key re-points the account at its own code, bypassing commit-reveal entirely.
   7702 enshrines ECDSA as the root of trust rather than removing it.
2. **EIP-4337, self-bundled.** The owner calls `EntryPoint.handleOps` directly.
   That outer call is a transaction, which must be signed by some key; if it is
   an EOA, ECDSA is back at the root, and the reveal secret is in the public
   mempool.
3. **EIP-4337, via a bundler.** A third-party bundler calls `handleOps`. The
   bundler's transaction is ECDSA-signed, and the bundler sees the UserOp, hence
   the revealed secret, before inclusion. ECDSA is relocated to the bundler's
   envelope, not eliminated; a new exposure (Section 4) appears.
4. **Native account abstraction (EIP-7701 / RIP-7560).** A protocol-level AA
   transaction type validated by the account's own logic, with no bundler EOA
   and no ECDSA envelope at the protocol level. This is the only architecture
   that removes ECDSA end to end. It is **not shipped on Ethereum L1 mainnet
   and has no fork slot there.** It is, however, live on some L2s: zkSync Era
   has run native account abstraction on mainnet since 2023 (every account is a
   contract, validated by the protocol via the account's own logic in the
   bootloader, transaction type 0x71, no secp256k1 envelope), and RIP-7560 is
   in testing. So the theorem below is an L1 statement, and L2s with native AA
   are where the end-to-end construction is already deployable.

### Theorem 1 (no ECDSA-free account on L1 mainnet)

On post-Pectra Ethereum **L1** mainnet there is no account whose authorization
and inclusion path is free of a secp256k1 signature.

*Proof.* Inclusion requires an L1 transaction. Every L1 EIP-2718 transaction
type available post-Pectra (legacy, 2930, 1559, 4844, and the 7702 set-code
type) carries a secp256k1 signature over its origin: an externally owned
account signs its transaction by construction, and a 7702-delegated EOA's
delegation is itself secp256k1-signed and revocable by the same key (path 1).
A 4337 UserOp is not a transaction; it must be wrapped by an
`EntryPoint.handleOps` transaction, whose origin is one of the above (paths 2,
3), and paymaster sponsorship, gasless relays, meta-transactions, and a
contract acting as bundler all still bottom out at an ECDSA `tx.origin`. The
only escape is a transaction type whose validity is not gated by a secp256k1
signature, i.e. native AA (path 4), which does not exist on L1. Hence every L1
inclusion path contains a secp256k1 signature. ∎

The L1 scope is essential: on an L2 with native AA (zkSync Era) the same
construction has no ECDSA anywhere, which is exactly why native AA is the
target architecture and the L2 deployment is the end-to-end existence proof.

The consequence for our scheme is exact: 4337 moves the ECDSA envelope from the
owner's own EOA (the base scheme's stated limitation) to a bundler's EOA. This
is a real improvement, because the owner no longer needs a quantum-vulnerable
key of their own to spend, but it is not elimination, and it is contingent on
native AA to complete. We state this rather than imply 4337 solves the envelope.

## 2. The 4337 construction

We implement commit-reveal as an ERC-4337 v0.8 account
(`contracts/src/QCAAccount4337.sol`). Authorization lives entirely in
`validateUserOp`: the reveal material (leaf index, secret, Merkle proof) is
carried in `userOp.signature`, and the action is `userOp.callData`. Validation
recomputes the commitment from the action and secret, checks it exists, and
hands the aging and expiry gates to the EntryPoint as a time range.

Two ERC-7562 validation rules shape the design, and both are honored:

- **STO-010 (own-storage reads).** Validation may read any slot of the account's
  own storage for an arbitrary key, but not an arbitrary slot of a shared
  contract. So the `commitments` mapping, keyed by an arbitrary commitment hash,
  must live in the account itself, not in a shared registry. It does.
- **OP-011 (banned opcodes).** Validation may not read `block.number` or
  `block.timestamp`. The aging check `now >= commitTime + minCommitAge` is
  therefore not evaluated in validation; instead the commitment stores its
  post time and validation returns `validAfter = commitTime + minCommitAge`,
  which the EntryPoint enforces outside the banned-opcode scope.

Two more rules bear on adversary analysis, not just construction:

- Writing the account's own storage in validation (the nullifier set,
  clearing the commitment) is permitted by STO-010 too, read *and* write, with
  no staking requirement; the account stays an unstaked entity. But a write in
  validation means one op invalidates sibling ops of the same account in the
  mempool (a second reveal for the same leaf becomes invalid), so bundlers drop
  them, which is a mempool-drop censorship surface (Section 4), not a rule
  violation.
- Emitting the nullifier event in validation (so a scanning wallet can
  reconstruct consumed leaves, matching the base scheme's write-ahead recovery)
  uses LOG, which is not banned. The base scheme's event-scan recovery would
  otherwise be lost on the 4337 path.

### Semantic change: aging is now wall-clock

Because validation cannot read block numbers, the commitment stores
`block.timestamp` and the aging parameter is in seconds, not blocks. The
anti-front-running argument of [GAME.md](GAME.md) is unchanged in structure (an
adversary who extracts the secret still needs their own commitment to age the
full window while the victim's is already aged), but the window is measured in
time, not block height. Two consequences a paper must carry: a fixed wall-clock
window spans a variable number of blocks, so the effective `a` in `beta^a`
varies with block time; and `block.timestamp` is proposer-set within consensus
drift, so a proposer can back-date the stored `committedAt` and forward-date the
reveal block to shave up to about twice the drift tolerance off the real aging
window. `minCommitAge` (seconds) must therefore carry a margin well above both
the block time and the consensus timestamp tolerance. This is a real difference
from the base scheme, not cosmetic, and is the price of the 4337 validation
rules.

## 3. Binding, and the limits of survivability

The construction binds, into the commitment, everything a bundler could
otherwise choose at reveal time to its own advantage:

- **The action.** Validation requires
  `callData = execute.selector || abi.encode(target, value, data)`, recomputes
  the action hash from exactly those fields, and the EntryPoint executes that
  same `callData`. Authorized action and executed action are byte-identical.
- **The fee ceiling.** The commitment binds a `maxFeeCap`, and validation
  rejects any UserOp whose `maxFeePerGas` exceeds it. Without this, a bundler
  replays the reveal with `maxFeePerGas` set astronomically; the EntryPoint
  charges `actualGas * effectiveGasPrice` from the account's deposit and pays it
  to the bundler as fees, draining the deposit. That is theft, not griefing, and
  it is closed only by binding the fee ceiling.
- **The call-gas floor.** The commitment binds a `callGasFloor`, and validation
  rejects any UserOp whose `callGasLimit` is below it. Without this, a bundler
  sets `callGasLimit` just high enough to pass validation but too low for
  `execute` to complete; the leaf is nullified in validation, the action's inner
  call runs out of gas, and the bundle still succeeds. The result is a forced,
  repeatable, irrecoverable leaf burn (worse than censorship, which is
  recoverable). Binding the floor closes it.

The fee and gas fields are UserOp calldata, not banned opcodes, so validation
may read them; binding them is the fix the following lemmas demand.

### Lemma 3 (any unbound reveal-time field reintroduces theft or forced burn)

If any field the EntryPoint acts on is chosen at reveal time and not covered by
the commitment, a bundler re-submits the revealed secret with that field set to
an attacker value and the aged commitment still matches.

*Proof.* If field `f` is outside `c`, then two UserOps differing only in `f`
share the same aged commitment `c`; the bundler opens `c` with its chosen `f`.
For `f = maxFeePerGas` this drains the deposit (theft); for `f = callGasLimit`
it forces a leaf burn; for `f = target/value/data` it would retarget the action.
∎

The three tests `test_bundlerCannotRetargetAction`,
`test_bundlerCannotInflateFeeToDrainDeposit`, and
`test_bundlerCannotStarveCallGasToBurnLeaf` exercise exactly these three fields
against a real EntryPoint v0.8. This is the crux: commit-reveal composes with a
hostile bundler only to the extent that binding is complete, and completeness
here means the action *and* the fee ceiling *and* the call-gas floor.

### Lemma 2 (with complete binding, a public-mempool bundler is limited to censorship, under a precondition)

Suppose the commitment binds the full action, the fee ceiling, and the call-gas
floor, and the leaf is nullified on use. Suppose further that the reveal reaches
the **public** alt-mempool and the victim re-broadcasts on non-inclusion within
`minCommitAge`. Then a bundler that observes the reveal can censor it or replay
the committed action unchanged, but cannot execute any other action, drain the
deposit, or force a leaf burn.

*Proof.* By Lemma 3's contrapositive, with the action, fee ceiling, and gas
floor all bound, no reveal-time field is free, so the only reachable outcomes on
the observed reveal are include-as-committed or drop. Dropping is censorship; by
the public-mempool-plus-re-broadcast assumption the victim re-lands the reveal
before an attacker's freshly posted competing commitment could age, so
censorship does not become theft. ∎

**The precondition is not optional, and dropping it is the base scheme's own
Theorem 3.** If the reveal is instead handed to a single bundler privately (the
common wallet UX: a user sends a UserOp to one bundler's RPC), that bundler has
the reveal before it is public, and [GAME.md](GAME.md) Theorem 3 applies
verbatim: the bundler commits its own competing action, withholds the victim's
reveal for `minCommitAge`, ages its commitment, and reveals for theft with
probability 1 against a passive victim. So the honest statement is: the 4337
construction downgrades a **public-mempool** bundler to censorship, but the
**default single-bundler** path is relay capitulation, i.e. deterministic theft,
inheriting the four-condition envelope of the base threat model (self-submitted,
public, against a final commit, actively re-broadcast). A paper must not present
"survivable" without that envelope; the survivability is real but conditional.

## 4. The bundler as adversary

Section 1 places an ECDSA-signed bundler on the inclusion path, and Section 3
shows the bundler cannot steal under full binding. What remains is the bundler's
censorship and timing power, which maps onto [GAME.md](GAME.md)'s adversary with
two adjustments:

- The bundler's block-production share is replaced by its share of UserOp
  inclusion, i.e. its position in the 4337 alt-mempool and its willingness to
  drop the op. A victim can switch bundlers or self-bundle, so the effective
  censoring share is the fraction of usable bundlers that collude, not a single
  bundler's share.
- The `validAfter` mechanism lets a bundler hold a valid reveal and release it
  late (anywhere in `[commitTime + minCommitAge, commitTime + commitTTL]`),
  which is a timing-choice power identical to the base scheme's
  non-cancellable-bearer-reveal surface, now exercised by the bundler. Security
  must therefore assume a fully adversarial bundler and rely on the option to
  switch or self-bundle plus complete binding, never on any bundler's honesty.

For a **public-mempool** reveal the theft bound of [GAME.md](GAME.md) Theorem 1
carries over in form (theft still needs an aged competing commitment, still
`beta^a` in the censoring share), with `beta` the collusion share of usable
bundlers and `a` in wall-clock units. For a **privately relayed** reveal there
is no bound: it is Theorem 3, deterministic theft, unless the victim re-lands it
publicly within `minCommitAge`. The recovery primitives carry over and, unlike
the reveal, run as plain transactions: the age-gated `burn` and the `rotate`
break-glass are both ordinary calls on the account, available even when the
account cannot get a UserOp bundled, which is the right property for a recovery
move and the reason the 4337 account implements both rather than routing them
through the EntryPoint.

## 5. What this buys, and what it does not

Buys: the account holder no longer needs a quantum-vulnerable signing key of
their own to authorize a spend; the authorization is pure commit-reveal, carried
in 4337 validation, with no signature in the account. A hostile bundler that
only sees the reveal in the public mempool is limited to censorship, provided
the action, the fee ceiling, and the call-gas floor are all bound (Lemma 2,
Lemma 3). Recovery (`burn`, `rotate`) stays available as plain transactions.

Does not buy: an ECDSA-free inclusion path on L1 (Theorem 1); it relocates the
envelope to the bundler. Does not make the default single-bundler UX safe: that
path is relay capitulation (Theorem 3), and safety there requires either public
self-submission with re-broadcast or a bundler trusted with the account's funds.
Does not remove the timing and censorship powers of whoever includes the op, and
adds a proposer timestamp lever via wall-clock aging. Does not, by itself, make
the aging block-denominated again.

The end-to-end ECDSA-free account is reachable only under native AA (path 4).
Against a native-AA reference (EIP-7701 / RIP-7560), the same validation logic
would run with no bundler and no envelope; we can project its cost and state its
security as the target, but cannot measure it on mainnet until native AA ships.
That projection, and the honest four-path enumeration, is the contribution.
