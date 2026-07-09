# Commit-reveal under account abstraction v0.1

[SPEC.md](SPEC.md) authorizes an account by hash-based commit-reveal instead of
a signature, and [GAME.md](GAME.md) proves that authorization degrades a
quantum key break to a bounded censorship race. Both have one stated gap: on
today's Ethereum the reveal transaction is carried in an ECDSA-signed envelope
(the sender and gas payer is an ECDSA EOA), which a quantum adversary can
break. This document asks whether native account abstraction closes that gap,
and answers precisely: it does not, and cannot, on post-Pectra mainnet. What it
does do is relocate the ECDSA envelope from the owner's EOA to a bundler's, and
in doing so it exposes the revealed secret to that bundler. The value of this
document is (1) a theorem that no account on current mainnet has an
ECDSA-free authorization path, and (2) a lemma that the bundler's view of the
secret is survivable, reducing to censorship rather than theft, exactly when the
commitment binds the whole action.

## 1. The four inclusion paths

An account authorized by commit-reveal must still get its reveal included in a
block. On post-Pectra mainnet (mid-2026) every path to inclusion terminates in
an ECDSA-signed transaction:

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
   that removes ECDSA end to end. It is not shipped and not scheduled.

### Theorem 1 (no ECDSA-free account on current mainnet)

On post-Pectra Ethereum mainnet there is no account whose authorization and
inclusion path is free of a secp256k1 signature.

*Proof.* Inclusion requires a transaction. Only two transaction origins exist
today: an externally owned account, whose transaction is secp256k1-signed by
construction, and a 7702-delegated EOA, whose delegation is itself
secp256k1-signed and revocable by the same key (path 1). A 4337 UserOp is not a
transaction; it must be wrapped by an `EntryPoint.handleOps` transaction, whose
origin is one of the two above (paths 2, 3). The only escape is a transaction
type whose validity is not gated by a secp256k1 signature, i.e. native AA (path
4), which does not exist on mainnet. Hence every inclusion path contains a
secp256k1 signature. ∎

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

### Semantic change: aging is now wall-clock

Because validation cannot read block numbers, the commitment stores
`block.timestamp` and the aging parameter is in seconds, not blocks. The
anti-front-running argument of [GAME.md](GAME.md) is unchanged in structure (an
adversary who extracts the secret still needs their own commitment to age the
full window while the victim's is already aged), but the window is measured in
time, not block height. Under variable block times the two differ; a paper
using this construction must state the aging unit and re-express the block-share
adversary accordingly (a fixed wall-clock window spans a variable number of
blocks, so the effective `a` in `beta^a` varies with block time). This is a real
difference from the base scheme, not a cosmetic one, and is the price of the
4337 validation rules.

## 3. Binding, and why exposure is survivable

The heart of the construction is that validation parses the same `callData`
bytes the EntryPoint will execute. Validation requires
`callData = execute.selector || abi.encode(target, value, data)`, recomputes the
action hash from exactly those fields, and requires a matching commitment. The
EntryPoint then executes that same `callData`. So the authorized action and the
executed action are byte-identical.

### Lemma 2 (binding downgrades exposure to griefing)

Suppose the commitment binds the full action tuple `(target, value, data)` and
the leaf is nullified on use. Then a bundler (or any mempool observer) who
learns the secret from a pending reveal UserOp can cause the action to be
censored or replayed unchanged, but cannot cause any other action to execute on
that leaf.

*Proof.* To execute an action `A'` on leaf `i`, an opener needs a commitment
`c' = H(TAG_COMMIT, chainid, account, H(TAG_ACTION, A'), i, secret)` that exists
and is aged. The observer has `secret` but, for any `A' != A`, has no such aged
commitment: `c'` differs from the victim's `c` (second-preimage resistance on
the action hash), and a freshly posted `c'` is not aged. Re-submitting the
victim's own reveal executes `A` itself, which the nullifier lets happen at most
once. So the observer's reachable outcomes are censor (drop the victim's op) or
replay-`A` (harmless), never a chosen `A'`. ∎

This is verified directly against a real EntryPoint v0.8 in
`test/QCAAccount4337.t.sol` (`test_bundlerCannotRetargetAction`): a UserOp that
reuses the revealed secret for a different action is rejected in validation.

### Lemma 3 (loose binding reintroduces theft)

If any executed field is chosen at reveal time and not covered by the
commitment, a bundler front-runs by re-submitting the revealed secret with that
field set to an attacker value, and theft returns.

*Proof.* If field `f` is outside `c`, then `A` and `A'` differing only in `f`
share the same commitment `c`, which is aged; the observer opens `c` with `A'`.
∎

Lemma 3 is why the construction binds the entire action and refuses any
bundler-substitutable field (the 4337 `beneficiary` and gas-payment surface
included): those must not carry security-relevant values. The gap between Lemmas
2 and 3 is a single design invariant, and a paper should present it as the
crux: commit-reveal composes with a hostile bundler exactly to the extent that
binding is complete.

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

The theft bound of [GAME.md](GAME.md) Theorem 1 carries over unchanged in form
(theft still requires an aged competing commitment, still `beta^a` in the
censoring share), with `beta` reinterpreted as collusion share and `a` in
wall-clock units. The burn-griefing analysis carries over too: the age-gated
burn here is a plain transaction, not a UserOp, so it is available even when the
account cannot get a UserOp bundled, which is the right property for a recovery
move.

## 5. What this buys, and what it does not

Buys: the account holder no longer needs a quantum-vulnerable signing key of
their own to authorize a spend; the authorization is pure commit-reveal, carried
in 4337 validation, with no signature in the account. The bundler's view of the
secret is survivable under binding (Lemma 2). The recovery primitive stays
available as a plain transaction.

Does not buy: an ECDSA-free inclusion path (Theorem 1); it relocates the
envelope to the bundler. Does not remove the timing and censorship powers of
whoever includes the op. Does not, by itself, make the aging block-denominated
again.

The end-to-end ECDSA-free account is reachable only under native AA (path 4).
Against a native-AA reference (EIP-7701 / RIP-7560), the same validation logic
would run with no bundler and no envelope; we can project its cost and state its
security as the target, but cannot measure it on mainnet until native AA ships.
That projection, and the honest four-path enumeration, is the contribution.
