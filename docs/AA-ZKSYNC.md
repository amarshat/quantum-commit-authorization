# Commit-reveal on zkSync Era native account abstraction v0.1

[AA.md](AA.md) proves that on Ethereum L1 no account has an ECDSA-free
authorization-and-inclusion path: ERC-4337 only relocates the envelope from the
owner to a bundler. The one architecture that removes it, native account
abstraction, is not on L1 but is live on some L2s. This document is the L2
existence proof: the commit-reveal account built as a zkSync Era native-AA
account (`contracts-zksync/src/QCAAccountZkSync.sol`), where the account's
authorization path has no elliptic-curve assumption and no ECDSA envelope. It
also states the price of getting there, which is the real contribution: native
AA does not make the account safer than the L1 4337 version; it moves the
front-running risk of the aging window onto a single centralized sequencer, the
strongest possible instance of the base scheme's relay-capitulation theorem.

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
  enforces the gas-envelope binding (`maxFeePerGas <= maxFeeCap`,
  `gasLimit >= callGasFloor`, both bound into the commitment as on L1), and
  checks that a matching commitment exists. It returns the magic value.
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

Aging is wall-clock here, as on L1 4337, with the same consequences (the
effective `a` in the `beta^a` theft bound varies with block time; proposer
timestamp drift is a small lever). `minCommitAge` in seconds must carry a margin
above both.

## 3. The sequencer is the relay, and this is the result

zkSync Era runs a **private mempool behind a single sequencer**. There is no
public peer-to-peer L2 mempool. A user submits the reveal transaction to the
sequencer's RPC, and that one party sees the secret and the Merkle proof before
inclusion, with full ordering and inclusion discretion.

That is the base scheme's relay-capitulation theorem in its strongest form. A
party that privately sees the reveal can open its own commitment binding a
competing action to the leaf, withhold the victim's reveal (it controls
inclusion), age its own commitment, and reveal for theft with probability 1. The
aging window does not help, because the sequencer decides what is included and
when, so it can guarantee its own commitment ages while the victim's never
lands. On L1 4337 the victim had a fallback: broadcast to a public mempool of
many bundlers, which downgrades a private-relay bundler from theft to
censorship. On zkSync Era there is no public L2 mempool, so there is no
fallback. The only escape, force-inclusion via the L1 priority queue,
reintroduces ECDSA and publishes the reveal in Ethereum's public mempool anyway.

So the honest verdict: native AA removes the ECDSA envelope but relocates the
entire front-running security of the aging window onto trust in a single
centralized sequencer. That is not a cryptoeconomic guarantee; it is a raw trust
assumption, and it must be a first-class limitation. The account's gas-envelope
binding still closes the fee-drain and call-gas-starvation surfaces (a hostile
sequencer cannot over-charge the account or starve execution, tests
`test_feeCapBindingRejectsInflatedFee` and `test_callGasFloorRejectsStarvation`),
but it cannot make the sequencer include the victim's reveal.

Sequencer decentralization (multi-node/consensus block production, based-rollup
ordering, staking) diffuses "one party sees every reveal" toward the
public-mempool censorship case, but a private-mempool-with-proposer-privilege
design can still let whoever builds the including block do the withhold-and-age
move. Eliminating it looks to need encrypted mempools or threshold ordering.
That is a clean open problem, and it is the paper's forward-looking contribution.

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
`gasUsed` here (depth-16 authorization-only reveal ~157.9K, +1 ETH action
~174.6K, commit ~130.4K, growing ~833 per tree level) is reported for scaling and
as the existence proof, not as a like-for-like cost against L1.

The one meaningful in-platform comparison is against the ECDSA account it
replaces. A zkSync EOA is the `DefaultAccount` system contract, which verifies
secp256k1 in its own validation, so a plain signed transfer is the cost of an
ECDSA account authorizing the same action: 118.7K (0-value) and 126.8K (1 ETH) in
these runs. The zero-ECDSA reveal is 1.3x and 1.4x those, respectively. So the
paper's claim is bounded and honest: authorization with no ECDSA anywhere on the
path costs a small constant multiple of an ordinary signed transaction on a live
native-AA platform, not less. Still separable for a later pass: splitting that
charge into execution gas versus pubdata bytes and an end-to-end ETH cost at a
stated `gasPerPubdata`. See `bench/results/RESULTS.md`.

One platform caveat to date-stamp: native EraVM account abstraction is on a
deprecation path (ZKsync OS, the go-forward VM, is EVM-based and uses ERC-4337).
The existence proof stands for zkSync Era as of this writing; Starknet is a more
durable native-AA platform for a follow-up.
