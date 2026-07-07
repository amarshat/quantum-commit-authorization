# Protocol specification v0.1

Commit-reveal authorization for an EVM account using one-time hash secrets under a Merkle root. This document is the normative reference for both the Solidity contract and the Rust tooling; the two implementations must produce byte-identical hashes for every structure defined here.

## Notation

- `H(x)` is keccak256.
- `enc(...)` is Solidity `abi.encode` of the listed values in order. Never `abi.encodePacked`: `abi.encode` pads every value to 32-byte words, so the encoding is injective for the fixed-arity tuples used here.
- All domain tags are 32-byte constants, `TAG_x = keccak256("QCA/v1/<name>")`. Every hash in the protocol has a distinct tag as its first field, so a hash computed in one role can never be replayed in another (leaf vs node vs commitment).

| Tag | Preimage string | Used for |
|---|---|---|
| `TAG_SECRET` | `QCA/v1/secret` | off-chain leaf secret derivation |
| `TAG_LEAF` | `QCA/v1/leaf` | leaf hashing |
| `TAG_NODE` | `QCA/v1/node` | Merkle inner nodes |
| `TAG_ACTION` | `QCA/v1/action` | action tuple hashing |
| `TAG_COMMIT` | `QCA/v1/commit` | commitments |

## Key material (off-chain)

The wallet holds one 32-byte seed `S` drawn from a CSPRNG.

```
secret_i = H(enc(TAG_SECRET, S, i))          i in [0, 2^d)
leaf_i   = H(enc(TAG_LEAF, secret_i))
root     = Merkle root over leaf_0 .. leaf_{2^d - 1}
node     = H(enc(TAG_NODE, left, right))
```

The tree is a complete binary tree of depth `d`. `secret_i` is one-time: it is exposed at reveal and must never authorize anything again. `TAG_SECRET` never appears on-chain; the contract only ever sees `secret_i`, from which neither `S` nor any sibling secret is derivable (keccak256 preimage resistance).

## On-chain state

The account contract stores:

- `root` (bytes32) and `depth` (uint256): the active authorization tree.
- `usedLeaves`: `mapping(bytes32 => bool)`, keyed by leaf hash `H(TAG_LEAF, secret)`. This is the nullifier set. Keying by leaf hash rather than by leaf index is deliberate: each secret is derived from the seed and a global index, so a leaf hash is unique across every tree the account ever uses, and a rotated tree's fresh secrets get fresh nullifier space with no index bookkeeping. The cost is one storage slot per consumed leaf instead of one packed bit; the earlier index-bitmap design saved gas but made rotation reuse an old index's nullifier bit, so it was dropped. Entries are never cleared.
- `commitments`: `mapping(bytes32 => uint256)`, commitment hash to the block number it was posted in. Zero means absent.
- Immutable parameters `minCommitAge` and `commitTTL`, both in blocks.

## Phases

### Register (bootstrap)

The constructor sets the initial `root` and `depth`. The deployment transaction is classical-crypto-signed; this bootstrap trust window is a documented assumption, not a solved problem (see threat model).

### Commit

```
action    = (target, value, data)
actionHash = H(enc(TAG_ACTION, target, value, H(data)))
c          = H(enc(TAG_COMMIT, chainid, account, actionHash, leafIndex, secret_leafIndex))
```

`commit(c)` stores `commitments[c] = block.number`. Rules:

- Reverts if `commitments[c]` is nonzero. Re-committing an existing hash would reset its age; allowing that lets an observer refresh a victim's commitment forever and hold their reveal below `minCommitAge`. First write wins.
- Anyone may post a commitment and pay for it. The committer's identity is irrelevant: `c` binds the account, the exact action and the secret, so a copied or front-run commit is either identical (harmless, the victim reveals against it) or useless (the copier does not know a secret for any other action).

The commitment hides `actionHash` and `leafIndex` because `secret_i` is a 32-byte high-entropy value inside the hash.

### Reveal

`reveal(target, value, data, leafIndex, secret, proof[])` verifies, in order:

1. `proof.length == depth` and `leafIndex < 2^depth`.
2. Membership: fold `leafHash = H(enc(TAG_LEAF, secret))` up the path using `TAG_NODE`, taking left/right from the bits of `leafIndex`; result must equal `root`.
3. Leaf unused: `usedLeaves[leafHash]` is false.
4. Commitment: recompute `c` from `block.chainid`, `address(this)`, the action tuple, `leafIndex`, `secret`; require `commitments[c] != 0`.
5. Age: `block.number >= commitBlock + minCommitAge`. A commitment can never be revealed in its own block; without a minimum age the anti-front-running property is void, because an attacker who sees a reveal in the mempool could commit and reveal a competing action in the same block. See the parameter note: `minCommitAge` also governs how reorg-safe the commit is when the secret is exposed, and those are two different budgets.
6. Freshness: `block.number <= commitBlock + commitTTL`. Expired commitments are dead. Expiry bounds how long secret-bound state can linger and forces an attacker who steals a mempool-observed secret to race a live window instead of banking commitments indefinitely.

Effects, strictly before the external call (checks-effects-interactions):

7. Set `usedLeaves[leafHash] = true`.
8. Delete `commitments[c]`.
9. Execute `target.call{value: value}(data)`; return the success flag without reverting. A reverted action still consumes the leaf and the commitment: the secret was published in calldata the moment the reveal transaction hit the mempool, so it must never be reusable. "Executed" throughout this document means the reveal reached this call and consumed the leaf, regardless of the callee's success flag.

### Burn

`burn(leafIndex, secret, proof)` proves membership exactly as reveal does and sets `usedLeaves[leafHash] = true` without executing any action. It is the defensive move for a leaked secret: a reveal that was reorged out or expired unincluded leaves the secret public while the leaf is still live on-chain, and burning nullifies that leaf directly instead of forcing the holder to win an aged-commitment race against everyone else who saw the secret. Anyone able to present a valid secret and proof may call it; before a leak only the holder can, and after a leak burning is the outcome we want. Burn executes nothing, so a hostile burn only denies the leaf, it never moves funds.

### Rotate

Root rotation is a normal revealed action whose target is the account itself calling `rotate(newRoot, newDepth)` (guarded `onlySelf`). Semantics:

- Outstanding commitments made under the old root become unrevealable if their leaves are not in the new tree; commitment validity is checked against the current root at reveal time. Rotating to a fresh tree therefore cancels all in-flight commitments. This is deliberate: rotation is the break-glass response to suspected seed exposure.
- Nullifiers are keyed by leaf hash, so a new tree built from fresh secrets gets fresh nullifier space automatically. A leaf consumed under the old tree stays consumed, which is harmless because the new tree's leaves have different hashes. There is no index bookkeeping and no capacity lost to rotation. (The tooling's `index_offset` exists only so that rotating within the same seed still produces distinct secrets; it is not required for correctness once nullifiers are hash-keyed.)

### Prune

`prune(c)` deletes an expired commitment (`block.number > commitBlock + commitTTL`) for the gas refund. Anyone may call it. Live commitments cannot be pruned.

## Parameters

`minCommitAge` and `commitTTL` are set at deployment. `minCommitAge` carries two distinct safety budgets that must not be conflated:

1. Anti-front-running margin. An attacker who learns a secret from a pending reveal needs `minCommitAge` blocks between their commit and their reveal, so the victim's already-aged reveal only loses if it stays unincluded for longer than that. Larger values buy censorship margin and cost latency.
2. Commit reorg-safety. Broadcasting a reveal exposes the secret. If the commit it opens is not yet final, a reorg can drop the commit while the secret is now public, which is a theft window, not just a liveness loss (see the threat model). The operational rule is therefore stronger than "reveal once aged": do not broadcast a reveal until its commit is final. A small `minCommitAge` (the test default is 4) is fine for budget 1 but is far below Ethereum finality (~64 to 95 slots), so a high-value account must either wait for commit finality before revealing or run a `minCommitAge` sized to its own reorg tolerance.

Defaults used in tests: `minCommitAge = 4`, `commitTTL = 256`. These are placeholders until the adversarial simulation produces measured guidance; treat them as parameters under study, not recommendations. In particular, `minCommitAge` should be sized against the builder concentration the account actually faces (censoring the reveal for the whole window against a coalition of block share p succeeds with probability ~`p^minCommitAge`), and the safe reveal window is narrower than the nominal `[commit + minCommitAge, commit + commitTTL]` once commit finality and the expiry edge are accounted for.

## Security properties (claimed)

Stated here so they can be attacked and, later, mechanized. Each is conditional on the stated secrecy premise; the premise, not the mechanism, is what fails in the reorg and expiry cases.

Secrecy premise: a leaf secret is known only to the honest owner until the moment that leaf's reveal becomes public. The contract cannot enforce this (commit is permissionless and binds the secret but authenticates no one); the properties below hold relative to it.

- **AUTH**: an action executes only against a matching aged, unexpired commitment binding `(chainid, account, action, leafIndex, secret)` whose leaf verifies under the current root. Under the secrecy premise the committer is the owner; without it, the committer is whoever holds the secret. "Holder" is not a claim the contract makes, only "a party in possession of the secret."
- **ONCE**: a leaf authorizes at most one execution per canonical chain, counting reverted actions as executions. This is not a cross-history statement: a reorg deeper than the reveal's inclusion depth resurrects the leaf and its commitment together (the EVM cannot see orphaned branches), and combined with the now-public secret that degrades the leaf to a race with no aged-commitment advantage. High-value actions must await finality.
- **NO-REBIND**: a commitment cannot be opened to any action tuple other than the one hashed into it. This is second-preimage resistance on a fixed published `c` (one preimage is the victim's), not collision resistance.
- **NO-RESURRECT**: consumed, expired or rotated-away authorizations cannot execute later, per canonical chain, subject to the same reorg caveat as ONCE.
- **HIDE**: before reveal, the commitment discloses nothing computationally useful for constructing a valid reveal. Recovering the action or index from `c` is a preimage search over the 256-bit secret (~2^128 under Grover). The low-entropy fields (`actionHash`, `leafIndex`) are hidden only computationally and only while the secret is secret, not information-theoretically.

Assumptions, per property:

- NO-REBIND, AUTH membership soundness, and HIDE rest on keccak256 (second-)preimage resistance: ~2^128 against a Grover-equipped quantum adversary at 256-bit output.
- No property rests on quantum collision resistance. Generic quantum collision on a 256-bit hash is only ~2^85 (Brassard-Hoyer-Tapp), well below the 2^128 floor, but it does not bite here because in every hash one preimage is fixed by the honest owner or by the honestly chosen root. Any future change that lets an adversary choose a root (guardian recovery, adversary-influenced rotation) would introduce a ~2^85 dependency and must be analyzed separately.
- Root uniqueness per account is required: cross-account isolation rests on distinct roots, not on the commitment's account field (a permissionless committer can always re-commit an observed secret on any account whose current root contains that leaf). Deploying two accounts from one seed, or rotating back to a prior root, breaks this.
- Chain finality as delivered by the underlying consensus. No assumption of ECDSA security anywhere in the authorization path.

## Known limitations

- The reveal transaction's outer envelope is ECDSA-signed on present-day Ethereum. An attacker cannot alter the revealed action (NO-REBIND), and the envelope is irrelevant to the reveal since anyone can submit their own, but full end-to-end PQ security needs account abstraction or protocol support for the envelope itself.
- A reveal is a non-cancellable, submitter-independent bearer instrument. The recomputed commitment does not bind `msg.sender`, so once a reveal is public anyone can land the committed action from any account, and the committer cannot cancel it by replace-by-fee. The action is immutable (NO-REBIND), but its block and intra-block placement within the reveal window are handed to the market, which matters for MEV-sensitive actions.
- Relayed or bundled reveals hand the secret to the relayer before it is public. A relayer can commit a theft action and withhold the victim's reveal, defeating the aged-commitment defense with no chain censorship required. Reveals must be self-submitted or sent only through a relayer trusted with the account's funds.
- Burn-on-expiry depends on off-chain state. Whether a leaf's secret was ever broadcast in an unincluded reveal leaves no on-chain trace, so a wallet that rebuilds state by scanning events cannot reconstruct it. Wallets must record "leaf i exposed" durably before broadcasting a reveal (write-ahead) and treat any leaf with unknown reveal status as burned (fail closed). The on-chain `burn` gives such a leaf a race-free nullification.
- Nullifier state and commitment records grow with use; prune reclaims expired commitments, spent-leaf entries are permanent by design.
- Censorship of a reveal through the commit window is a liveness attack whose cost is bounded only when the victim actively fee-escalates the reveal across the whole window; a passive, near-basefee reveal reduces security to the builder lottery. Quantified in the threat model and the planned simulation.
- `committedAt` must always be read from on-chain state, never assumed from a local commit receipt: an identical front-run commit can make the sender's own commit transaction revert while the commitment still exists at a slightly earlier block.
