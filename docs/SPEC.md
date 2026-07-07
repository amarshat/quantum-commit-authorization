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
- `usedLeaves`: a bitmap, `mapping(uint256 => uint256)`, one bit per leaf index. This is the nullifier set. Bits are never cleared, including across root rotations.
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
2. Leaf unused: bit `leafIndex` of `usedLeaves` is 0.
3. Membership: fold `H(enc(TAG_LEAF, secret))` up the path using `TAG_NODE`, taking left/right from the bits of `leafIndex`; result must equal `root`.
4. Commitment: recompute `c` from `block.chainid`, `address(this)`, the action tuple, `leafIndex`, `secret`; require `commitments[c] != 0`.
5. Age: `block.number >= commitBlock + minCommitAge`. A commitment can never be revealed in its own block; without a minimum age the anti-front-running property is void, because an attacker who sees a reveal in the mempool could commit and reveal a competing action in the same block.
6. Freshness: `block.number <= commitBlock + commitTTL`. Expired commitments are dead. Expiry bounds how long secret-bound state can linger and forces an attacker who steals a mempool-observed secret to race a live window instead of banking commitments indefinitely.

Effects, strictly before the external call (checks-effects-interactions):

7. Set the leaf's nullifier bit.
8. Delete `commitments[c]`.
9. Execute `target.call{value: value}(data)`; bubble revert. A reverted action still consumes the leaf and the commitment: the secret was published in calldata the moment the reveal transaction hit the mempool, so it must never be reusable.

### Rotate

Root rotation is a normal revealed action whose target is the account itself calling `rotate(newRoot, newDepth)` (guarded `onlySelf`). Semantics:

- Outstanding commitments made under the old root become unrevealable only if their leaves are not in the new tree; commitment validity is checked against the current root at reveal time. Rotating to a fresh tree therefore cancels all in-flight commitments. This is deliberate: rotation is the break-glass response to suspected seed exposure.
- The nullifier bitmap is not reset. If a new tree reuses an old leaf index with a fresh secret, the old bit would block it, so rotations should use disjoint index ranges or accept the loss; the tooling handles this by tracking a global index offset. (Design note: keying nullifiers by leaf hash instead of index was rejected because the bitmap packs 256 nullifiers per storage slot, and index reuse across rotations is a tooling problem, not a protocol one.)

### Prune

`prune(c)` deletes an expired commitment (`block.number > commitBlock + commitTTL`) for the gas refund. Anyone may call it. Live commitments cannot be pruned.

## Parameters

`minCommitAge` and `commitTTL` are set at deployment. The safety argument for `minCommitAge` is: an attacker who learns a secret from a pending reveal needs `minCommitAge` blocks between their commit and their reveal, so the victim's reveal only loses if it stays unincluded for longer than that. Larger values buy censorship margin and cost latency. Defaults used in tests: `minCommitAge = 4`, `commitTTL = 256`. These are placeholders until the adversarial simulation produces measured guidance; treat them as parameters under study, not recommendations.

## Security properties (claimed)

Stated here so they can be attacked and, later, mechanized:

- **AUTH**: an action executes only if the holder of the corresponding leaf secret committed to exactly that `(chainid, account, action, leafIndex)` tuple.
- **ONCE**: a leaf index authorizes at most one executed action across the account's lifetime, including across rotations, reorgs and reverted actions.
- **NO-REBIND**: a commitment cannot be opened to any action tuple other than the one hashed into it (injective encoding plus keccak256 collision resistance).
- **NO-RESURRECT**: consumed, expired or rotated-away authorizations can never execute later.
- **HIDE**: before reveal, a commitment discloses nothing that enables any party, including a quantum-capable observer, to construct a valid reveal for any action.

Assumptions: keccak256 preimage and collision resistance against a quantum adversary (Grover-limited, so 128-bit preimage security at 256-bit output); chain finality semantics as delivered by the underlying consensus; no assumption of ECDSA security anywhere in the authorization path.

## Known limitations

- The reveal transaction's outer envelope is ECDSA-signed on present-day Ethereum. An attacker cannot alter the revealed action (NO-REBIND), and mempool-copying the envelope gains nothing, but full end-to-end PQ security needs account abstraction or protocol support for the envelope itself.
- Nullifier state and commitment records grow with use; prune covers expiries, spent-leaf bits are permanent by design.
- Censorship of reveals through the commit window is a liveness attack, not a theft attack; quantified in the threat model and the (planned) simulation.
