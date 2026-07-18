# Message-bound hash-signature authorization v0.2 (draft, QCA 3 milestone M1)

A one-time / few-time hash-signature validator for an EVM account, as the
successor construction to the bearer-preimage commit-reveal of [SPEC.md](SPEC.md).
Instead of authorizing an action by revealing a preimage under a Merkle root,
the account carries a hash-based signature (WOTS one-time, or FORS few-time) over
the exact transaction intent, whose public key is a Merkle-tree leaf.

**Novelty boundary (read this first).** The *construction* here is not novel and
we do not claim it. A message-bound hash-signature account is XMSS (RFC 8391) /
SLH-DSA hypertree (FIPS 205) reused as an authorization module, and the
smart-account form already ships: RivaLabs Ephemeral Keys (ethresear.ch 24273),
EF Kohaku (`@kohaku-eth/pq-account`, SPHINCS+), and poqeth (AsiaCCS 2025,
on-chain WOTS+/XMSS/SPHINCS+ verifiers). This document specifies the vehicle we
need in order to *measure* the state-management race. The contribution lives in
[STATE_MODEL.md](STATE_MODEL.md): the forcing-adversary model, the ONCE-sign
impossibility, and the downgrade theorem. Build this minimally; the analysis is
the contribution.

**v0.2 changelog (M1 red-team boundary).** Folded a three-agent panel
(pq-cryptographer, formal-verifier, mev-adversary). Crypto: added a secret-keyed
message randomizer `R` (steering / collision-rebind break), per-call `ADRS` in
the tweakable hash (within-account multi-target Grover), and a specified
digest-to-index expansion. Spec: removed `account` from the leaf (it was circular
with the CREATE2-from-root rule), added a signed `validUntil`, made the FORS
few-time scheme the recommended default, and required the retry to reuse the same
2D-nonce key. Every change is annotated inline with its finding.

Everything here inherits the reorg and finality caveats of ONCE / NO-RESURRECT
from [SPEC.md](SPEC.md) and the state machine of [STATE_MODEL.md](STATE_MODEL.md).

## Notation

- `H(x)` is keccak256. `enc(...)` is `abi.encode` (32-byte-word padded,
  injective for fixed-arity tuples). Never `abi.encodePacked`.
- `XOF(x, L)` is SHAKE256 squeezed to `L` bits (used only for the
  digest-to-index expansion, where keccak256's 256-bit output is too short).
- Domain tags are 32-byte constants `TAG_x = keccak256("QCA/v2/<name>")`. The
  `v2` prefix separates every hash role from the `v1` commit-reveal tags.
- `PUB_SEED` is a per-account 32-byte public seed, fixed at deployment. It gives
  *cross-account* multi-target separation only; *within-account* separation is
  the job of `ADRS` below (pq-crypto F2).
- `ADRS` is a per-call address tuple folded into every public tweakable-hash call
  (WOTS chain, Merkle node, FORS leaf/node), so that no two hash calls in one
  account evaluate the same function. This is the RFC 8391 / SP 800-208 /
  Hülsing-Rijneveld-Song (PKC 2016) multi-target discipline; `PUB_SEED` alone
  does not deliver it. `ADRS = enc(adrsType, deviceId, treeAddr, pos)` with fields
  per role: WOTS `(chain c, hash-position q)`, Merkle `(height, node-index)`,
  FORS `(tree t, node-index)`.

| Tag | Preimage string | Used for |
|---|---|---|
| `TAG_PRF` | `QCA/v2/prf` | secret-element key stream `sk = PRF(seed, deviceId, i, j)` |
| `TAG_R` | `QCA/v2/randomizer` | secret-keyed message randomizer `R` (pq-crypto F1) |
| `TAG_F` | `QCA/v2/F` | **WOTS-only** chain function, tweakable, `PUB_SEED`+`ADRS`-keyed |
| `TAG_WOTS_PK` | `QCA/v2/wots-pk` | WOTS public-key compression (chain ends to pk) |
| `TAG_FORS_LEAF` | `QCA/v2/fors-leaf` | FORS leaf hashing (`F(sk)`) |
| `TAG_FORS_NODE` | `QCA/v2/fors-node` | FORS internal tree nodes (pq-crypto F4) |
| `TAG_FORS_ROOT` | `QCA/v2/fors-root` | FORS per-tree root |
| `TAG_FORS_PK` | `QCA/v2/fors-pk` | compression of the `k` FORS roots to the FORS pk (pq-crypto F4) |
| `TAG_LEAF` | `QCA/v2/leaf` | Merkle leaf over a per-index public key |
| `TAG_NODE` | `QCA/v2/node` | Merkle inner nodes |
| `TAG_INTENT` | `QCA/v2/intent` | canonical intent encoding |
| `TAG_ACTION` | `QCA/v2/action` | action tuple hashing |
| `TAG_MSG` | `QCA/v2/msg` | randomized message digest and index expansion |
| `TAG_NULLIFIER` | `QCA/v2/nullifier` | nullifier key over a consumed leaf |
| `TAG_RECOVERY` | `QCA/v2/recovery` | action-bound recovery leaves (analysis deferred, §Recovery) |
| `TAG_ENV_BASE` / `_4337` / `_ZKSYNC` | `QCA/v2/env/<x>` | environment separation |

The distinct `TAG_LEAF` / `TAG_NODE` fold is the RFC 6962 leaf-vs-node
second-preimage guard (pq-crypto F4 corrected the earlier CVE-2012-2459
attribution: the odd-node duplication malleability of CVE-2012-2459 is instead
prevented by using a complete tree of exactly `2^d` KDF-real leaves with proof
length `== depth`, and the tree MUST NOT be padded by node duplication).

## Key material (off-chain)

The wallet holds one 32-byte seed `S` from a CSPRNG, derived per device and per
leaf index (defense D4, disjoint concurrent keys; [STATE_MODEL.md](STATE_MODEL.md)):

```
sk_{device,i,j} = PRF(TAG_PRF, S, deviceId, i, j)              # j-th secret element of leaf i
pk_i            = a WOTS or FORS public key over sk_{device,i,*}, each tweakable-hash
                  call keyed by (PUB_SEED, ADRS)
leaf_i          = H(TAG_LEAF, chainId, schemeId, deviceId, PUB_SEED, pk_i)
root            = Merkle root over leaf_0 .. leaf_{2^d - 1}
node            = H(TAG_NODE, PUB_SEED, ADRS_node, left, right)
```

**The leaf does not bind `account`** (formal F5). Binding it was circular: the
account address is `CREATE2(salt = f(root, ...))`, the root is the Merkle root of
the leaves, and a leaf that hashed in `account` would need the address before the
leaves that determine it exist, a keccak fixed point. It is also unnecessary:
cross-account isolation is provided by the *intent* binding `account` (below), so
a signature valid for account A rebuilds a different digest under account B. The
one-tree-per-account deployment rule still holds, re-justified as *forgery*
avoidance rather than nullifier isolation: an owner who signs the same leaf's key
on two accounts produces two signatures over two different intent digests, which
is the two-signature WOTS catastrophe, not merely a nullifier replay.

`deviceId` partitions the index space by KDF domain (not by convention: a
restored backup cannot violate a KDF domain). Revoking a device nullifies its
whole unused range at once; this is the only permitted index-range bitmap (D4,
monotone, non-resurrecting), distinct from the epoch bitmap v1's F-2026-06 removed.

`schemeId` (`1` = WOTS one-time, `2` = FORS few-time) is bound into the leaf and
into the account address, so a leaf of one scheme cannot verify under the other
and "crypto-agile" means *deploy a new account*, never *switch modules on the
same funds* (a weakest-module downgrade surface otherwise).

## The signed intent

The signature is over a randomized, canonical intent digest, not the raw
EntryPoint `userOpHash`. Two independent reasons, both load-bearing:

1. **Ceiling binding (defense D1).** Binding the exact `userOpHash` makes every
   in-ceiling fee bump change the message and force a fresh signature on a fresh
   leaf, which is the forced-reuse pressure the scheme exists to remove. So fee
   and gas fields are signed as *ceilings*.
2. **Secret-keyed randomizer `R` (pq-crypto F1).** The digest MUST include a
   secret-keyed `R`, SPHINCS+ style, or an adversary who influences the intent
   (the `actionHash` comes from externally supplied calldata) can *steer* the
   FORS indices to a target, or grind an intent-digest *collision* to rebind the
   signature to a different action. `R` makes the digest unpredictable to anyone
   without `S`, which both kills index-steering and downgrades the digest's
   requirement from collision resistance (2^128 classical / ~2^85 BHT) to
   second-preimage resistance (2^128 quantum).

```
actionHash = H(TAG_ACTION, target, value, H(data))
intent     = (chainId, account, schemeId, envTag, nonceKey, nonceSeq, actionHash,
              maxFeeCap, callGasFloor, maxPvgCeil, [maxGasCeil, maxPubdataCeil],
              notBefore, validUntil)
R          = PRF(TAG_R, S, deviceId, i, H(TAG_INTENT, enc(intent)))   # deterministic, secret-keyed
digest     = H(TAG_MSG, R, PUB_SEED, H(TAG_INTENT, enc(intent)))      # WOTS signs this 256-bit digest
md         = XOF(enc(TAG_MSG, R, PUB_SEED, H(TAG_INTENT, enc(intent))), k*a)   # FORS index bits
sig        = ( Sign(sk_{device,i,*}, digest | md), R )               # R shipped in the signature
```

- **`R` is deterministic** (`opt_rand = 0` in FIPS 205 terms): no signing-time
  RNG is needed, and determinism is what keeps write-ahead replay of the *same*
  op idempotent. `R` is included in the signature so the verifier can recompute
  the digest.
- **FORS index expansion (pq-crypto F3).** FORS needs `k*a` index bits
  (256s: 308, 256f: 315, custom 13x21: 273), more than keccak256's 256, so the
  indices come from `XOF(...)` squeezed to exactly `k*a` bits, split into `k`
  consecutive `a`-bit fields, each read as a uniform index in `[0, 2^a)`. Naive
  bit-slice reuse or biased `mod 2^a` reduction breaks the `k(a - log2 r)` bound
  and is forbidden.
- **`nonceKey` / `nonceSeq`** are the two components of the account's 2D nonce
  (EntryPoint `NonceManager` under 4337: 192-bit key + 64-bit sequence; zkSync
  `NonceHolder`; an explicit counter on the base account). Monotonicity that
  serializes a stranded op against its replacement holds only *within a key*
  (formal F2), so the wallet MUST bind, and on retry reuse, the same `nonceKey`,
  never a fresh parallel key. See [STATE_MODEL.md](STATE_MODEL.md) Lemma S1.
- **Ceilings** (`maxFeeCap`, `callGasFloor`, `maxPvgCeil`, zkSync
  `maxGasCeil`/`maxPubdataCeil`) are signed bounds; validation rejects any op
  whose actual field violates the bound. Only monotone-cost fields, each with a
  written monotone-safety argument. This reuses paper 2's F-2026-01..05 field
  enumeration unchanged. Caveat carried from the mev-adversary review: a *tight*
  `maxPvgCeil` (needed to stop deposit drain, AA.md F-2026-01) can be exceeded by
  a legitimately risen `preVerificationGas` under induced calldata congestion,
  forcing a re-sign; the theft-safe and forcing-safe ceilings are in tension and
  the wallet policy must choose a margin knowingly. On L2 the pubdata/blob fee is
  far more volatile than L1 basefee, so `maxPubdataCeil` is the soft ceiling.
- **`notBefore` / `validUntil`** are the signed lower and upper wall-clock
  validity bounds, returned to the EntryPoint as `validAfter` / `validUntil`
  (aging enforced outside validation, ERC-7562 OP-011). `validUntil` was missing
  in v0.1 and is required (formal F4, mev F6): without it a message-bound op is a
  valid bearer instrument *forever*, the wallet can never conclude an attempt is
  "dead by expiry," and by AA.md Lemma 3 an unbound `validUntil` is an unbound
  field the adversary maximizes. It re-bounds the non-cancellable-bearer timing
  window that message-binding otherwise leaves open.

The account reads back the EntryPoint's view of the fields it binds exactly
(action, both nonce components) and rejects on mismatch. Ceilings are bounds;
exactly-bound fields are read back; the randomized digest ties both to `S`.

## Scheme parameters and honest cost

The security target `k(a - log2 r_max) >= 256` is **128-bit quantum**, not
256-bit classical: the FORS forgery is an unstructured search over covered
digests, so Grover halves the exponent and `>= 256` classical is `>= 128`
quantum, matching the design's 2^128 floor (pq-crypto, framing). A future reader
"optimizing" this to `>= 128` would land at 2^64 quantum; do not.

`r_max` is the maximum number of times one leaf's signature may be exposed before
forgery stops being negligible. It is bounded by off-chain state-desync accidents
(a stale-backup restore that re-signs a leaf), **not** by the adversary (the
forcing adversary cannot drive it above the honest floor;
[STATE_MODEL.md](STATE_MODEL.md) R1/R2). Realistic accident budget `r_max = 2`.

Design points (n = 32-byte keccak values, mandatory: n = 16 gives only 2^64
Grover preimage, below the 2^128 floor):

| scheme | params | sig bytes | est. gas (calldata-incl.) | reuse budget |
|---|---|---|---|---|
| WOTS (w=16), one-time | len 67 | ~2,176 (incl. `R`) | ~112k-165k | `r_max = 1` (hard) |
| FORS few-time (256f) | k=35, a=9 | ~11,230 (incl. `R`) | ~260k-520k | `r_max = 2` |
| FORS few-time (256s) | k=22, a=14 | ~10,590 (incl. `R`) | ~250k-500k | `r_max = 4` |
| FORS few-time (custom) | k=13, a=21 | ~9,180 (incl. `R`) | ~220k-440k | `r_max = 2` |

FORS sizes are `k(a+1)n + 32` (the `+32` is `R`), plus the depth-`d` Merkle path;
the v0.1 table understated the FIPS sets by 15-20% (pq-crypto F5). Reference:
QCA1 4337 auth-only ~157k, Ephemeral Keys self-reported ~136k, on-chain ML-DSA-44
~8.2M, ETHFALCON ~1.6M.

Consequences, stated plainly:

1. **The recommended default is FORS few-time, `r_max = 2`** (formal F6). Q3
   concludes one restore accident is realistic, so the honest accident budget is
   `r_max = 2`, and WOTS with `r_max = 1` survives *zero* accidents: a single
   accidental second signature on a WOTS leaf is a classical arbitrary-action
   forgery (~2^43-46 keccak, low-single-digit minutes at ~2^43 on a GPU, hours
   toward 2^46; the qualitative "catastrophic, classical, no quantum" is right).
   The document cannot claim `r_max = 2` is realistic and then default to a
   `r_max = 1` scheme.
2. **WOTS one-time is the low-cost option under a stated assumption.** At ~2.1 KB
   and ~112k-165k gas it is at parity with Ephemeral Keys and QCA1 and is the
   right choice *only* for a wallet that can guarantee hardware-durable
   write-ahead storage with no restore path. That assumption is exactly what Q3
   says is unrealistic for general wallets, so WOTS is the expert option, not the
   default.
3. **`r_max` is nearly free to raise once you pay for FORS**, and **custom deep
   FORS is unnecessary**: FIPS-205 SLH-DSA-256 FORS parameters meet the standalone
   `>= 256` bound up to `r_max = 4` (256s: k=22,a=14) or `r_max = 2` (256f:
   k=35,a=9). The 128/192 sets are excluded: `128s/128f/192s` fail the
   combinatorial bound standalone (168/198/238 < 256), and `192f` meets it
   combinatorially (264) but is excluded because `n = 24` gives only 2^96 Grover
   preimage, below the floor (pq-crypto F6 corrected the stated reason).

Honest headline: **a latency win over on-chain lattice verification; parity with
prior hash-sig accounts only on the WOTS expert option; a gas loss on the FORS
default.** Reported as full calldata-inclusive amortized gas under EIP-7623/7976,
never verify-only.

## On-chain state

- `root`, `depth`, `schemeId`, `PUB_SEED`: the active tree and scheme.
- `usedLeaves`: `mapping(bytes32 => bool)`, keyed by `H(TAG_NULLIFIER, leaf_i)`.
  Permanent, never cleared, keyed by leaf hash, not by index or epoch (the
  F-2026-06 discipline: a backup restore rebuilds the same tree and gets the same
  nullifier keys, so consumed stays consumed; an epoch bitmap would reset to zero
  and resurrect every consumed leaf).
- `revokedRanges`: the per-device revocation bitmap (D4; the only allowed bitmap).
- the 2D nonce, via EntryPoint `NonceManager` / zkSync `NonceHolder` / base counter.

## Validation and execution

Per canonical chain, in order (4337 `validateUserOp` shown):

1. Rebuild `leaf_i = H(TAG_LEAF, chainId, schemeId, deviceId, PUB_SEED, pk_i)`
   from the carried public key; verify Merkle membership to `root` (proof length
   `== depth`, folded with `TAG_NODE` + `ADRS_node`).
2. Recompute `R`-randomized `digest` / `md` from the op's action, the signed
   ceilings, and the shipped `R`; verify `Verify(pk_i, digest|md, sig)` with the
   per-call `ADRS` tweak.
3. Nullifier `H(TAG_NULLIFIER, leaf_i)` unset and `deviceId` range not revoked.
4. Ceilings: reject if `maxFeePerGas > maxFeeCap`, `callGasLimit < callGasFloor`,
   `preVerificationGas > maxPvgCeil` (+ zkSync gas/pubdata ceilings).
5. Read-back: EntryPoint `userOpHash`'s action and both nonce components equal
   the signed ones.
6. Return `validAfter = notBefore`, `validUntil = validUntil` to the EntryPoint.

Effects, checks-effects-interactions, nullifier write in the validation phase
(mempool-invalidates a sibling op on the same leaf, the AA.md accepted drop
surface):

7. Set `usedLeaves[H(TAG_NULLIFIER, leaf_i)] = true`.
8. `target.call{gas: callGasLimit, value: value}(data)`; consume leaf and nonce
   regardless of the callee's success flag.

The EIP-150-safe gas check precedes the nullifier write (F-2026-02 / F-2026-05
carry over), so a copy starved of outer gas reverts and leaves the leaf live.

## Bootstrap, recovery, rotation

- **Bootstrap.** The `CREATE2` salt MUST be a pure function of
  `(root, recoveryRoot, schemeId, PUB_SEED)` and the genesis intent MUST bind
  `chainId` and the account address (else bootstrap theft, or cross-chain CREATE2
  replay). Classical-signed deployment, a documented trust window as in v1.
- **Recovery (analysis deferred out of M1; formal F9).** Recovery uses
  action-bound leaves `leaf = H(TAG_RECOVERY, chainId, account, actionHash,
  secret)` to a fixed safe destination, long timelock, PQ guardian veto not
  requiring the possibly-lost normal key, and MUST preserve the permanent
  nullifier set. Two analyses are owed before recovery is in scope and are NOT
  done here: (a) a guardian-influenced root reintroduces the ~2^85 adversary-
  chosen-root BHT collision axis and must be analyzed separately; (b) the D2
  write-ahead and hash-keyed-nullifier discipline must be extended to the recovery
  tree, whose leaves are themselves one-time keys subject to R1. Recovery is not
  in the M1 state machine.
- **Rotation.** A self-call replacing `root`; cancels in-flight signatures whose
  leaves are absent from the new tree; preserves the permanent hash-keyed
  nullifier automatically (fresh secrets, fresh leaf hashes, fresh nullifier keys).

## Blocking rules (normative; a build that violates any of these is broken)

1. **One leaf, one signature, ever** on the honest path. Write-ahead burn (D2):
   mark the leaf consumed in durable local storage *before* releasing the
   signature; never re-sign a consumed leaf; unknown-status leaf = consumed
   (fail closed).
2. **Secret-keyed randomizer `R` in the digest** (pq-crypto F1). Never sign a
   digest that is a public deterministic function of an adversary-influenceable
   intent.
3. **Per-call `ADRS` in every public tweakable-hash call** (pq-crypto F2).
   `PUB_SEED` alone is cross-account only; the 2^128 within-account floor needs
   `ADRS`.
4. **Specified uniform index expansion** to `>= k*a` bits (pq-crypto F3).
5. **No `+C` marketed as reuse-tolerant.** Baseline is checksum-bearing
   WOTS/XMSS/LMS; FORS is the few-time option, deployed with the written `r_max`
   analysis.
6. **No bare `userOpHash` signing for a one-time leaf.** Sign the ceiling-intent;
   read back the EntryPoint hash for exactly-bound fields only.
7. **No epoch/index nullifier bitmap** for the main set (bitmap only for D4
   device revocation).
8. **No crypto-agile multi-module account** where a weak module authorizes general
   actions. `schemeId` bound into `CREATE2`; weak modules get action-restricted
   capabilities only.
9. **Retry reuses the same 2D-nonce key** (formal F2), never a parallel key.

## Security properties (claimed; attacked in STATE_MODEL.md)

- **ONCE-exec.** At most one execution per leaf per canonical chain, by the
  permanent nullifier (no reorg) and nonce monotonicity within a key (across a
  reorg; Lemma S1).
- **ONCE-public (tight safety target) / ONCE-sign (sufficient off-chain proxy).**
  Forgery needs two signatures on one leaf to become *observable by the
  adversary*; the tight invariant is ONCE-public, of which ONCE-sign (at most one
  signature ever produced) is a sufficient proxy D2 maintains. Both are
  off-chain-unenforceable ([STATE_MODEL.md](STATE_MODEL.md) R1).
- **NO-REBIND (message-bound), now collision-hardened.** A signature opens to
  exactly the signed intent. With `R` (blocking rule 2) this rests on
  second-preimage resistance of the intent digest, not collision resistance, so it
  holds at 2^128 quantum even against an adversary who influences `data`. Without
  `R` it degrades to collision resistance and the read-back does not save it.
- No property rests on quantum collision resistance *given* `R` and `ADRS`. Absent
  either, the 2^85 BHT axis reopens (collision-rebind absent `R`; multi-target
  Grover to ~2^113 absent `ADRS`). Guardian recovery, which lets an adversary
  influence a root, reintroduces the 2^85 axis independently and is deferred.
