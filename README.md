# quantum-commit-authorization

Hash-based commit-reveal authorization for EVM accounts: spend with one-time hash secrets instead of attaching a post-quantum signature to every transaction.

## Why this exists

If a cryptographically relevant quantum computer arrives, Shor's algorithm breaks the elliptic-curve signatures (ECDSA, BLS) that every major chain uses to authorize transactions. The standardized post-quantum replacements fix the math but are heavy on-chain: an ML-DSA-44 signature is 2,420 bytes, SLH-DSA runs 8 to 17 KB. That cost is paid on every single transaction, forever, replicated across every node.

There is an older idea that avoids signatures entirely: authorize an action by revealing the preimage of a hash you committed to earlier. Security then rests on hash preimage resistance, which quantum computers only dent (Grover halves the exponent) rather than break. Versions of this idea have been proposed repeatedly since 2014: Fawkescoin (Bonneau and Miller), commit-delay-reveal migration for Bitcoin (Stewart et al. 2018), Dryja's Fawkescoin-variant soft fork sketch (2025), and a pairwise commit-reveal scheme by Finlow-Bates, Jakobsson and Siadati (2026).

What none of that work delivers: a real implementation, a security analysis against a realistic mempool adversary, or cost measurements against the post-quantum signatures it claims to beat. That is the gap this project fills. Build it, attack it, measure it honestly, including the cases where a plain PQ signature wins.

## How it works

One account contract, three moves:

1. **Register.** The account stores the Merkle root of `2^d` one-time leaves. Each leaf is the hash of a secret derived from a single seed, so the wallet only stores 32 bytes. Registration happens once and is amortized over all later actions.
2. **Commit.** To act, post a 32-byte commitment binding chain id, account, the exact action (target, value, calldata), a leaf index, and the leaf's secret. The commitment reveals nothing about the secret or the action.
3. **Reveal.** After a minimum age in blocks and before the commitment expires, reveal the secret, the Merkle path, and the action. The contract checks the leaf is unused, the path is valid against the root, the commitment matches and has aged, then marks the leaf spent and executes the action.

An attacker watching the mempool learns the secret the moment the reveal transaction appears. It does them no good: using it requires a fresh commitment, and fresh commitments must age `minCommitAge` blocks before they can be revealed. The victim's already-aged reveal lands first. How large that safety margin really is under congestion, censorship and reorgs is exactly what this project measures instead of assuming.

Full protocol in [docs/SPEC.md](docs/SPEC.md), adversary analysis in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## What this does not solve

Honesty up front, since this space is full of overclaiming:

- On today's Ethereum the reveal transaction itself is still wrapped in an ECDSA-signed envelope. The protocol protects the authorization layer; the envelope needs account abstraction (or a quantum-emergency fork) to matter fully.
- Registration is a classical-crypto bootstrap. There is a trust window at account creation. This is a migration and contingency design, not a from-genesis pure-PQ chain.
- Commit-reveal costs two transactions and a delay. Whether that beats one fat PQ signature is an empirical question, and the benchmarks here treat it as one.

## Layout

```
contracts/   Solidity account contract and tests (Foundry)
tooling/     Rust workspace: leaf derivation, Merkle trees, commitment
             construction, golden test vectors shared with the contracts
docs/        Protocol spec and threat model
```

## Roadmap

- [x] Protocol spec and threat model
- [x] Account contract: commit, reveal, nullifiers, expiry, root rotation
- [x] Rust tooling and cross-implementation golden vectors
- [ ] Gas benchmarks vs on-chain ML-DSA / Falcon / SLH-DSA verification
- [ ] Adversarial mempool simulation (reveal races, commit griefing, reorgs)
- [ ] Recovery paths for lost leaf state

## License

MIT
