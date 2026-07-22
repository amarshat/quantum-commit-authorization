# quantum-commit-authorization

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21363508.svg)](https://doi.org/10.5281/zenodo.21363508)

Hash-based commit-reveal authorization for EVM accounts: spend with one-time hash secrets instead of attaching a post-quantum signature to every transaction.

**New to this? Read the [plain-language explainer](https://amarshat.github.io/quantum-commit-authorization/)** for what the problem is, why the obvious fix is too expensive, and the approach this work takes.

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
bench/       Gas benchmarks against on-chain PQ signature verifiers
             (ETHFALCON and ETHDILITHIUM vendored as pinned submodules);
             results in bench/results/RESULTS.md
docs/        Protocol spec, threat model, the authorization game, and the
             account-abstraction analysis (AA.md)
sim/         Committed simulator result vectors (tooling/qca-sim generates)
fees/        Historical base-fee sample and the empirical fee-cost analysis
contracts-zksync/  zkSync Era native-AA build (zero-ECDSA account, foundry-zksync)
```

## Roadmap

- [x] Protocol spec and threat model
- [x] Account contract: commit, reveal, nullifiers, expiry, root rotation, defensive burn
- [x] Rust tooling and cross-implementation golden vectors
- [x] First adversarial review pass (PQ crypto, MEV, formal); findings folded into the design and docs
- [x] Gas benchmarks vs on-chain ML-DSA and Falcon verification ([results](bench/results/RESULTS.md), measured from transaction receipts: the depth-16 commit+reveal flow totals 114K gas for authorization alone, 148K including a 1 ETH transfer, against 1.6M for the cheapest non-standard Falcon verifier and 8.2M for FIPS ML-DSA-44 per call; the two-tx structure breaks even only if basefee rises about 15x between commit and reveal; SLH-DSA rows are cited from upstream publications, not re-run, since no implementation has a license permitting vendoring)
- [x] Formal authorization game ([docs/GAME.md](docs/GAME.md)): the reveal race as a security game against a quantum mempool adversary, theft bounded by beta^a in the block-builder share, cross-checked by the simulator. An adversarial review of the model found a one-transaction denial-of-service (burn-griefing) that the first design missed; the fix (age-gating the defensive nullify) is in the contract, and its consequence is a clean impossibility result: race-free recovery from a leaked leaf cannot exist.
- [x] Adversarial mempool simulator ([tooling/qca-sim](tooling/qca-sim)): Monte Carlo over the game, reproduces every closed-form bound and measures what the proofs cannot (fee-auction ties, concentrated builders, leaked-leaf recovery). Committed result vectors in [sim/results](sim/results).
- [x] Empirical base-fee analysis ([fees/results/RESULTS.md](fees/results/RESULTS.md)): replaying two years of real mainnet base fees (2024-2026), the two-transaction flow was cheaper than every measured PQ verifier at 100% of entry points over the operative minCommitAge window, and beats the cheapest Falcon verifier 99.7% of the time even under a full 256-block censorship delay. The single-number break-even is now a measured distribution.
- [x] Related short note ([DOI 10.5281/zenodo.21446561](https://doi.org/10.5281/zenodo.21446561), *The Cancel Credential Must Be Post-Quantum*): a separate observation with its own artifacts in this repo. In a post-quantum account the credential that cancels or vetoes a pending action must itself be post-quantum, an unused one-time key, because an ordinary ECDSA veto key would re-expose exactly the quantum-breakable surface the account was built to remove. Reference construction in [contracts/src/TimeLockRevokeAccount.sol](contracts/src/TimeLockRevokeAccount.sol) (time-lock queue, permissionless post-delay execute, one-time-key revoke; 54 tests including five proofs of concept), and the cancellation measurement (the owner cancels with probability 1 - beta^Delta against a censoring builder over a Delta-block veto window) via the `cancel` command in [tooling/qca-sim](tooling/qca-sim).
- [ ] Recovery paths for lost leaf state
- [ ] Paper draft

## Also in this repo: an agent wallet-drain coverage map

[`agent-calldata-demo/`](agent-calldata-demo/) is a separate piece of work that
shares this repository. It is not part of the post-quantum protocol above: no
shared code, no shared threat model. It asks a different question with a
different adversary. When an AI agent holds a wallet and a poisoned tool hands it
a benign-looking instruction backed by malicious calldata, which wallet defense
actually stops the drain? The harness runs eight poisoned-tool drains against a
seven-rung ladder of defenses and prints the coverage matrix: English plan-review
catches none of them (the malice is in the bytes, not the words), decoding the
counterparty catches the easy ones, and one drain survives a capability-complete
wallet.

The one honest thread linking it to the protocol above: both are about the gap
between an intended authorization and what actually gets authorized on-chain. The
protocol defends the authorization layer against a quantum adversary; the demo
maps what a poisoned-tool adversary can push through the same layer. Different
work, adjacent question.

Runnable harness, coverage matrix, and the short note (DOI
[10.5281/zenodo.21470174](https://doi.org/10.5281/zenodo.21470174)) in
[agent-calldata-demo/README.md](agent-calldata-demo/README.md).

## License

MIT
