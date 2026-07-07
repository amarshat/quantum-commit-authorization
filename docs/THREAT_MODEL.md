# Threat model v0.1

Adversary capabilities, attacks considered, mitigations, and the failures we do not claim to solve. Companion to [SPEC.md](SPEC.md).

## Adversary

We assume a quantum-capable adversary who can:

- Break any elliptic-curve keypair whose public key they have seen (Shor). ECDSA, Ed25519 and BLS provide zero security against them.
- Run Grover search, halving the effective preimage-security exponent of hash functions. keccak256 retains ~128-bit preimage security, which we treat as sufficient.
- Observe the full public mempool in real time, extract any calldata (including revealed secrets), and submit transactions with arbitrary fees.
- Build blocks or bribe builders: reorder, insert, and censor transactions within the limits of the fee market and (bounded) reorgs.

They cannot: invert keccak256, forge Merkle membership, or rewrite finalized history.

## Attacks and outcomes

### Reveal-phase theft (the headline attack)

Attacker sees a pending reveal, extracts `secret_i`, and tries to spend with it. To execute any action they need a commitment binding that secret to their action, and commitments must age `minCommitAge` blocks before reveal. The victim's commitment has already aged. Outcome: attacker wins only if the victim's reveal stays unincluded for more than `minCommitAge` blocks after the attacker's commit lands, i.e. theft requires sustained censorship, not observation. This converts a cryptographic break into a liveness race, which is measurable. The simulation milestone exists to measure it.

Residual exposure: a reveal that expires unincluded (fee spike, censorship) leaves its secret public with its commitment dead. The wallet must treat that leaf as burned and must not recommit it, since the attacker can commit to it too and then it is a pure race with no aged-commitment advantage. Tooling enforces leaf burn-on-expiry.

### Commitment front-running and copying

An observer can copy a pending `commit(c)` and post it first. The stored record is identical (same hash, same block); the victim reveals against it unaffected. The copier cannot produce a different valid commitment for the same secret without knowing the secret. Re-commit of an existing hash reverts, so an attacker cannot reset a live commitment's age to hold the victim under `minCommitAge` forever.

### Commit spam and griefing

Commitments are permissionless and 32 bytes plus a block number. A spammer pays full storage gas per slot and imposes no verification cost on anyone else: reveals look up exactly one commitment key. There is no per-account commitment queue to fill; an attacker cannot occupy a victim's "slots" because commitments are keyed by hash, not by account. Cost-to-attacker strictly exceeds cost-imposed. `prune` reclaims expired slots.

### Censorship and reveal-withholding

A builder coalition can suppress a reveal until its commitment expires. The user loses the leaf (burned) and gas, not funds; they rotate or recommit with a fresh leaf. Extortion pressure ("pay or we expire your commitment") is bounded by the cost of censoring every block in the TTL window against the whole builder market. This is the known cost of any commit-reveal scheme; we quantify it rather than claim it away.

### Reorgs

- Commit reorged out, reveal already broadcast: reveal fails (no commitment), secret is now public. Same handling as expiry: leaf burned, never recommitted.
- Reveal reorged out and replayed: the reveal transaction is valid until TTL and anyone can re-land it unchanged; it executes the identical committed action once (nullifier blocks a second execution).
- Nullifier rollback: a reorg deeper than the reveal's confirmation resurrects the leaf bit along with the commitment, and the original reveal can re-execute exactly as committed. NO-REBIND holds across reorgs; ONCE holds per canonical chain. High-value actions should wait for finality like any other transaction.

### Expiry races

Reveal landing exactly at `commitBlock + commitTTL` is valid; one block later is not. An attacker cannot shift either bound (block numbers, not timestamps, so no validator clock games). The sharp edge is user-side fee management near the deadline, which is UX, and it is one of the measured costs in the benchmark milestone.

### Same-block and short-range races

`minCommitAge >= 1` makes commit-then-reveal in one block impossible, killing the classic copy-the-reveal-and-outbid front-run. The residual race window is precisely `minCommitAge` blocks of required censorship, parameterized and under study.

### Cross-context replay

Commitments bind chain id, account address, full action tuple, and leaf index inside one tagged hash with injective encoding. A reveal is not valid on another chain, against another account, for another action, or under a different domain tag. Contentious forks that keep the same chain id replay everything identically by construction of the fork; that is a property of forks, not of this scheme.

## Out of scope / honest failures

- **ECDSA envelope**: today the reveal transaction is carried in an ECDSA-signed envelope. A quantum attacker can steal the envelope's gas-paying EOA, not the account's funds (the committed action is immutable). Full protection needs AA-native or protocol-level integration.
- **Bootstrap window**: root registration is classically signed. If a CRQC exists before an account registers, registration itself can be hijacked. This is a migration design for keys registered while classical crypto still holds.
- **Seed compromise**: the scheme authenticates possession of leaf secrets. A stolen seed is total compromise; rotation is the response if detected in time.
- **State loss**: losing the seed or the leaf-usage index is handled by tooling (deterministic derivation from seed; usage recoverable by scanning chain events), but a lost seed is unrecoverable by design. Guardian/fallback recovery is a roadmap item, not a present property.
- **Fee-market DoS on the user**: two transactions mean two inclusion fees under independent congestion. Whether that is cheaper than one PQ-signature transaction is an open empirical question this project treats as a result, not an assumption.
