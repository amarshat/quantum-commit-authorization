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

That degradation to a censorship race holds only inside an envelope the rest of this document draws explicitly, and all four conditions must hold at once: the reveal is (1) self-submitted, (2) into the public mempool, (3) against a commit that is already final, and (4) by a victim who actively fee-escalates the reveal across the whole `minCommitAge` window. Break any one and it is not a bounded censorship race: a relayed reveal is deterministic theft (see relayed reveals), a reveal against a non-final commit is a reorg theft window (see reorgs), and a passive near-basefee reveal reduces security to the builder lottery (see censorship).

Residual exposure: a reveal that expires unincluded (fee spike, censorship) leaves its secret public with its commitment dead. The leaf is now a bearer authorization for anyone who saw the calldata. The wallet must treat it as burned and never recommit it; better, it should call `burn` to nullify the leaf on-chain, which needs no aged commitment and so wins against any racing attacker. Recording which leaves were exposed is off-chain state that chain-scanning cannot reconstruct (see state loss), so it must be persisted write-ahead, before the reveal is broadcast.

### Relayed and bundled reveals

If the reveal is handed to a relayer or bundler (the normal path for a smart account: ERC-4337 bundlers, gasless relays, private-order flow), the aged-commitment defense collapses. The relayer learns `secret_i` privately, before it is public. It can compute its own commitment for a theft action, post that commit, and simply withhold the victim's reveal. No chain censorship is required, because the relayer holds the only copy of the victim's reveal. After `minCommitAge` blocks the relayer reveals the theft; the victim's still-withheld reveal is now dead on `LeafAlreadyUsed`. The victim's aged commitment is worthless because there was never a race. Handing a reveal to any party is therefore equivalent to handing that party signing authority over the leaf. Reveals must be self-submitted, or only relayed through a party trusted with the account's funds. Binding a beneficiary chosen at commit time would narrow but not close this, since the theft action's beneficiary differs from the victim's.

### Commitment front-running and copying

An observer can copy a pending `commit(c)` and post it first. The stored record is identical (same hash, same block); the victim reveals against it unaffected. The copier cannot produce a different valid commitment for the same secret without knowing the secret. Re-commit of an existing hash reverts, so an attacker cannot reset a live commitment's age to hold the victim under `minCommitAge` forever.

### Commit spam and griefing

Commitments are permissionless and 32 bytes plus a block number. A spammer pays full storage gas per slot and imposes no verification cost on anyone else: reveals look up exactly one commitment key. There is no per-account commitment queue to fill; an attacker cannot occupy a victim's "slots" because commitments are keyed by hash, not by account. Cost-to-attacker strictly exceeds cost-imposed. `prune` reclaims expired slots.

### Censorship and reveal-withholding

A builder coalition can suppress a reveal until its commitment expires. The user loses the leaf and gas, not funds; they rotate or burn and recommit with a fresh leaf. The economic bound is a fee auction and it protects the victim only if the victim is awake and escalating: to keep an actively-bid reveal out for the whole window costs on the order of the value at stake per block, which is unprofitable. A passive reveal posted near basefee from an unattended wallet is cheap to keep out, and then the defense is just the builder lottery: a coalition with block share `p` builds the whole `minCommitAge` window with probability ~`p^minCommitAge` (for `p = 0.5`, `minCommitAge = 4` that is ~6%, not negligible for a high-value target). So `minCommitAge` must be sized against real builder concentration, not latency, and the "reveal must be fee-escalated across the window" precondition is load-bearing. Extortion ("pay or we expire your commitment") is cheapest against a reveal posted late in the window, so reveal in the middle, not at either edge.

### Reorgs

- Commit reorged out, reveal already broadcast: this is a theft window, not just a lost leaf. The reveal reverts because the commitment is gone (the existence check precedes the nullifier write), so the leaf is never nullified on-chain, yet the secret is now public. Any observer can post a fresh commitment for a theft action on that live leaf and, after `minCommitAge`, take it; the victim no longer has an aged-commitment advantage. Defense: do not broadcast a reveal until its commit is final (see the `minCommitAge` two-budget note in the spec), and if a secret does leak this way, call `burn` immediately to nullify the leaf without a race.
- Reveal reorged out and replayed: the reveal transaction is valid until TTL and anyone can re-land it unchanged; it executes the identical committed action once (nullifier blocks a second execution).
- Nullifier rollback: a reorg deeper than the reveal's inclusion depth resurrects the leaf together with its commitment, and the original reveal can re-execute exactly as committed. NO-REBIND holds; ONCE and NO-RESURRECT hold per canonical chain only, not across orphaned branches. High-value actions must wait for finality like any other transaction.

### Expiry races

Reveal landing exactly at `commitBlock + commitTTL` is valid; one block later is not. An attacker cannot shift either bound (block numbers, not timestamps, so no validator clock games). The sharp edge is user-side fee management near the deadline, which is UX, and it is one of the measured costs in the benchmark milestone.

### Same-block and short-range races

`minCommitAge >= 1` makes commit-then-reveal in one block impossible, killing the classic copy-the-reveal-and-outbid front-run. The residual race window is precisely `minCommitAge` blocks of required censorship, parameterized and under study.

### Cross-context replay

The commitment binds chain id, account address, full action tuple, and leaf index inside one tagged hash with injective encoding, so a reveal transaction is not valid on another chain, against another account, for another action, or under a different domain tag. The secret itself is weaker: since commit is permissionless, an observer who sees a revealed secret can post their own commitment on any other account whose current root contains that same leaf. Cross-account isolation therefore rests on roots being distinct, which requires distinct seeds per account. Deploying two accounts from one seed, or rotating back to a previously used root, breaks it. Contentious forks that keep the same chain id replay everything identically by construction of the fork; that is a property of forks, not of this scheme.

### Non-cancellable bearer reveal

The commitment does not bind the reveal's submitter, so a public reveal is a bearer instrument: anyone can land the committed action from any account, and the committer cannot cancel it by replace-by-fee (there is no nonce they control gating it). The action is immutable, but a searcher can choose its block and intra-block position anywhere in the reveal window. For MEV-sensitive actions (swaps, liquidations, auction bids) this is a real timing surface; such actions should be self-submitted privately with a tight self-chosen inclusion window.

## Out of scope / honest failures

- **ECDSA envelope**: today the reveal transaction is carried in an ECDSA-signed envelope. A quantum attacker can steal the envelope's gas-paying EOA, not the account's funds (the committed action is immutable). Full protection needs AA-native or protocol-level integration.
- **Bootstrap window**: root registration is classically signed. If a CRQC exists before an account registers, registration itself can be hijacked. This is a migration design for keys registered while classical crypto still holds.
- **Seed compromise**: the scheme authenticates possession of leaf secrets. A stolen seed is total compromise; rotation is the response if detected in time.
- **State loss**: losing the seed or the leaf-usage index is partly handled by tooling. Secrets derive deterministically from the seed, and *executed* leaves are recoverable by scanning `Revealed`/`LeafBurned` events. But whether a secret was broadcast in an *unincluded* reveal (fee spike, censorship, dropped tx) leaves no on-chain trace, so a wallet that rebuilds state purely by scanning cannot know a leaf is exposed and may recommit it. Wallets must persist "leaf i exposed" write-ahead, before broadcasting the reveal, and fail closed (treat unknown-status leaves as burned). A lost seed is unrecoverable by design. Guardian/fallback recovery is a roadmap item, not a present property.
- **Fee-market DoS on the user**: two transactions mean two inclusion fees under independent congestion. Whether that is cheaper than one PQ-signature transaction is an open empirical question this project treats as a result, not an assumption.
