# Code Ocean reproduction capsule

Regenerates the paper's **offline, deterministic** results and verifies they are
byte-identical to the committed vectors, then prints the headline numbers behind the
figures and tables. Reproducing (all confirmed byte-identical):

- **Authorization game** (`sim/results/*.json`): the theft race Theorem (beta^a under
  i.i.d. builders), the passive-victim corollary, the recovery bracket, and the
  Markov-builder concentration proposition. Deterministic Monte-Carlo (ChaCha8 seeded).
- **Cross-implementation golden vectors** (`golden.json`): the Rust `qca-core`
  hashing/commitment vectors the Solidity suite asserts against.
- **Empirical fee cost** (`fees/results/*`): the break-even and the
  100%-of-entry-points result, computed from the committed two-year base-fee dataset.
- **Gas report** (`bench/report.py`): the L1 gas table from the committed receipts.
- **Rust unit tests** (`qca-core`, `qca-cli`, `qca-sim`).

## Excluded (and why)

The live-chain and network steps cannot run in a sandbox and are **not** in the
capsule; their committed outputs are the inputs reproduced above:

- the zkSync Era Sepolia on-chain deploy and measurement (needs a funded testnet key
  and the public network; verifiable via the block-explorer links in the receipts),
- the anvil-based L1 gas measurement (needs the Foundry toolchain),
- the archive-node base-fee fetch (one-time data collection; the sample is committed).

## Setup on Code Ocean

1. Create a capsule and attach this repository as the code
   (`https://github.com/amarshat/quantum-commit-authorization`).
2. Environment: use `codeocean/Dockerfile` (Ubuntu + Rust 1.82 + Python 3 stdlib).
3. Run command: `codeocean/run`.

Expected: the run prints `[MATCH]` for each result set, the headline-numbers block,
and finishes with `Reproduced 3/3 committed result sets byte-identically.` Results
(`gas-report.md`, `summary.txt`) are written to `/results`. Runtime is a few minutes,
dominated by the 2,000,000-trial simulator sweeps.

## Run locally

```
bash codeocean/run     # from the repo root; needs cargo + python3
```
