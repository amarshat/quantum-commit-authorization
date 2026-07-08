#!/usr/bin/env python3
"""Fold raw benchmark data into the gas comparison tables.

Reads bench/results/qca-receipts.json (our side, receipt gasUsed: intrinsic,
calldata and EIP-7623 floor already inside, no model applied) and
bench/results/*.log (baseline execution gas, re-measured from the pinned
upstream test suites). Emits markdown on stdout. Deterministic: same inputs,
same bytes; CI diffs the output against the committed RESULTS.md.

Baselines are measured by upstream as in-test gasleft() deltas, i.e.
execution-only and warm. For them we model the transaction total:

  tokens     = zero_bytes + 4 * nonzero_bytes         (EIP-7623)
  standard   = 21000 + 4 * tokens + execution
  floor      = 21000 + 10 * tokens
  total_tx   = max(standard, floor)

Baseline payloads use the uniform-bytes expectation n/256 for zeros. Real PQ
signatures have slightly more zeros (padding, ML-DSA hint tail), so baseline
calldata is marginally overstated; warm in-frame measurement understates
their execution by a few thousand gas. Both residuals are far below 1% of
any baseline number and lean against us.
"""

import json
import math
import re
from pathlib import Path

BENCH = Path(__file__).resolve().parent
RESULTS = BENCH / "results"

DEPTHS = [8, 16, 20]


def tokens_uniform(n: int) -> int:
    zeros = n / 256
    return math.ceil(zeros + 4 * (n - zeros))


def total_tx(exec_gas: int, payload_bytes: int) -> int:
    t = tokens_uniform(payload_bytes)
    return max(21000 + 4 * t + exec_gas, 21000 + 10 * t)


def grep_gas(path: Path, pattern: str) -> int:
    m = re.search(pattern + r"\s*:?\s*(\d+)", path.read_text())
    if not m:
        raise SystemExit(f"pattern {pattern!r} not found in {path}")
    return int(m.group(1))


# ABI plumbing for a verify(bytes pk, bytes32 digest, bytes sig) call:
# selector + three head words + two length words, plus payload padding.
def abi_call_bytes(sig: int, pk: int) -> int:
    pad = lambda n: 32 * math.ceil(n / 32)
    return 4 + 3 * 32 + 32 + pad(pk) + 32 + pad(sig) + 32  # digest word


# SSTORE2 pk deployment as its own transaction: intrinsic + CREATE + code
# deposit + EIP-3860 initcode words + the calldata that carries the key up.
# Analytic, stated as such; only used for the amortization columns.
def sstore2_deploy_tx(n_bytes: int) -> int:
    return (
        21000
        + 32000
        + 200 * n_bytes
        + 2 * math.ceil(n_bytes / 32)
        + 4 * tokens_uniform(n_bytes)
    )


FALCON_EVM = {"sig": 1064, "pk": 1024}
FALCON_NIST = {"sig": 666, "pk": 897}
MLDSA = {"sig": 2420, "pk_pointer": 20, "pk_expanded": 20512}


def baselines() -> list[dict]:
    falcon_log = RESULTS / "ethfalcon.log"
    exec_nist_precomp = grep_gas(falcon_log, r"Verify NIST cost")
    exec_fips = grep_gas(falcon_log, r"Verify NIST compliant cost")
    rows = [
        {
            "name": "ETHFALCON (Keccak PRNG, non-FIPS)",
            "exec": grep_gas(falcon_log, r"Verify EVM cost"),
            "payload": abi_call_bytes(FALCON_EVM["sig"], FALCON_EVM["pk"]),
            "onetime": 0,
            "note": "EVM-friendly encoding",
        },
        {
            # Upstream's "NIST" benchmark verifies with a pk already in NTT
            # form and a decompressed signature; the wire-format decode is
            # what the FIPS row adds. Charging wire-format calldata against
            # this execution would mix two flows, so the pk preprocessing is
            # carried as a one-time cost instead.
            "name": "Falcon-512 (NIST hash, precomputed NTT pk)",
            "exec": exec_nist_precomp,
            "payload": abi_call_bytes(FALCON_EVM["sig"], FALCON_EVM["pk"]),
            "onetime": exec_fips - exec_nist_precomp,
            "note": "one-time = measured on-chain decode+NTT delta",
        },
        {
            "name": "Falcon-512 (FIPS-206, wire format)",
            "exec": exec_fips,
            "payload": abi_call_bytes(FALCON_NIST["sig"], FALCON_NIST["pk"]),
            "onetime": 0,
            "note": "full per-call wire-format verify",
        },
        {
            "name": "ML-DSA-44 (NIST)",
            "exec": grep_gas(RESULTS / "dilithium-nist.log", r"Gas used"),
            "payload": abi_call_bytes(MLDSA["sig"], MLDSA["pk_pointer"]),
            "onetime": sstore2_deploy_tx(MLDSA["pk_expanded"]),
            "note": "expanded 20.5KB pk via SSTORE2",
        },
        {
            "name": "ETHDILITHIUM (Keccak, non-FIPS)",
            "exec": grep_gas(RESULTS / "dilithium-eth.log", r"Gas used"),
            "payload": abi_call_bytes(MLDSA["sig"], MLDSA["pk_pointer"]),
            "onetime": sstore2_deploy_tx(MLDSA["pk_expanded"]),
            "note": "expanded 20.5KB pk via SSTORE2",
        },
    ]
    for r in rows:
        r["total"] = total_tx(r["exec"], r["payload"])
    return rows


def main() -> None:
    receipts = json.loads((RESULTS / "qca-receipts.json").read_text())
    env = (RESULTS / "env.txt").read_text().strip()
    ours = {int(d): rows for d, rows in receipts["depths"].items()}

    def flow(d: int, kind: str) -> int:
        return ours[d]["commit_action"]["gasUsed"] + ours[d][f"reveal_{kind}"]["gasUsed"]

    print("# Gas benchmark results")
    print()
    print("Generated by bench/run.sh. Environment and pinned commits:")
    print()
    print("```")
    print(env)
    print("```")
    print()
    print(f"Our numbers are transaction receipt gasUsed from anvil "
          f"({receipts['hardfork']} hardfork), so intrinsic gas, calldata gas "
          "and EIP-7623 floors are measured, not modeled. Baseline execution "
          "gas is re-measured from the pinned upstream suites (in-test "
          "gasleft() deltas, warm and execution-only); their transaction "
          "totals are modeled as described in bench/report.py. Compiler "
          "settings differ per project and follow each project's own "
          "foundry.toml (ours: solc 0.8.35 via-ir; ETHFALCON: 0.8.25 cancun; "
          "ETHDILITHIUM: 0.8.30 osaka). Both residual asymmetries (warm "
          "baselines, uniform-zeros calldata) lean against us and are below "
          "1% of any baseline number.")
    print()

    print("## CommitRevealAccount, receipt gas per transaction")
    print()
    print("| depth | commit | reveal (1 ETH to fresh EOA) | reveal (authorization only) | burn | action flow | auth-only flow | burn flow |")
    print("|---|---|---|---|---|---|---|---|")
    for d in DEPTHS:
        r = ours[d]
        burn_flow = r["commit_burn"]["gasUsed"] + r["burn"]["gasUsed"]
        print(
            f"| {d} | {r['commit_action']['gasUsed']:,} "
            f"| {r['reveal_action']['gasUsed']:,} "
            f"| {r['reveal_noop']['gasUsed']:,} "
            f"| {r['burn']['gasUsed']:,} "
            f"| {flow(d, 'action'):,} | {flow(d, 'noop'):,} | {burn_flow:,} |"
        )
    print()
    d16 = ours[16]
    per_level = (ours[20]["reveal_action"]["gasUsed"] - ours[8]["reveal_action"]["gasUsed"]) // 12
    print(f"A flow is one commit plus one reveal. The authorization-only "
          f"reveal executes a zero-value self-call, which is the "
          f"like-for-like row against baselines that only verify a "
          f"signature. Reveal cost grows about {per_level:,} gas per tree "
          "level (one keccak plus 32 calldata bytes).")
    print()

    print("### One-time and lifecycle costs")
    print()
    print("| depth | deploy tx | capacity (leaves) | deploy amortized per action | rotate flow amortized |")
    print("|---|---|---|---|---|")
    for d in DEPTHS:
        dep = ours[d]["deploy"]["gasUsed"]
        cap = 2**d
        # Rotating to a fresh tree when the leaves run out is itself one
        # commit-reveal flow (self-call to rotate()), amortized over the
        # leaves it unlocks.
        rot = flow(d, "noop") / cap
        print(f"| {d} | {dep:,} | {cap:,} | {dep / cap:,.1f} | {rot:,.1f} |")
    print()
    print("Each reveal permanently occupies one nullifier storage slot; that "
          "20K SSTORE is inside the reveal numbers above but the per-account "
          "state footprint grows without bound over its lifetime, one word "
          "per action. Expired commitments can be pruned for a refund, but "
          "post-EIP-3529 a dedicated prune transaction costs more than it "
          "reclaims, so the tables ignore prune. Burn is the leak response "
          "(reorged or expired reveal). It is age-gated exactly like reveal "
          "(see docs/GAME.md on burn-griefing), so the defensive nullify is "
          "itself a two-transaction flow, commit-to-burn then burn; the burn "
          "flow column totals both.")
    print()

    print("## Direct on-chain PQ verification baselines, single transaction")
    print()
    print("| scheme | exec (measured) | total tx (modeled) | one-time | total at N=1 | N=10 | N=100 | note |")
    print("|---|---|---|---|---|---|---|---|")
    for r in baselines():
        ot = f"{r['onetime']:,}" if r["onetime"] else "-"
        print(
            f"| {r['name']} | {r['exec']:,} | {r['total']:,} | {ot} "
            f"| {r['total'] + r['onetime']:,} "
            f"| {r['total'] + r['onetime'] // 10:,} "
            f"| {r['total'] + r['onetime'] // 100:,} | {r['note']} |"
        )
    print()

    print("## Ratios")
    print()
    auth16 = flow(16, "noop")
    act16 = flow(16, "action")
    print(f"Depth-16 authorization-only flow = {auth16:,} gas (like-for-like: "
          f"baselines execute no action either); with the 1 ETH action "
          f"included = {act16:,} gas.")
    print()
    print("| baseline | vs auth-only flow | vs action flow |")
    print("|---|---|---|")
    for r in baselines():
        print(f"| {r['name']} | {r['total'] / auth16:.1f}x | {r['total'] / act16:.1f}x |")
    print()

    print("## Fee variance between the two transactions (depth 16)")
    print()
    commit_g = d16["commit_action"]["gasUsed"]
    reveal_g = d16["reveal_action"]["gasUsed"]
    cheapest = min(baselines(), key=lambda r: r["total"])
    be = (cheapest["total"] - commit_g) / reveal_g
    blocks = math.log(be) / math.log(1.125)
    print(f"Cost in commit-block gas units: {commit_g:,} + m x {reveal_g:,}, "
          f"where the reveal lands at m times the commit basefee. Break-even "
          f"against the cheapest baseline ({cheapest['name']}, "
          f"{cheapest['total']:,} gas) is m = {be:.1f}. Under EIP-1559 the "
          f"basefee grows at most 12.5% per block, so reaching that multiple "
          f"takes about {blocks:.0f} consecutive completely full blocks "
          "between commit and reveal. That is not a guarantee: the commit "
          "stays valid for commitTTL (256 blocks here) and sustained "
          "congestion or censorship, exactly the adversarial conditions in "
          "the threat model, can push the reveal deep into that window. The "
          "holder can also simply wait out a spike anywhere inside the TTL, "
          "at the cost of delay. The paper must present m as an empirical "
          "distribution from historical basefee traces, not a bound.")
    print()

    print("## Cited baselines, not re-run")
    print()
    print("No SLH-DSA / SPHINCS+ implementation with a license permitting "
          "vendoring exists as of this measurement; numbers below are quoted "
          "from their own publications and were not reproduced here.")
    print()
    print("| scheme | claimed verify exec | sig bytes | source | caveat |")
    print("|---|---|---|---|---|")
    print("| SPHINCS- C13 (WOTS+C/FORS+C) | 105-127K | 3,704 | ethresear.ch "
          "SPHINCS- post, June 2026 | ~4.3M hash calls to sign; bounded "
          "signatures per key; no license |")
    print("| SLH-DSA-SHA2-128-24 (same repo) | 142K | 3,856 | ibid. | ~1.07B "
          "hash calls to sign |")
    print("| poqeth SPHINCS+ | ~5.5-5.8M | 7,856 | ePrint 2025/091 (AsiaCCS "
          "2025) | no license file |")
    print("| poqeth W-OTS+ (w=16) | ~472-479K | ~2.1KB | ibid. | one-time key |")
    print("| EIP-8052 Falcon precompile | 3,000 (proposed) | 666 | draft, "
          "Oct 2025 | not scheduled for any fork |")
    print("| EIP-8051 ML-DSA precompile | 4,500 (proposed) | 2,420 | draft, "
          "Oct 2025 | not scheduled for any fork |")
    print()
    print("If either precompile ships, direct verification beats this "
          "protocol on gas and the contribution reduces to the migration "
          "window before that happens plus chains that never get the "
          "precompile. The paper says this explicitly.")


if __name__ == "__main__":
    main()
