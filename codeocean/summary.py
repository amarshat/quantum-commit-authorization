#!/usr/bin/env python3
"""Print the paper's headline numbers from the (re)generated result vectors, so a
reviewer sees the figures/tables reproduce. Pure function of committed/regenerated
files; no arguments."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(rel):
    return json.loads((ROOT / rel).read_text())


def beta_of(c):
    return c["bound_lower"] / c["bound_upper"]


print("=" * 64)
print("Authorization game: simulation vs proved closed form")
print("=" * 64)
theft = load("sim/results/theft-sweep.json")
print("Theorem 1 (i.i.d. builders), theft p_steal vs beta^a at age a=4:")
for c in sorted(theft, key=beta_of):
    if c["params"]["age"] == 4:
        b = beta_of(c)
        print(f"  beta={b:.2f}: sim={c['p_steal']:.5f}  beta^a={b**4:.5f}")

conc = load("sim/results/theft-concentrated.json")
print("\nProposition (Markov builders, persistence p=0.75, a=4):")
for c in sorted(conc, key=beta_of):
    b = beta_of(c)
    p = 0.75
    p_sw = b * (1 - p) / (1 - b)
    lift = c["p_steal"] / (b**4)
    if abs(b - 0.1) < 1e-6:
        print(f"  beta={b:.1f}: sim={c['p_steal']:.5f}  honest-broadcast p_sw*p^3={p_sw*p**3:.5f}"
              f"  stationary beta*p^3={b*p**3:.5f}  lift over beta^a={lift:.0f}x")

print("\n" + "=" * 64)
print("Empirical fee cost (2 years of real Ethereum base fees)")
print("=" * 64)
stats = load("fees/results/basefee-stats.json")["ratio_percentiles_by_gap"]
op = {g: s for g, s in stats.items() if int(g) <= 32}
mx = max(s["max"] for s in op.values())
print(f"  gaps sampled: {sorted(int(g) for g in stats)}")
print(f"  max base-fee ratio over operating window (g<=32): {mx:.2f}x")
print(f"  break-even against cheapest verifier: ~15x (value action) / ~23x (auth only)")
print(f"  => cheaper at 100% of operating-window entry points")

print("\n" + "=" * 64)
print("L1 gas (from committed receipts)")
print("=" * 64)
base = load("bench/results/qca-receipts.json")["depths"]["16"]
flow = int(base["commit_action"]["gasUsed"]) + int(base["reveal_noop"]["gasUsed"])
verifiers = {"ETHFALCON (non-FIPS)": 1_605_156, "Falcon-512 (FIPS)": 4_868_495,
             "ETHDILITHIUM": 4_894_586, "ML-DSA-44 (FIPS)": 8_189_296}
print(f"  depth-16 auth flow (commit+reveal): {flow:,} gas")
for name, g in verifiers.items():
    print(f"    vs {name}: {g/flow:.1f}x cheaper")
