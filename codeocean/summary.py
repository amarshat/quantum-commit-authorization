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

print("\nMeasured builder concentration (builders/results/stats.json):")
st = load("builders/results/stats.json")
for k, z in st["sizing"].items():
    loc = st["local_sizing"][k]
    print(f"  {k}: median beta={z['beta_median']:.3f} max beta={z['beta_max']:.3f}"
          f"  median p-beta={z['p_minus_beta_median']:+.4f}  run(4)/beta^4={z['run4_over_iid_median']:.2f}")
    for t in ("0.001", "1e-06"):
        print(f"    minCommitAge for {t}: anchor i.i.d. {z['min_commit_age_at_max_beta'][t]},"
              f" local share W=256 {loc['256']['min_commit_age'][t]}, W=128 {loc['128']['min_commit_age'][t]}")
measured = load("sim/results/theft-measured.json")
print("Simulator at measured shares, a=13 and a=25 (sim vs beta^a):")
for c in sorted(measured, key=lambda c: (c["params"]["age"], beta_of(c))):
    if c["params"]["age"] in (13, 25):
        b = beta_of(c)
        print(f"  a={c['params']['age']} beta={b:.4f}: sim={c['p_steal']:.3g}  beta^a={b**c['params']['age']:.3g}")

print("\n" + "=" * 64)
print("Empirical fee cost (2 years of real Ethereum base fees)")
print("=" * 64)
stats = load("fees/results/basefee-stats.json")["ratio_percentiles_by_gap"]
cheaper = load("fees/results/basefee-stats.json")["flow_cheaper_fraction"]
ethf = next(k for k in cheaper if k.startswith("g64|action|ETHFALCON")).split("|", 2)[2]
print(f"  gaps sampled: {sorted(int(g) for g in stats)}")
print(f"  break-even against cheapest verifier: ~15x (value action) / ~23x (auth only)")
print("  operative gap is max(minCommitAge, finality), finality 64-95 blocks:")
for g in (64, 96, 178, 234):
    print(f"    g={g}: max ratio {stats[str(g)]['max']:.2f}x, flow cheaper than ETHFALCON at"
          f" {cheaper[f'g{g}|action|{ethf}'] * 100:.3f}% of entry points")

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
