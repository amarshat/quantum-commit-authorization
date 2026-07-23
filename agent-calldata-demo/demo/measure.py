"""Empirical coverage measurement: run the corpus past REAL deployed defenses.

Distinct from demo/scorecard.py (the MODELED capability ladder). Here each defense
is a real artifact evaluated at one of two honest tiers:

  - hosted:          a real deployed product queried over its API
                     (Tenderly simulation, GoPlus reputation).
  - open-rules-port: a faithful port of an open-source wallet's published rule
                     logic, fed ground-truth context (Rabby). See demo/rabby.py
                     for exactly what is and is not reproduced.

For each case and defense the verdict is catch / miss / blind / na / skip:
  catch = the defense flags the drain;   miss  = it sees but does not flag it;
  blind = it structurally cannot see the artifact (e.g. a simulator on an
          off-chain signature); na = out of scope for this defense/case
          (e.g. a hosted simulator on a local synthetic chain);
  skip  = the defense is not configured (no API key).

Emits out/measured.json and prints a coverage matrix with tiers labeled, so it is
always clear what is a real API call versus a ported rule set.

    python3 -m demo.measure
"""

from __future__ import annotations

import json
import os

from . import cast, corpus, goplus, rabby, tenderly
from .chain import Chain

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")

STATE_MARK = {"catch": "✓", "miss": "✗", "blind": "–", "na": "·", "skip": " "}


class Defense:
    def __init__(self, name, tier, available_fn, verdict_fn):
        self.name = name
        self.tier = tier
        self._available = available_fn
        self._verdict = verdict_fn

    def available(self) -> bool:
        return self._available()

    def verdict(self, case) -> tuple[str, str]:
        return self._verdict(case)


def _goplus_verdict(case) -> tuple[str, str]:
    flags = set(goplus.reputation(case.counterparty, case.chain_id))
    if case.recipient and case.recipient.lower() != case.counterparty.lower():
        flags |= set(goplus.reputation(case.recipient, case.chain_id))
    if flags:
        return "catch", "reputation flags: " + ",".join(sorted(flags))
    return "miss", "no known-bad reputation on the sink (fresh / rotated address)"


DEFENSES = [
    Defense(tenderly.NAME, tenderly.TIER, tenderly.available, tenderly.verdict),
    Defense(rabby.NAME, rabby.TIER, rabby.available, rabby.verdict),
    Defense("GoPlus reputation", "hosted", goplus.available, _goplus_verdict),
]


def build_cases(chain: Chain) -> list[corpus.Case]:
    cases: list[corpus.Case] = []
    if cast.is_up(chain.rpc):
        cases += corpus.synthetic_cases(chain)
    else:
        print("(no anvil node; skipping the synthetic suite. Start one with run.sh "
              "to include it. Continuing with the real corpus only.)")
    cases += corpus.real_cases()
    return cases


def measure(cases: list[corpus.Case], defenses: list[Defense]) -> list[dict]:
    rows: list[dict] = []
    for c in cases:
        verdicts: dict[str, dict] = {}
        for d in defenses:
            if not d.available():
                verdicts[d.name] = {"state": "skip", "reason": "not configured", "tier": d.tier}
                continue
            state, reason = d.verdict(c)
            verdicts[d.name] = {"state": state, "reason": reason, "tier": d.tier}
        rows.append({
            "id": c.id,
            "source": c.source,
            "label": c.label,
            "malicious": c.malicious,
            "action_type": c.action_type,
            "kind": c.kind,
            "verdicts": verdicts,
        })
    return rows


def print_matrix(rows: list[dict], defenses: list[Defense]) -> None:
    print("\n" + "=" * 84)
    print("MEASURED COVERAGE: corpus x real deployed defenses")
    print("=" * 84)
    for d in defenses:
        cfg = "" if d.available() else "  (not configured)"
        print(f"  {d.name}  [{d.tier}]{cfg}")
    print("\n  " + "  ".join(f"{s}={k}" for k, s in STATE_MARK.items() if k != "skip"))
    print("-" * 84)

    names = [d.name for d in defenses]
    head = f"{'case':<26} {'src':<5} " + " ".join(f"{n.split()[0][:8]:<8}" for n in names)
    print(head)
    for r in rows:
        cells = " ".join(f"{STATE_MARK.get(r['verdicts'][n]['state'], '?'):<8}" for n in names)
        src = "syn" if r["source"] == "synthetic" else r["source"]
        print(f"{r['id']:<26} {src:<5} {cells}")

    print("\nPer-defense catch rate on malicious cases it can actually see "
          "(excludes blind / na / skip):")
    for d in defenses:
        seen = [r for r in rows if r["malicious"] and r["verdicts"][d.name]["state"] in ("catch", "miss")]
        caught = sum(1 for r in seen if r["verdicts"][d.name]["state"] == "catch")
        blind = sum(1 for r in rows if r["malicious"] and r["verdicts"][d.name]["state"] == "blind")
        na = sum(1 for r in rows if r["malicious"] and r["verdicts"][d.name]["state"] == "na")
        rate = f"{caught}/{len(seen)}" if seen else "0/0"
        extra = f"  (+{blind} blind, {na} n/a)" if (blind or na) else ""
        tag = "" if d.available() else "  [skipped: not configured]"
        print(f"  {d.name:<28} {rate:>7}{extra}{tag}")

    fp_cases = [r for r in rows if not r["malicious"]]
    if fp_cases:
        print("\nFalse positives on benign controls:")
        for d in defenses:
            fp = sum(1 for r in fp_cases if r["verdicts"][d.name]["state"] == "catch")
            print(f"  {d.name:<28} {fp}/{len(fp_cases)}")
    else:
        print("\n(No benign controls in the corpus yet; add malicious:false records to "
              "corpus/real/ to measure false-positive rates.)")


def write_files(rows: list[dict]) -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "measured.json"), "w") as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)


def main() -> None:
    chain = Chain()
    cases = build_cases(chain)
    if not cases:
        print("no cases (no anvil node and no corpus/real/*.json). Nothing to measure.")
        return
    rows = measure(cases, DEFENSES)
    print_matrix(rows, DEFENSES)
    write_files(rows)
    print(f"\nwrote {os.path.join(OUT_DIR, 'measured.json')} "
          f"({len(rows)} cases x {len(DEFENSES)} defenses)")


if __name__ == "__main__":
    main()
