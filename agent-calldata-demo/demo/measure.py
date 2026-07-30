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

import collections
import json
import os

from . import alchemy, cast, corpus, goplus, rabby, source_tier, tenderly
from .chain import Chain

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")

STATE_MARK = {"catch": "✓", "miss": "✗", "blind": "–", "na": "·", "skip": " "}


class Defense:
    def __init__(self, name, tier, available_fn, verdict_fn, detector=True):
        self.name = name
        self.tier = tier
        self._available = available_fn
        self._verdict = verdict_fn
        # A detector's `catch` means "would have stopped this". An availability
        # lens's `catch` means "the information was readable". Mixing them into
        # one catch-rate table would report a 100% detector and count legitimate
        # verified contracts as false positives, so the aggregates skip them.
        self.detector = detector

    def available(self) -> bool:
        return self._available()

    def verdict(self, case) -> tuple[str, str]:
        return self._verdict(case)


def _goplus_verdict(case) -> tuple[str, str]:
    # Reputation needs an address. Prefer the decoded counterparty/recipient; but
    # an undecodable ON-CHAIN call still has a valid lookup target: the contract
    # the signer is interacting with (the tx `to`). A wallet renders that address
    # even when it cannot decode the calldata, so not looking it up would fake a
    # blind spot. Off-chain signatures with no decoded party are the only true na.
    targets = [a for a in (case.counterparty, case.recipient) if a]
    if not targets and case.kind == "onchain" and case.to:
        targets = [case.to]
    if not targets:
        return "na", "no address to look up (off-chain signature with no decoded party)"
    flags: set[str] = set()
    for a in {t.lower(): t for t in targets}.values():
        flags |= set(goplus.reputation(a, case.chain_id))
    if flags:
        return "catch", "reputation flags: " + ",".join(sorted(flags))
    return "miss", "no known-bad reputation on the target (fresh / rotated / unlabeled address)"


DEFENSES = [
    Defense(alchemy.NAME, alchemy.TIER, alchemy.available, alchemy.verdict),
    # Tenderly's simulation API is now paid / sales-gated (free tier is browser
    # only). Kept here so its skipped column records the obtainability gap.
    Defense(tenderly.NAME, tenderly.TIER, tenderly.available, tenderly.verdict),
    Defense(rabby.NAME, rabby.TIER, rabby.available, rabby.verdict),
    Defense("GoPlus reputation", "hosted",
            lambda: goplus.available() and goplus.preflight(), _goplus_verdict),
    # Reads the code of the object that governs the outcome, which is usually not
    # the transaction target. Availability, not detection: see demo/source_tier.py.
    Defense(source_tier.NAME, source_tier.TIER, source_tier.available, source_tier.verdict,
            detector=False),
]


def build_cases(chain: Chain) -> list[corpus.Case]:
    cases: list[corpus.Case] = []
    if cast.is_up(chain.rpc):
        cases += corpus.synthetic_cases(chain)
    else:
        print("(no anvil node; skipping the synthetic suite. Start one with run.sh "
              "to include it. Continuing with the constructed + real corpus only.)")
    cases += corpus.constructed_sim_cases()   # simulator-tier substrate (real calldata)
    cases += corpus.real_cases()              # rule/reputation-tier substrate (historical)
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
        if not d.detector:
            continue
        seen = [r for r in rows if r["malicious"] and r["verdicts"][d.name]["state"] in ("catch", "miss")]
        caught = sum(1 for r in seen if r["verdicts"][d.name]["state"] == "catch")
        blind = sum(1 for r in rows if r["malicious"] and r["verdicts"][d.name]["state"] == "blind")
        na = sum(1 for r in rows if r["malicious"] and r["verdicts"][d.name]["state"] == "na")
        rate = f"{caught}/{len(seen)}" if seen else "0/0"
        extra = f"  (+{blind} blind, {na} n/a)" if (blind or na) else ""
        tag = "" if d.available() else "  [skipped: not configured]"
        print(f"  {d.name:<28} {rate:>7}{extra}{tag}")

    for d in defenses:
        if d.detector or not d.available():
            continue
        mal = [r for r in rows if r["malicious"]]
        c = collections.Counter(r["verdicts"][d.name]["state"] for r in mal)
        div = sum(1 for r in mal
                  if "IS verified, but it is not the object" in r["verdicts"][d.name]["reason"])
        print(f"\n{d.name} on {len(mal)} malicious cases (availability, not detection):")
        print(f"  readable source for the governing object: {c['catch']}")
        print(f"  code but no verified source:              {c['blind']}")
        print(f"  no code at all (inapplicable):            {c['na']}")
        print(f"  tx target verified but NOT that object:   {div}  <- the wrong-object gap")

    fp_cases = [r for r in rows if not r["malicious"]]
    if fp_cases:
        print("\nFalse positives on benign controls:")
        for d in defenses:
            if not d.detector:
                continue
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
    if goplus.available() and not goplus.preflight():
        print("WARNING: GoPlus keys are set but its API is unreachable (corporate "
              "TLS proxy / network / rate limit). GoPlus is SKIPPED, not measured; "
              "its column below is blank, not a wall of misses. Do NOT freeze the "
              "reputation numbers from this run: rerun off the proxy.")
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
    s = alchemy.STATS
    capped = f", {s['capped']} capped" if s["capped"] else ""
    print(f"Alchemy (PAYG) usage this run: {s['live']} live call(s), {s['cache']} cache hit(s)"
          f"{capped}  [cap {alchemy._MAX_CALLS}, cached responses reused free].")
    if source_tier.available():
        print(source_tier.summary())


if __name__ == "__main__":
    main()
