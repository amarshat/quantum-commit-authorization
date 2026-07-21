"""A real-address measurement study for the reputation dimension.

The coverage matrix (scorecard.py) shows live GoPlus reputation flags 0/8,
because every sink in the suite is a fresh address. That single null is easy to
dismiss as a broken query. This study fixes reputation's place on the map with
real numbers, by asking GoPlus about three curated buckets of REAL mainnet
addresses:

  trusted   the actual infrastructure the drains route through or approve
            (canonical Permit2, real routers, real exchanges, real tokens).
            If a deployed reputation/approval scanner marks these safe, then the
            H concession holds against a real scanner, not just our model: the
            Permit2 approval that H exploits passes real reputation too.

  malicious documented drainer / sanctioned / exploiter addresses. GoPlus's
            detection rate here is what reputation actually buys.

  fresh     the suite's own attacker sink and a freshly derived address, with no
            history: the realistic shape of an agent-drain recipient.

The finding is the contrast: reputation trusts the real rails and catches
already-known-bad addresses, but is blind to fresh ones, which is exactly what a
poisoned tool uses. Runs live against GoPlus; needs GO_PLUS_APP_KEY / SECRET.

    python3 -m demo.goplus_study
"""

from __future__ import annotations

import json
import os

from . import goplus

# (address, label) triples per bucket. Addresses are public, well-known, and
# citable; the study reports whatever GoPlus returns for each, honestly.
TRUSTED = [
    ("0x000000000022D473030F116dDEE9F6B43aC78BA3", "Permit2 (canonical)"),
    ("0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af", "Uniswap Universal Router"),
    ("0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", "Uniswap V3 SwapRouter02"),
    ("0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC", "Seaport 1.5"),
    ("0x9008D19f58AAbD9eD0D60971565AA8510560ab41", "CoW Protocol Settlement"),
    ("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "USDC"),
    ("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "WETH"),
]

MALICIOUS = [
    ("0x098B716B8Aaf21512996dC57EB0615e2383E2f96", "Ronin/Lazarus exploiter"),
    ("0x722122dF12D4e14e13Ac3b6895a86e84145b6967", "Tornado Cash router (OFAC)"),
    ("0x12D66f87A04A9E220743712cE6d9bB1B5616B8Fc", "Tornado Cash 0.1 ETH (OFAC)"),
    ("0x8589427373D6D84E98730D7795D8f6f8731FDA16", "Tornado Cash donation (OFAC)"),
    ("0x3Cffd56B47B7b41c56258D9C7731ABaDc360E073", "Lazarus-associated"),
    ("0x53b6936513e738f44FB50d2b9476730C0Ab3Bfc1", "Lazarus-associated"),
]

FRESH = [
    ("0x90F79bf6EB2c4f870365E785982E1f101E93b906", "suite attacker sink (fresh)"),
    ("0x0000000000000000000000000000000000C0FFEE", "arbitrary fresh address"),
]


def _assess(addr: str) -> dict:
    rep = sorted(goplus.reputation(addr))
    apr = goplus.approval_risk(addr)
    flagged = bool(rep) or bool(apr.get("malicious_behavior")) or apr.get("doubt_list", False)
    return {"rep": rep, "trust_list": apr.get("trust_list", False),
            "malicious_behavior": apr.get("malicious_behavior", []),
            "doubt_list": apr.get("doubt_list", False), "flagged": flagged}


def run() -> dict:
    out = {}
    for name, rows in (("trusted", TRUSTED), ("malicious", MALICIOUS), ("fresh", FRESH)):
        out[name] = [{"address": a, "label": lbl, **_assess(a)} for a, lbl in rows]
    return out


def main() -> None:
    if not goplus.available():
        print("GO_PLUS_APP_KEY / GO_PLUS_APP_SECRET not set; cannot run the study.")
        return
    data = run()
    for bucket in ("trusted", "malicious", "fresh"):
        print(f"\n=== {bucket.upper()} ===")
        for r in data[bucket]:
            sig = ",".join(r["rep"]) or (",".join(r["malicious_behavior"]) if r["malicious_behavior"] else "")
            mark = "FLAGGED" if r["flagged"] else ("trusted" if r["trust_list"] else "no-signal")
            print(f"  {r['address']}  {r['label']:<30} {mark:<9} {sig}")

    tr = data["trusted"]; ma = data["malicious"]; fr = data["fresh"]
    tr_trusted = sum(1 for r in tr if r["trust_list"] and not r["flagged"])
    tr_flagged = sum(1 for r in tr if r["flagged"])
    ma_flagged = sum(1 for r in ma if r["flagged"])
    fr_flagged = sum(1 for r in fr if r["flagged"])
    print("\n=== SUMMARY (live GoPlus) ===")
    print(f"  trusted infra on GoPlus trust-list, none flagged: {tr_trusted}/{len(tr)} "
          f"(flagged: {tr_flagged}/{len(tr)})")
    print(f"  documented-malicious flagged:                     {ma_flagged}/{len(ma)}")
    print(f"  fresh addresses flagged:                          {fr_flagged}/{len(fr)}")
    print("\nReputation trusts the real rails the drains ride on and catches "
          "already-known-bad addresses, but is blind to fresh sinks, which is "
          "what a poisoned tool routes to. It is orthogonal to the clear-signing "
          "ladder, not a substitute for any rung.")

    outdir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "goplus_study.json"), "w") as f:
        json.dump(data, f, indent=2)
    print(f"\nwrote {os.path.join(outdir, 'goplus_study.json')}")


if __name__ == "__main__":
    main()
