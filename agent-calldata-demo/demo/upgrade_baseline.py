"""Benign baseline for the label-free upgrade signals.

upgrade_signals.py asks, for each malicious upgradeTo row, what was visible on
chain at signing time without any label: the implementation's age, whether its
bytecode is a near-copy of an implementation already used in a drain, and
whether its deployer already shipped one. Those counts mean nothing on their
own. A signal that fires on every upgrade is a type rule with extra steps.

This module runs the same three signals over the general EIP-1967 population
that type_rule_limit.py collected (800 Upgraded events, four 50k-block windows),
which is overwhelmingly ordinary protocol administration, and reports how often
each would fire there:

  age        implementation age at the upgrade block, against the age range
             the malicious rows show
  clone      highest opcode similarity to any of the five drainer
             implementations (same normalisation as upgrade_signals.py)
  deployer   whether the implementation's deployer deployed any drainer
             implementation

The benign side is compared against all five drainers regardless of date,
while each malicious row only saw drains that came before it. That makes the
benign false-positive counts upper bounds.

Events whose implementation is one of the drainers, or that the reputation
service flags, are taken out of the benign set and listed separately.

Needs ETHERSCAN_API_KEY. Uses the shared Etherscan cache.

    python3 -m demo.upgrade_baseline
"""

from __future__ import annotations

import json
import os
import statistics

from .upgrade_signals import (SECONDS_PER_BLOCK, block_of_tx, creation, opcodes,
                              runtime_code, similarity)

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_POP = os.path.join(_HERE, "results", "type_rule_limit.json")
_SIG = os.path.join(_HERE, "results", "upgrade_signals.json")
_OUT = os.path.join(_HERE, "results", "upgrade_baseline.json")

THRESHOLDS = (0.80, 0.90, 0.95, 0.99)
BATCH = 5  # getcontractcreation takes at most five addresses


def creation_all(addresses: list[str]) -> dict:
    out = {}
    for i in range(0, len(addresses), BATCH):
        out.update(creation(addresses[i:i + BATCH]))
    return out


def best_match(ops: list[str], drainers: dict) -> tuple[float, str | None]:
    best, who = 0.0, None
    for d, dops in drainers.items():
        if not ops or not dops:
            continue
        # Length alone caps the ratio at 2*min/(a+b); skip pairs that cannot
        # beat the current best, since full comparisons on 20 KB contracts
        # are the slow part.
        if 2 * min(len(ops), len(dops)) / (len(ops) + len(dops)) <= best:
            continue
        s = similarity(ops, dops)
        if s > best:
            best, who = s, d
    return best, who


def main() -> None:
    pop = json.load(open(_POP))
    sig = json.load(open(_SIG))

    drainers = {a: opcodes(runtime_code(a)) for a in sig["implementations"]}
    drainer_deployers = {v["deployer"] for v in sig["implementations"].values()}
    mal_ages = [r["age_days"] for r in sig["rows"]]

    flagged = {r["implementation"].lower() for r in pop["rows"] if r["reputation_flags"]}
    events = pop["upgrade_events"]
    # A wallet only ever sees an upgrade an EOA signs and sends to the proxy
    # itself. type_rule_limit.py read the sender's code at the latest block, so
    # an EOA that later added an EIP-7702 delegation (0xef0100...) looked like a
    # contract; it had no code when it signed, so it counts as an EOA here.
    def eoa(e: dict) -> bool:
        return not e["from_is_contract"] or runtime_code(e["from"]).startswith("0xef0100")

    relevant_tx = {e["tx"] for e in pop["sender_classification"]["per_event"]
                   if e["sent_directly_to_proxy"] and eoa(e)}

    excluded = [e for e in events
                if e["implementation"].lower() in drainers or e["implementation"].lower() in flagged]
    benign = [e for e in events if e not in excluded]
    impls = sorted({e["implementation"].lower() for e in benign})

    created = creation_all(impls)
    info = {}
    for n, a in enumerate(impls):
        c = created.get(a)
        code = runtime_code(a)
        ops = opcodes(code)
        sim, who = best_match(ops, drainers)
        info[a] = {
            "deployer": c["contractCreator"].lower() if c else None,
            "creation_block": block_of_tx(c["txHash"]) if c else None,
            "code_bytes": (len(code) - 2) // 2,
            "max_sim_to_drainer": round(sim, 4),
            "closest_drainer": who,
        }
        if n % 50 == 0:
            print(f"  {n}/{len(impls)} implementations")

    rows = []
    for e in benign:
        a = e["implementation"].lower()
        i = info[a]
        age = e["block"] - i["creation_block"] if i["creation_block"] is not None else None
        rows.append({
            "tx": e["tx"], "proxy": e["proxy"], "implementation": a, "block": e["block"],
            "wallet_relevant": e["tx"] in relevant_tx,
            "age_days": round(age * SECONDS_PER_BLOCK / 86400, 2) if age is not None else None,
            "max_sim_to_drainer": i["max_sim_to_drainer"],
            "deployer_shipped_a_drainer": i["deployer"] in drainer_deployers if i["deployer"] else None,
        })

    lo, hi = min(mal_ages), max(mal_ages)

    def summarise(subset: list[dict]) -> dict:
        ages = [r["age_days"] for r in subset if r["age_days"] is not None]
        return {
            "events": len(subset),
            "age_known": len(ages),
            "age_days_median": statistics.median(ages) if ages else None,
            "age_under_1_day": sum(x < 1 for x in ages),
            "age_in_malicious_range": sum(lo <= x <= hi for x in ages),
            "clone_fires": {str(t): sum(r["max_sim_to_drainer"] >= t for r in subset)
                            for t in THRESHOLDS},
            "deployer_fires": sum(bool(r["deployer_shipped_a_drainer"]) for r in subset),
        }

    out = {
        "note": "Label-free upgrade signals run over benign EIP-1967 upgrades. The clone and "
                "deployer checks compare against all five drainer implementations regardless of "
                "date, so these false-positive counts are upper bounds.",
        "malicious_age_days_range": [lo, hi],
        "malicious_max_prior_similarity": max((r["closest_prior_similarity"] or 0)
                                              for r in sig["rows"]),
        "excluded_events": [{"tx": e["tx"], "implementation": e["implementation"],
                             "is_drainer": e["implementation"].lower() in drainers,
                             "reputation_flagged": e["implementation"].lower() in flagged}
                            for e in excluded],
        "all_benign": summarise(rows),
        "wallet_relevant": summarise([r for r in rows if r["wallet_relevant"]]),
        "top_similarities": sorted(({"implementation": a, **v} for a, v in info.items()),
                                   key=lambda x: -x["max_sim_to_drainer"])[:15],
        "rows": rows,
    }
    with open(_OUT, "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")

    print(json.dumps({k: out[k] for k in ("malicious_age_days_range", "malicious_max_prior_similarity",
                                          "all_benign", "wallet_relevant")}, indent=1))
    print(f"excluded {len(excluded)} events; top similarities:")
    for t in out["top_similarities"][:8]:
        print(f"  {t['implementation']}  {t['max_sim_to_drainer']}  {t['code_bytes']} bytes")
    print(f"wrote {_OUT}")


if __name__ == "__main__":
    main()
