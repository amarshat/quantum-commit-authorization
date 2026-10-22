"""Where the tokens went: a check of the strict census kits against rescues.

upgrade_population_strict.py calls an implementation a kit when an upgrader
lost tokens in a transaction someone else sent to the upgraded proxy. A
rescue service leaves the same trace: the owner upgrades to a rescue
implementation, the rescuer's bot calls the proxy, and the tokens go to an
address the owner chose. The two differ in where the tokens land. A drainer
sends many victims' tokens to a few addresses it controls; a rescue sends
each owner's tokens to that owner's own safe address. For every strictly
drained upgrade this reads the through-proxy transfers inside its window and
reports, per implementation:

  victims          drained senders
  sinks            distinct recipients of their tokens
  shared_sink      victims whose tokens reached a recipient that also
                   received tokens of another victim of the same kit
  seed_sink        victims whose tokens reached a recipient of a seeded kit
  callers          distinct senders of the draining transactions

A kit passes when some victim's tokens reached a shared or seeded sink. A
kit with one victim and no seeded sink cannot pass or fail.

    python3 -m demo.upgrade_population_sinks

Reads only the Etherscan cache, through the same lookups as first_loss.
Writes results/upgrade_population_sinks.json.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict

from .upgrade_detectors import wilson
from .upgrade_expand import LOSS_WINDOW, transfers_out, tx

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RES = os.path.join(_HERE, "results")
_STRICT = os.path.join(_RES, "upgrade_population_strict.json")
_OUT = os.path.join(_RES, "upgrade_population_sinks.json")


def through_proxy(r: dict) -> list[tuple[str, str]]:
    """(recipient, caller) of each token that left r's sender through its proxy
    inside the strict window."""
    hi = r["block"] + LOSS_WINDOW
    end = r["window_end"] if r["window_end"] is not None else hi + 1
    out = []
    for action in ("tokennfttx", "tokentx"):
        for t in transfers_out(r["sender"], r["block"], hi, action):
            if int(t["blockNumber"]) >= end:
                continue
            sent = tx(t["hash"])
            if sent["from"].lower() == r["sender"] or (sent.get("to") or "").lower() != r["proxy"]:
                continue
            out.append((t["to"].lower(), sent["from"].lower()))
    return out


def main() -> None:
    strict = json.load(open(_STRICT))
    rows = [r for r in strict["rows"] if r["strict_drained"] and r["strict_side"] != "other"]
    moved = {r["tx"]: through_proxy(r) for r in rows}

    seed_sinks = {to for r in rows if r["strict_side"] == "known_kit" for to, _ in moved[r["tx"]]}
    by_impl = defaultdict(list)
    for r in rows:
        by_impl[r["implementation"]].append(r)

    per_impl = {}
    for a, rs in by_impl.items():
        victims_of = defaultdict(set)
        for r in rs:
            for to, _ in moved[r["tx"]]:
                victims_of[to].add(r["sender"])
        shared = {to for to, v in victims_of.items() if len(v) > 1}
        victims = {r["sender"] for r in rs}
        known = rs[0]["strict_side"] == "known_kit"
        per_impl[a] = {
            "side": rs[0]["strict_side"],
            "victims": len(victims),
            "sinks": len(victims_of),
            "shared_sink": len({r["sender"] for r in rs if any(to in shared for to, _ in moved[r["tx"]])}),
            "seed_sink": None if known else len(
                {r["sender"] for r in rs if any(to in seed_sinks for to, _ in moved[r["tx"]])}),
            "callers": len({c for r in rs for _, c in moved[r["tx"]]}),
        }
        v = per_impl[a]
        v["passes"] = bool(v["shared_sink"] or v["seed_sink"])
        v["testable"] = v["passes"] or v["victims"] > 1

    def side(s: str) -> dict:
        mine = {a: v for a, v in per_impl.items() if v["side"] == s}
        return {"implementations": len(mine), "pass": sum(v["passes"] for v in mine.values()),
                "untestable": sum(not v["testable"] for v in mine.values()),
                "fail": sorted(a for a, v in mine.items() if v["testable"] and not v["passes"]),
                "victims": sum(v["victims"] for v in mine.values()),
                "victims_at_shared_or_seed_sink": sum(max(v["shared_sink"], v["seed_sink"] or 0)
                                                      for v in mine.values())}

    summary = {"known_kit": side("known_kit"), "unseeded_kit": side("unseeded_kit")}
    # The categorical warning's precision when only kits that pass count.
    passing = {a for a, v in per_impl.items() if v["passes"]}
    sent = {r["tx"]: r["sent_to_proxy"]
            for r in json.load(open(os.path.join(_RES, "upgrade_population_eval.json")))["rows"]}
    p = strict["summary"]["base_rate"]["categorical_warning_precision"]
    k = sum(sent[r["tx"]] and (r["strict_side"] == "known_kit" or r["implementation"] in passing)
            for r in strict["rows"])
    summary["unseeded_upgrades_of_passing_kits"] = sum(
        r["strict_side"] == "unseeded_kit" and r["implementation"] in passing for r in strict["rows"])
    summary["precision_passing_kits_only"] = {"k": k, "n": p["n"], "ci95": wilson(k, p["n"])}
    with open(_OUT, "w") as f:
        json.dump({"note": __doc__.split("\n\n")[0], "summary": summary, "per_implementation": per_impl},
                  f, indent=1)
        f.write("\n")
    print(json.dumps(summary, indent=1))
    for a, v in sorted(per_impl.items(), key=lambda kv: -kv[1]["victims"]):
        print(" ", a[:10], v)
    print(f"wrote {_OUT}")


if __name__ == "__main__":
    main()
