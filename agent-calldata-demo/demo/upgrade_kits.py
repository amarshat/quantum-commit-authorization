"""Where each drain went, and how long each kit ran before a wallet could know.

Two things the paper reports that no other results file holds:

  1. drain routes. upgrade_expand.py counts a loss in any transaction the
     victim did not send. This module reads the destination of each such
     transaction and splits them into those sent to the victim's upgraded
     proxy (how this attack moves tokens) and those sent elsewhere
     (marketplaces, other drainer contracts). It also counts distinct victims,
     since a victim can sign more than one upgrade.

  2. kit-level detection. The six kits are the real unit of analysis: rows of
     one kit are not independent. For each kit, the first upgrade, the first
     upgrade drained-via-proxy-before catches, and the delay between them in
     blocks, days and victims.

    python3 -m demo.upgrade_kits

Writes results/upgrade_kits.json. Reads the Etherscan cache only for
transactions upgrade_expand.py already fetched.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict

from .upgrade_expand import tx

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RES = os.path.join(_HERE, "results")
_OUT = os.path.join(_RES, "upgrade_kits.json")

BLOCKS_PER_DAY = 7200  # 12 s slots


def main() -> None:
    rows = json.load(open(os.path.join(_RES, "upgrade_expand.json")))["rows"]
    hist = {h["tx"]: h for h in json.load(open(os.path.join(_RES, "upgrade_benign_history.json")))["malicious"]}

    drain_txs, to_proxy, elsewhere = set(), set(), defaultdict(int)
    via_proxy_rows, drained_victims, via_proxy_victims = 0, set(), set()
    for r in rows:
        if not r["drained"]:
            continue
        drained_victims.add(r["victim"])
        hit = False
        for h in r["drain_txs"]:
            to = (tx(h).get("to") or "").lower()
            drain_txs.add(h)
            if to == r["proxy"]:
                to_proxy.add(h)
                hit = True
            else:
                elsewhere[to] += 1
        if hit:
            via_proxy_rows += 1
            via_proxy_victims.add(r["victim"])

    kits = []
    by_kit = defaultdict(list)
    for r in rows:
        by_kit[r["implementation"]].append(r)
    for impl, rs in sorted(by_kit.items(), key=lambda kv: min(r["block"] for r in kv[1])):
        rs.sort(key=lambda r: r["block"])
        caught = [r for r in rs if hist[r["tx"]]["drained_via_proxy_before"]]
        first = rs[0]
        k = {"implementation": impl, "upgrades": len(rs), "first_block": first["block"],
             "caught": len(caught), "missed_before_first_catch": 0,
             "delay_blocks": None, "delay_days": None}
        if caught:
            c = caught[0]
            k["first_caught_block"] = c["block"]
            k["missed_before_first_catch"] = sum(r["block"] < c["block"] for r in rs)
            k["delay_blocks"] = c["block"] - first["block"]
            k["delay_days"] = round(k["delay_blocks"] / BLOCKS_PER_DAY, 2)
        k["missed_rows"] = [r["tx"] for r in rs if not hist[r["tx"]]["drained_via_proxy_before"]]
        kits.append(k)

    summary = {
        "malicious_rows": len(rows),
        "distinct_victims": len({r["victim"] for r in rows}),
        "drained_rows": sum(r["drained"] for r in rows),
        "drained_distinct_victims": len(drained_victims),
        "rows_drained_via_proxy": via_proxy_rows,
        "victims_drained_via_proxy": len(via_proxy_victims),
        "drain_txs": len(drain_txs),
        "drain_txs_to_proxy": len(to_proxy),
        "drain_txs_elsewhere": len(drain_txs) - len(to_proxy),
        "top_elsewhere_destinations": sorted(elsewhere.items(), key=lambda kv: -kv[1])[:15],
        "kits": kits,
    }
    with open(_OUT, "w") as f:
        json.dump({"note": __doc__.split("\n\n")[0], "summary": summary}, f, indent=1)
        f.write("\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "kits"}, indent=1))
    for k in kits:
        print(k["implementation"][:10], k["upgrades"], k["caught"], k["missed_before_first_catch"],
              k["delay_blocks"], k["delay_days"])
    print(f"wrote {_OUT}")


if __name__ == "__main__":
    main()
