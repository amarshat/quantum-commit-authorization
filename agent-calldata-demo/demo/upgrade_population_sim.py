"""Simulate the census upgrades that are not plain upgradeTo calls.

upgrade_sim.py replays the 1,389 seeded upgrades, all of them upgradeTo,
which by its semantics changes one storage slot and moves nothing. An
upgradeToAndCall runs call data in the proxy's context inside the signed
transaction, so it can move assets there, where a simulator would see them.
This replays every census upgrade whose selector is not upgradeTo, with the
same trace and the same verdict as upgrade_sim.py, at the block before it.

    python3 -m demo.upgrade_population_sim

Needs ALCHEMY_ENDPOINT_URL. Writes results/upgrade_population_sim.json.
"""

from __future__ import annotations

import json
import os
from collections import Counter

from .upgrade_detectors import UPGRADE_TO
from .upgrade_population import rpc_batch
from .upgrade_sim import adverse, asset_changes, logs_of, trace

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RES = os.path.join(_HERE, "results")
_STRICT = os.path.join(_RES, "upgrade_population_strict.json")
_OUT = os.path.join(_RES, "upgrade_population_sim.json")


def main() -> None:
    rows = [r for r in json.load(open(os.path.join(_RES, "upgrade_population_eval.json")))["rows"]
            if r["selector"] != UPGRADE_TO]
    side = {r["tx"]: r["strict_side"] for r in json.load(open(_STRICT))["rows"]}
    txs = []
    for i in range(0, len(rows), 100):
        txs += rpc_batch([("eth_getTransactionByHash", [r["tx"]]) for r in rows[i:i + 100]])
    out = []
    for r, t in zip(rows, txs):
        owner = t["from"].lower()
        call = {"from": t["from"], "to": t["to"], "data": t["input"], "value": t["value"]}
        res = trace(call, r["block"] - 1)
        if "result" not in res:
            out.append({"tx": r["tx"], "side": side[r["tx"]], "selector": r["selector"], "error": res.get("error")})
            continue
        ch = asset_changes(res["result"], owner)
        out.append({"tx": r["tx"], "side": side[r["tx"]], "selector": r["selector"],
                    "implementation": r["implementation"], "logs": len(logs_of(res["result"])),
                    "asset_changes": ch, "simulator_flags": adverse(ch, owner),
                    "reverted": bool(res["result"].get("error"))})
    summary = {}
    for s in ("known_kit", "unseeded_kit", "other"):
        mine = [r for r in out if r["side"] == s]
        ok = [r for r in mine if "error" not in r]
        summary[s] = {"rows": len(mine), "traced": len(ok),
                      "selectors": dict(Counter(r["selector"] for r in mine)),
                      "with_asset_change": sum(bool(r["asset_changes"]) for r in ok),
                      "simulator_flags": sum(r["simulator_flags"] for r in ok),
                      "reverted": sum(r["reverted"] for r in ok)}
    with open(_OUT, "w") as f:
        json.dump({"note": __doc__.split("\n\n")[0], "summary": summary, "rows": out}, f, indent=1)
        f.write("\n")
    print(json.dumps(summary, indent=1))
    print(f"wrote {_OUT}")


if __name__ == "__main__":
    main()
