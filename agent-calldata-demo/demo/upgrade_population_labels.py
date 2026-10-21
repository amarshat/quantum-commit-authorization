"""Check the label-free split of upgrade_population_eval.py against labels.

upgrade_population_eval.py splits the non-seeded OpenSea proxy upgrades by
the chain alone: an implementation whose upgrader was drained through the
proxy is an unseeded kit, the rest are benign. Neither side used a label, so
labels are a check on the split rather than an input to it:

  goplus        today's GoPlus flags on each implementation
  scamsniffer   whether ScamSniffer's current list contains it
  has_code      whether the implementation has code today; an upgrade to an
                address with none (or to 0x0 / 0xdead) disables the proxy,
                which is what an owner revoking it would do
  before_warning  upgrades signed before the first public warning
                (28 October 2022, block 15,850,000)

    python3 -m demo.upgrade_population_labels <scamsniffer-repo>

Needs GO_PLUS_APP_KEY / GO_PLUS_APP_SECRET and ALCHEMY_ENDPOINT_URL. Writes
results/upgrade_population_labels.json.
"""

from __future__ import annotations

import json
import os
import sys

from . import goplus
from .upgrade_population import rpc_batch

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RES = os.path.join(_HERE, "results")
_EVAL = os.path.join(_RES, "upgrade_population_eval.json")
_OUT = os.path.join(_RES, "upgrade_population_labels.json")

WARNING_BLOCK = 15_850_000  # about 28 October 2022, the first public warnings


def main() -> None:
    listed_now = open(os.path.join(sys.argv[1], "blacklist", "all.json")).read().lower()
    if not goplus.available() or not goplus.preflight():
        raise SystemExit("Needs GO_PLUS_APP_KEY and GO_PLUS_APP_SECRET.")
    rows = [r for r in json.load(open(_EVAL))["rows"] if r["side"] != "known_kit"]
    impls = sorted({r["implementation"] for r in rows})
    codes = {}
    for i in range(0, len(impls), 100):
        chunk = impls[i:i + 100]
        codes.update(zip(chunk, rpc_batch([("eth_getCode", [a, "latest"]) for a in chunk])))

    per_impl = {}
    for a in impls:
        mine = [r for r in rows if r["implementation"] == a]
        per_impl[a] = {
            "side": mine[0]["side"], "upgrades": len(mine),
            "goplus": sorted(goplus.reputation(a)),
            "scamsniffer": a[2:] in listed_now,
            "has_code": codes[a] not in ("0x", "0x0"),
        }
    summary = {}
    for side in ("unseeded_kit", "benign"):
        mine = {a: v for a, v in per_impl.items() if v["side"] == side}
        rs = [r for r in rows if r["side"] == side]
        summary[side] = {
            "implementations": len(mine),
            "upgrades": len(rs),
            "implementations_goplus_flagged": sum(bool(v["goplus"]) for v in mine.values()),
            "upgrades_goplus_flagged": sum(bool(per_impl[r["implementation"]]["goplus"]) for r in rs),
            "implementations_in_scamsniffer": sum(v["scamsniffer"] for v in mine.values()),
            "upgrades_in_scamsniffer": sum(per_impl[r["implementation"]]["scamsniffer"] for r in rs),
            "upgrades_to_codeless": sum(not per_impl[r["implementation"]]["has_code"] for r in rs),
            "upgrades_before_warning": sum(r["block"] < WARNING_BLOCK for r in rs),
            "drained_via_proxy_before_warning": sum(r["block"] < WARNING_BLOCK and r["drained_via_proxy_after"]
                                                    for r in rs),
        }
    with open(_OUT, "w") as f:
        json.dump({"note": __doc__.split("\n\n")[0], "summary": summary, "per_implementation": per_impl},
                  f, indent=1)
        f.write("\n")
    print(json.dumps(summary, indent=1))
    print(f"wrote {_OUT}")


if __name__ == "__main__":
    main()
