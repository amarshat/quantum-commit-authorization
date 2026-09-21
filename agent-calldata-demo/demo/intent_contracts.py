"""Classify the contracts that govern a CoW settlement but appear in no order.

Powered by Etherscan.io APIs.

`demo/intent_gap.py` produces the set T\\S: addresses that executed against a
user's approved balance while named nowhere in the artifact the user signed.
This asks what those addresses are, which is the part that decides whether the
gap matters:

  * verified      is there source to read at all?
  * proxy-shaped  if there is, is it the code that will actually run?
  * age           could a defense holding a fixed allowlist have known it?

The first two are the same failure shapes the historical corpus shows, recovered
at a site with different mechanics. Until 2026-09-19 those counts were produced
by a manual pass over the address list and the paper had to say so; this module
replaces the manual pass, so the numbers regenerate with the run.

    python3 -m demo.intent_contracts        # reads results/intent_gap.json

Writes results/intent_gap_contracts.{json,md}. Responses are cached, so a
re-run is free.
"""

from __future__ import annotations

import json
import os
import sys

from .intent_gap import _get, ATTRIBUTION

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(ROOT, "results")


def classify(addr: str) -> dict:
    res = _get({"chainid": "1", "module": "contract", "action": "getsourcecode",
                "address": addr}, cache_key=f"src:{addr}")
    row = (res.get("result") or [{}])[0]
    if not isinstance(row, dict):
        row = {}
    src = row.get("SourceCode") or ""
    return {
        "address": addr,
        "name": row.get("ContractName") or "",
        "verified": bool(src),
        # Etherscan resolves proxies itself and reports the implementation it
        # found. Trust that over guessing from the contract name.
        "proxy": row.get("Proxy") == "1",
        "implementation": (row.get("Implementation") or "") or None,
    }


def creation_block(addr: str) -> int | None:
    res = _get({"chainid": "1", "module": "contract", "action": "getcontractcreation",
                "contractaddresses": addr}, cache_key=f"created:{addr}")
    r = res.get("result")
    if not isinstance(r, list) or not r:
        return None
    b = r[0].get("blockNumber")
    try:
        return int(b)
    except (TypeError, ValueError):
        return None


def main() -> None:
    path = os.path.join(RESULTS, "intent_gap.json")
    if not os.path.exists(path):
        raise SystemExit(f"{path} not found. Run demo.intent_gap with --end-block first.")
    data = json.load(open(path))
    counts: dict[str, int] = data["outside_counts"]
    n_settlements = data["settlements"]
    # Earliest settlement block in the sample, for the age question.
    first_block = min(r["block"] for r in data["settlement_rows"])

    out = []
    for i, (addr, used) in enumerate(sorted(counts.items(), key=lambda kv: -kv[1]), 1):
        info = classify(addr)
        created = creation_block(addr)
        info["settlements_governed"] = used
        info["created_block"] = created
        info["blocks_old_at_first_settlement"] = (
            first_block - created if created is not None else None)
        out.append(info)
        print(f"  [{i}/{len(counts)}] {addr} {info['name'] or '(unverified)'}",
              file=sys.stderr)

    unverified = [c for c in out if not c["verified"]]
    proxies = [c for c in out if c["proxy"]]
    # ~7200 blocks/day; "young" = deployed within a year of the sample's start.
    young = [c for c in out if c["blocks_old_at_first_settlement"] is not None
             and c["blocks_old_at_first_settlement"] < 365 * 7200]

    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, "intent_gap_contracts.json"), "w") as f:
        json.dump({"note": "Contracts governing execution while named in no signed order.",
                   "source_run": data["params"],
                   "totals": {"distinct": len(out), "unverified": len(unverified),
                              "proxy_shaped": len(proxies), "under_one_year": len(young)},
                   "contracts": out}, f, indent=1)

    lines = [
        "# Contracts that governed execution while named in no signed order",
        "",
        f"From the pinned run in `intent_gap.json`: {n_settlements} CoW settlements, "
        f"end block {data['params']['end_block']}, "
        f"{data['params']['windows']} windows of {data['params']['per_window']} "
        f"spaced {data['params']['spacing_days']} days.",
        "",
        f"- **{len(out)} distinct contracts**",
        f"- **{len(unverified)} have no published source.** At the moment these decide "
        "what happens to a user's approved balance, a code-reading defense has nothing "
        "to read.",
        f"- **{len(proxies)} are proxy-shaped**, so the source that can be read is not "
        "necessarily the code that will run.",
        f"- **{len(young)} were under a year old** at the start of the sample. A defense "
        "holding a fixed allowlist of known-good execution venues would be perpetually "
        "stale.",
        "",
        "Both of the first two are the failure shapes the historical corpus shows, "
        "recovered here at a site with different mechanics, a different signer model "
        "and a different adversary.",
        "",
        "| contract | name | settlements | verified | proxy | created block |",
        "|---|---|---:|---|---|---:|",
    ]
    for c in out:
        lines.append(
            f"| `{c['address']}` | {c['name'] or '—'} | {c['settlements_governed']} | "
            f"{'yes' if c['verified'] else '**no**'} | "
            f"{'**yes**' if c['proxy'] else 'no'} | {c['created_block'] or '—'} |")
    lines += ["", f"*{ATTRIBUTION}.*", ""]
    with open(os.path.join(RESULTS, "intent_gap_contracts.md"), "w") as f:
        f.write("\n".join(lines))

    print(f"\n{len(out)} distinct contracts: {len(unverified)} unverified, "
          f"{len(proxies)} proxy-shaped, {len(young)} under a year old")
    print(f"wrote {RESULTS}/intent_gap_contracts.{{json,md}}")


if __name__ == "__main__":
    main()
