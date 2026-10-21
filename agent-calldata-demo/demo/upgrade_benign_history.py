"""The history detectors measured on the benign side, not assumed.

upgrade_detectors.py sets `reuse` and `drained_before` to False for every
benign row, because no benign implementation is a known drainer. That makes
the benign false-positive count for the paper's main detector zero by
construction. This module measures it instead, with the same definitions as
the malicious side:

  reuse            some proxy was upgraded to this implementation at an
                   earlier block
  drained_before   the sender of one of those earlier upgrades, an EOA, lost
                   NFTs or ERC-20 tokens in a transaction it did not send,
                   within 7 days of its upgrade and before this row (the loss
                   rule of upgrade_expand.py); `_any_sender` drops the EOA
                   condition
  drained_via_proxy_before
                   the same, counting only losses in transactions sent to
                   that earlier upgrader's own proxy, which is how this attack
                   moves tokens. Added after the loose rule fired on 192 of
                   the 781 benign rows, mostly marketplace sales.

Only the newest RECENT earlier upgrades are checked, on both sides, so the
two use one detector; a wallet would keep a bounded window too. A row whose
implementation has more earlier upgrades than that is marked `capped`.

    python3 -m demo.upgrade_benign_history

Writes results/upgrade_benign_history.json.
"""

from __future__ import annotations

import json
import os

from .upgrade_detectors import wilson
from .upgrade_expand import LOSS_WINDOW, logs, transfers_out, tx
from .upgrade_signals import runtime_code

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RES = os.path.join(_HERE, "results")
_OUT = os.path.join(_RES, "upgrade_benign_history.json")

RECENT = 50


def earlier_upgrades(impl: str, before: int) -> tuple[list[dict], bool]:
    """The newest RECENT Upgraded(impl) logs below `before`, newest first.

    Searches backwards in doubling windows, so a heavily used implementation
    costs a few small queries rather than its whole history. The flag says
    whether more than RECENT exist.
    """
    found: list[dict] = []
    hi, width = before - 1, 1000
    while hi >= 0 and len(found) <= RECENT:
        lo = max(0, hi - width + 1)
        found += logs(impl, lo, hi)
        hi, width = lo - 1, width * 2
    found.sort(key=lambda l: int(l["blockNumber"], 16), reverse=True)
    return found[:RECENT], len(found) > RECENT


def is_eoa(address: str) -> bool:
    """No code, or only an EIP-7702 delegation marker, which an EOA can add later."""
    code = runtime_code(address)
    return code == "0x" or code.startswith("0xef0100")


def lost_between(sender: str, lo: int, hi: int, proxy: str) -> dict:
    """How tokens left `sender` in [lo, hi] in transactions it did not send.

    `foreign` is the loss rule of upgrade_expand.loss. `via_proxy` keeps only
    transactions sent to `proxy`, the upgraded proxy itself, which is how the
    attack moves the tokens; a sale filled by a marketplace is sent to the
    marketplace. Stops as soon as both are known.
    """
    out = {"foreign": False, "via_proxy": False}
    if hi < lo:
        return out
    for action in ("tokennfttx", "tokentx"):
        for t in transfers_out(sender, lo, hi, action):
            sent = tx(t["hash"])
            if sent["from"].lower() == sender:
                continue
            out["foreign"] = True
            if (sent.get("to") or "").lower() == proxy:
                out["via_proxy"] = True
                return out
    return out


def drained_before(ups: list[dict], before: int) -> dict:
    """Check the earlier upgraders, newest first, for a loss before `before`.

    `any` counts every sender under the loose loss rule; `eoa` only senders
    that are EOAs, the kind a wallet signs for (a contract sender never sends
    its own transactions, so every outflow of it would look foreign);
    `via_proxy` is `eoa` with the loss routed through the upgraded proxy.
    """
    out = {"any": False, "eoa": False, "via_proxy": False, "checked": 0}
    for l in ups:
        out["checked"] += 1
        sender = tx(l["transactionHash"])["from"].lower()
        b = int(l["blockNumber"], 16)
        lost = lost_between(sender, b, min(b + LOSS_WINDOW, before - 1), l["address"].lower())
        if not lost["foreign"]:
            continue
        out["any"] = True
        if is_eoa(sender):
            out["eoa"] = True
            out["via_proxy"] = out["via_proxy"] or lost["via_proxy"]
        if out["eoa"] and out["via_proxy"]:
            break
    return out


def judge(rows: list[dict]) -> list[dict]:
    out = []
    for i, r in enumerate(rows):
        ups, capped = earlier_upgrades(r["implementation"], r["block"])
        d = drained_before(ups, r["block"])
        out.append({"tx": r["tx"], "block": r["block"], "implementation": r["implementation"],
                    "wallet_relevant": r.get("wallet_relevant"),
                    "earlier_upgrades_seen": len(ups), "checked": d["checked"],
                    "capped": capped, "reuse": bool(ups),
                    "drained_before": d["eoa"], "drained_before_any_sender": d["any"],
                    "drained_via_proxy_before": d["via_proxy"]})
        if i % 10 == 0:
            print(f"  {i}/{len(rows)}", flush=True)
    return out


def tally(rows: list[dict], field: str) -> dict:
    k, n = sum(r[field] for r in rows), len(rows)
    return {"fires": k, "of": n, "ci95": wilson(k, n)}


def main() -> None:
    base = json.load(open(os.path.join(_RES, "upgrade_baseline.json")))["rows"]
    mal = json.load(open(os.path.join(_RES, "upgrade_expand.json")))["rows"]

    print(f"benign: {len(base)} rows")
    benign = judge(base)
    print(f"malicious: {len(mal)} rows, same cap")
    malicious = judge(mal)

    wallet = [b for b in benign if b["wallet_relevant"]]
    summary = {"recent_cap": RECENT}
    for name, rows in (("malicious", malicious), ("benign_all", benign), ("benign_wallet_relevant", wallet)):
        summary[name] = {f: tally(rows, f) for f in ("reuse", "drained_before", "drained_before_any_sender",
                                               "drained_via_proxy_before")}
        summary[name]["capped_rows"] = sum(r["capped"] for r in rows)
    with open(_OUT, "w") as f:
        json.dump({"note": __doc__.split("\n\n")[0], "summary": summary,
                   "malicious": malicious, "benign": benign}, f, indent=1)
        f.write("\n")
    print(json.dumps(summary, indent=1))
    print(f"wrote {_OUT}")


if __name__ == "__main__":
    main()
