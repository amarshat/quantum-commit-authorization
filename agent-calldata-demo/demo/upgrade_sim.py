"""What does pre-sign simulation show for a malicious proxy upgrade?

The third defense category on the same rows as upgrade_tier.py. A wallet's
simulator runs the transaction the user is about to sign against current state
and shows the asset changes. Hosted simulators only run against latest state
(alchemy_simulateAssetChanges is latest-only, and these victims' proxies were
upgraded and drained long ago), so this replays each signed upgradeTo with
debug_traceCall at the block before it was mined: the state the victim's
wallet would have simulated against. The trace returns every log the call
emits; asset changes are the Transfer, Approval and ApprovalForAll logs, plus
any ETH value.

The verdict uses the same adverse rule as demo/alchemy.py: an approval from the
owner to someone else, or an asset leaving the owner with nothing coming back.
The expected result, and the reason the case matters, is that an upgrade moves
no assets: the loss lands later, in a transaction the attacker sends, which the
victim's wallet never simulates.

Rows come from results/upgrade_expand.json when it exists (every upgrade to a
known drainer), else from the 19 PTXPHISH rows.

Needs ALCHEMY_ENDPOINT_URL (an archive node with debug_traceCall) and
ETHERSCAN_API_KEY.

    python3 -m demo.upgrade_sim

Writes results/upgrade_sim.json.
"""

from __future__ import annotations

import json
import os
import time
import urllib.request

from .intent_gap import _get
from .upgrade_expand import tx

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TIER = os.path.join(_HERE, "results", "upgrade_tier.json")
_EXPAND = os.path.join(_HERE, "results", "upgrade_expand.json")
_OUT = os.path.join(_HERE, "results", "upgrade_sim.json")
_CACHE = os.path.join(_HERE, "results", ".trace_cache.json")

TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
APPROVAL = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
APPROVAL_FOR_ALL = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"


def _topic_addr(t: str) -> str:
    return "0x" + t[-40:].lower()


def trace(call: dict, block: int) -> dict:
    cache = json.load(open(_CACHE)) if os.path.exists(_CACHE) else {}
    key = f"{call['from']}:{call['to']}:{call['data']}:{block}"
    if key in cache:
        return cache[key]
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "debug_traceCall",
                       "params": [call, hex(block),
                                  {"tracer": "callTracer", "tracerConfig": {"withLog": True}}]}).encode()
    for attempt in range(5):
        try:
            req = urllib.request.Request(os.environ["ALCHEMY_ENDPOINT_URL"], data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=60) as r:
                out = json.load(r)
            break
        except Exception:  # noqa: BLE001  (429s and timeouts on the shared endpoint)
            if attempt == 4:
                raise
            time.sleep(2 * (attempt + 1))
    if "result" in out:
        cache[key] = out
        with open(_CACHE, "w") as f:
            json.dump(cache, f)
    return out


def logs_of(frame: dict) -> list[dict]:
    out = list(frame.get("logs") or [])
    for c in frame.get("calls") or []:
        out += logs_of(c)
    return out


def asset_changes(result: dict, owner: str) -> list[dict]:
    changes = []
    if int(result.get("value", "0x0"), 16):
        changes.append({"kind": "eth", "from": owner, "to": result.get("to"), "value": result["value"]})
    for l in logs_of(result):
        t = l.get("topics") or []
        if not t:
            continue
        if t[0] == TRANSFER and len(t) >= 3:
            changes.append({"kind": "transfer", "token": l["address"].lower(),
                            "from": _topic_addr(t[1]), "to": _topic_addr(t[2])})
        elif t[0] in (APPROVAL, APPROVAL_FOR_ALL) and len(t) >= 3:
            changes.append({"kind": "approval", "token": l["address"].lower(),
                            "from": _topic_addr(t[1]), "to": _topic_addr(t[2])})
    return changes


def adverse(changes: list[dict], owner: str) -> bool:
    out = any(c["from"] == owner and c["to"] != owner for c in changes if c["kind"] != "approval")
    back = any(c["to"] == owner and c["from"] != owner for c in changes)
    approved = any(c["kind"] == "approval" and c["from"] == owner for c in changes)
    return approved or (out and not back)


def rows_in() -> list[dict]:
    if os.path.exists(_EXPAND):
        return [{"id": r["tx"], "tx": r["tx"], "block": r["block"], "proxy": r["proxy"],
                 "drain_txs": r.get("drain_txs", [])}
                for r in json.load(open(_EXPAND))["rows"]]
    out = []
    for r in json.load(open(_TIER))["within_subjects"]["per_row"]:
        b, p = r["signing_block"], r["target"].lower()
        res = _get({"chainid": 1, "module": "logs", "action": "getLogs", "fromBlock": b,
                    "toBlock": b, "address": p}, cache_key=f"logs-at:{p}:{b}")["result"]
        out.append({"id": r["id"], "tx": res[0]["transactionHash"], "block": b, "proxy": p,
                    "drain_txs": []})
    return out


def main() -> None:
    rows = []
    for r in rows_in():
        t = tx(r["tx"])
        owner = t["from"].lower()
        call = {"from": t["from"], "to": t["to"], "data": t["input"], "value": t["value"]}
        res = trace(call, r["block"] - 1)
        if "result" not in res:
            rows.append({**r, "error": res.get("error")})
            continue
        ch = asset_changes(res["result"], owner)
        rows.append({**r, "victim": owner, "selector": t["input"][:10],
                     "logs": len(logs_of(res["result"])), "asset_changes": ch,
                     "simulator_flags": adverse(ch, owner),
                     "loss_in_tx_victim_signed": False if not r["drain_txs"]
                     else r["tx"] in r["drain_txs"]})
        print(f"  {r['id'][:14]}  logs {rows[-1]['logs']}  changes {len(ch)}  flags {rows[-1]['simulator_flags']}")

    ok = [r for r in rows if "error" not in r]
    summary = {
        "rows": len(rows), "traced": len(ok),
        "simulator_flags": sum(r["simulator_flags"] for r in ok),
        "rows_with_any_asset_change": sum(bool(r["asset_changes"]) for r in ok),
        "rows_with_a_later_drain_tx": sum(bool(r["drain_txs"]) for r in ok),
        "errors": len(rows) - len(ok),
    }
    with open(_OUT, "w") as f:
        json.dump({"note": __doc__.split("\n\n")[0], "summary": summary, "rows": rows}, f, indent=1)
        f.write("\n")
    print(json.dumps(summary, indent=1))
    print(f"wrote {_OUT}")


if __name__ == "__main__":
    main()
