"""Find every upgrade to a known drainer implementation, and what each one lost.

The 19 PTXPHISH rows in upgrade_tier.py are the victims one dataset happened to
record. upgrade_baseline.py found 18 more upgrades to the same five drainer
implementations inside only four 50k-block windows, none of them in PTXPHISH,
so the real population is larger. OpenSea's OwnedUpgradeabilityProxy emits
`Upgraded(address indexed implementation)`, the same event EIP-1967 proxies
emit, so filtering logs on topic0 = that event and topic1 = a drainer
implementation enumerates its victims directly.

Per upgrade this records:

  victim     the upgrade transaction's sender (the proxy owner who signed)
  recall     whether it is one of the 19 PTXPHISH rows; the scan should find
             most of them, or the method has a gap
  reputation GoPlus on the proxy (tx.to) and on the implementation, the same
             within-subjects comparison as upgrade_tier.py
  age        implementation age at the upgrade
  loss       NFT and ERC-20 transfers out of the victim's address within
             LOSS_WINDOW blocks after the upgrade, in transactions the victim
             did not send. A drain through the upgraded proxy is sent by the
             attacker, so this excludes the victim's own sales and moves.

It also compares the one flagged implementation of unknown family that
upgrade_baseline.py surfaced against the five kits.

Needs ETHERSCAN_API_KEY; GoPlus is used when its credentials are set.

    python3 -m demo.upgrade_expand

Writes results/upgrade_expand.json.
"""

from __future__ import annotations

import json
import os

from . import goplus
from .intent_gap import _get
from .type_rule_limit import UPGRADED_TOPIC
from .upgrade_signals import SECONDS_PER_BLOCK, opcodes, runtime_code, similarity

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SIG = os.path.join(_HERE, "results", "upgrade_signals.json")
_TIER = os.path.join(_HERE, "results", "upgrade_tier.json")
_OUT = os.path.join(_HERE, "results", "upgrade_expand.json")

# Flagged by GoPlus in the EIP-1967 sample, not one of the five PTXPHISH kits.
CANDIDATE = "0x3de34a1fd5c088821aa1a03f0f2284af9bff8b37"
LOSS_WINDOW = 7 * 7200  # about seven days of blocks
PAGE = 1000


def logs(impl: str, lo: int, hi: int) -> list[dict]:
    """All Upgraded(impl) logs in [lo, hi], splitting the range when a page fills."""
    topic1 = "0x" + impl[2:].rjust(64, "0")
    r = _get({"chainid": 1, "module": "logs", "action": "getLogs",
              "fromBlock": lo, "toBlock": hi, "topic0": UPGRADED_TOPIC,
              "topic1": topic1, "topic0_1_opr": "and", "page": 1, "offset": PAGE},
             cache_key=f"upgraded-to:{impl}:{lo}:{hi}")
    res = r.get("result")
    if not isinstance(res, list):
        if "No records" in str(r.get("message", "")) or res == []:
            return []
        raise SystemExit(f"getLogs failed for {impl} [{lo},{hi}]: {r}")
    if len(res) >= PAGE and hi > lo:
        mid = (lo + hi) // 2
        return logs(impl, lo, mid) + logs(impl, mid + 1, hi)
    return res


def tx(h: str) -> dict:
    return _get({"chainid": 1, "module": "proxy", "action": "eth_getTransactionByHash",
                 "txhash": h}, cache_key="tx:" + h)["result"]


def latest_block() -> int:
    r = _get({"chainid": 1, "module": "proxy", "action": "eth_blockNumber"})
    return int(r["result"], 16)


def transfers_out(victim: str, lo: int, hi: int, action: str) -> list[dict]:
    r = _get({"chainid": 1, "module": "account", "action": action, "address": victim,
              "startblock": lo, "endblock": hi, "page": 1, "offset": 10000, "sort": "asc"},
             cache_key=f"{action}:{victim}:{lo}:{hi}")
    res = r.get("result")
    if not isinstance(res, list):
        # "No transactions found" is a real empty answer; anything else is a
        # failure and must not be read as zero loss.
        if "no transactions" in str(r.get("message", "")).lower():
            return []
        raise SystemExit(f"{action} failed for {victim} [{lo},{hi}]: {r}")
    return [t for t in res if t["from"].lower() == victim]


def loss(victim: str, block: int) -> dict:
    hi = block + LOSS_WINDOW
    out = {"nft": 0, "erc20": 0, "nft_contracts": set(), "erc20_tokens": set(), "txs": set()}
    for action, kind in (("tokennfttx", "nft"), ("tokentx", "erc20")):
        for t in transfers_out(victim, block, hi, action):
            if tx(t["hash"])["from"].lower() == victim:
                continue  # the victim's own move, not a drain
            out[kind] += 1
            out["nft_contracts" if kind == "nft" else "erc20_tokens"].add(t["contractAddress"].lower())
            out["txs"].add(t["hash"])
    return {"nft_transfers": out["nft"], "erc20_transfers": out["erc20"],
            "nft_contracts": sorted(out["nft_contracts"]),
            "erc20_tokens": sorted(out["erc20_tokens"]),
            "drain_txs": sorted(out["txs"]),
            "drained": bool(out["txs"])}


def main() -> None:
    sig = json.load(open(_SIG))
    kits = sig["implementations"]
    known = {(r["target"].lower(), r["signing_block"]) for r in
             json.load(open(_TIER))["within_subjects"]["per_row"]}

    cand_ops = opcodes(runtime_code(CANDIDATE))
    candidate = {a: round(similarity(cand_ops, opcodes(runtime_code(a))), 4) for a in kits}
    print(f"candidate {CANDIDATE}: similarity to kits {candidate}")

    impls = dict(kits)
    impls[CANDIDATE] = {"creation_block": None}
    tip = latest_block()
    use_goplus = goplus.available()

    rows = []
    for impl, meta in impls.items():
        lo = meta.get("creation_block") or 0
        found = logs(impl, lo, tip)
        print(f"{impl}: {len(found)} upgrades")
        for l in found:
            block = int(l["blockNumber"], 16)
            proxy = l["address"].lower()
            t = tx(l["transactionHash"])
            victim = t["from"].lower()
            row = {
                "tx": l["transactionHash"], "block": block, "proxy": proxy,
                "implementation": impl, "victim": victim,
                "sent_to_proxy": (t.get("to") or "").lower() == proxy,
                "in_ptxphish": (proxy, block) in known,
                "age_days": round((block - meta["creation_block"]) * SECONDS_PER_BLOCK / 86400, 2)
                            if meta.get("creation_block") else None,
                **loss(victim, block),
            }
            if use_goplus:
                row["reputation_on_proxy"] = sorted(goplus.reputation(proxy))
                row["reputation_on_implementation"] = sorted(goplus.reputation(impl))
            rows.append(row)

    rows.sort(key=lambda r: r["block"])
    seen = set()
    for r in rows:
        r["first_use_of_kit"] = r["implementation"] not in seen
        seen.add(r["implementation"])

    n = len(rows)
    summary = {
        "upgrades": n,
        "distinct_victims": len({r["victim"] for r in rows}),
        "by_implementation": {a: sum(r["implementation"] == a for r in rows) for a in impls},
        "ptxphish_rows_found": sum(r["in_ptxphish"] for r in rows),
        "ptxphish_rows_total": len(known),
        "drained_within_window": sum(r["drained"] for r in rows),
        "nft_transfers_out": sum(r["nft_transfers"] for r in rows),
        "erc20_transfers_out": sum(r["erc20_transfers"] for r in rows),
    }
    if use_goplus:
        summary["flagged_aiming_at_proxy"] = sum(bool(r["reputation_on_proxy"]) for r in rows)
        summary["flagged_aiming_at_implementation"] = sum(bool(r["reputation_on_implementation"]) for r in rows)

    out = {"note": __doc__.split("\n\n")[0], "loss_window_blocks": LOSS_WINDOW,
           "candidate": {"address": CANDIDATE, "similarity_to_kits": candidate},
           "summary": summary, "rows": rows}
    with open(_OUT, "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")
    print(json.dumps(summary, indent=1))
    print(f"wrote {_OUT}")


if __name__ == "__main__":
    main()
