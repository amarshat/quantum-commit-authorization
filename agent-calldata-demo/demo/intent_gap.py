"""Does the artifact a user signs govern which contracts execute against it?

Powered by Etherscan.io APIs.

The rest of this harness measures transactions a user signs directly. An intent
system inverts that: the user signs an *order* and never authors the transaction
that settles it. A solver does, later, and supplies the calls that execute
against the user's approved balance.

So this asks, for CoW Protocol settlements: of the contracts that actually run
against the user's balance, how many appear anywhere in the artifact the user
signed?

    |T|      distinct interaction targets in the settlement
    |S|      addresses derivable from the signed orders in that settlement
             (sell token, buy token, receiver, and the settlement contract)
    |T \\ S|  contracts that govern execution and are named in no order

The prediction registered before this was written (see
private/paper-wrong-object/PREDICTION.md) was a median |T\\S|/|T| above 0.5.

What this is NOT: a vulnerability claim. A CoW order's limit price and receiver
are enforced at settlement, so the value outcome is bounded no matter which
contracts execute. That is the design working. The finding is about what a
defense can *see* at signing time: the signed artifact governs the value bound
and nothing else, while the execution set is governed elsewhere.

Two bounds worth stating with any number this produces:

  * |T| comes from settlement calldata, so contracts reached through nested
    internal calls are invisible. |T| is a LOWER bound on the true governing
    set, which makes the prediction harder to confirm, not easier.
  * Sampling a single block window measures one moment of solver behaviour.
    Use --windows to spread the sample over months.

Gated on ETHERSCAN_API_KEY (free tier: 5 calls/sec). Responses are cached to a
gitignored file, so a re-run is free and offline.

Usage:
    python3 -m demo.intent_gap                      # recent settlements
    python3 -m demo.intent_gap --windows 6 --per-window 20 --spacing-days 45
"""

from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://api.etherscan.io/v2/api"
ATTRIBUTION = "Powered by Etherscan.io APIs"

# CoW Protocol GPv2Settlement, mainnet.
SETTLEMENT = "0x9008d19f58aabd9ed0d60971565aa8510560ab41"
SETTLE_SELECTOR = "0x13d79a0b"

_RATE_SLEEP = float(os.environ.get("ETHERSCAN_RATE_SLEEP", "0.25"))
_CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cache")
_CACHE_FILE = os.path.join(_CACHE_DIR, "intent_gap.json")

STATS = {"live": 0, "cache": 0}
_cache: dict | None = None


def available() -> bool:
    return bool(os.environ.get("ETHERSCAN_API_KEY"))


def _load_cache() -> dict:
    global _cache
    if _cache is None:
        try:
            with open(_CACHE_FILE) as f:
                _cache = json.load(f)
        except (OSError, ValueError):
            _cache = {}
    return _cache


def _save_cache() -> None:
    os.makedirs(_CACHE_DIR, exist_ok=True)
    with open(_CACHE_FILE, "w") as f:
        json.dump(_cache, f)


def _get(params: dict, cache_key: str | None = None) -> dict:
    cache = _load_cache()
    if cache_key and cache_key in cache:
        STATS["cache"] += 1
        return cache[cache_key]
    q = urllib.parse.urlencode({**params, "apikey": os.environ["ETHERSCAN_API_KEY"]})
    req = urllib.request.Request(f"{BASE}?{q}", headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=40) as r:
        out = json.loads(r.read())
    time.sleep(_RATE_SLEEP)
    STATS["live"] += 1
    if cache_key:
        cache[cache_key] = out
        _save_cache()
    return out


# --------------------------------------------------------------------------
# Minimal ABI decoder for GPv2Settlement.settle. Hand-rolled deliberately: the
# artifact has no pip dependencies, and parsing a CLI decoder's printed output
# would be fragile across tool versions.
#
#   settle(address[] tokens,
#          uint256[] clearingPrices,
#          Trade[] trades,                    Trade has a dynamic member (bytes)
#          Interaction[][3] interactions)     fixed 3 (pre, intra, post)
#
#   Trade       = (uint sellTokenIndex, uint buyTokenIndex, address receiver, ...)
#   Interaction = (address target, uint value, bytes callData)
# --------------------------------------------------------------------------

def _word(data: bytes, i: int) -> int:
    return int.from_bytes(data[i * 32:(i + 1) * 32], "big")


def _addr(data: bytes, i: int) -> str:
    return "0x" + data[i * 32 + 12:(i + 1) * 32].hex()


def decode_settle(calldata: str) -> dict:
    """Return {tokens, trades:[{sell,buy,receiver}], targets:[address]}."""
    data = bytes.fromhex(calldata[10:])  # strip 0x + selector

    off_tokens = _word(data, 0) // 32
    off_trades = _word(data, 2) // 32
    off_inter = _word(data, 3) // 32

    n_tokens = _word(data, off_tokens)
    tokens = [_addr(data, off_tokens + 1 + i) for i in range(n_tokens)]

    n_trades = _word(data, off_trades)
    trades = []
    for i in range(n_trades):
        # each element of a dynamic-struct array is an offset from the array body
        rel = _word(data, off_trades + 1 + i) // 32
        base = off_trades + 1 + rel
        trades.append({"sell": _word(data, base), "buy": _word(data, base + 1),
                       "receiver": _addr(data, base + 2)})

    # a fixed-size array of dynamic arrays is itself dynamic: 3 offsets
    targets: list[str] = []
    for phase in range(3):
        rel = _word(data, off_inter + phase) // 32
        arr = off_inter + rel
        n = _word(data, arr)
        for j in range(n):
            srel = _word(data, arr + 1 + j) // 32
            targets.append(_addr(data, arr + 1 + srel))

    return {"tokens": tokens, "trades": trades, "targets": targets}


def measure_settlement(tx: dict) -> dict | None:
    try:
        dec = decode_settle(tx["input"])
    except (ValueError, IndexError):
        return None
    if not dec["targets"]:
        return None
    signed = {SETTLEMENT}
    for t in dec["trades"]:
        signed.add(t["receiver"].lower())
        for idx in (t["sell"], t["buy"]):
            if idx < len(dec["tokens"]):
                signed.add(dec["tokens"][idx].lower())
    executed = {a.lower() for a in dec["targets"]}
    outside = executed - signed
    return {"hash": tx["hash"], "block": int(tx["blockNumber"]),
            "ts": int(tx["timeStamp"]), "trades": len(dec["trades"]),
            "T": len(executed), "S": len(signed), "outside": len(outside),
            "ratio": len(outside) / len(executed), "outside_addrs": sorted(outside)}


def fetch_settlements(start: int, end: int, limit: int) -> list[dict]:
    res = _get({"chainid": "1", "module": "account", "action": "txlist",
                "address": SETTLEMENT, "startblock": str(start), "endblock": str(end),
                "page": "1", "offset": str(limit * 3), "sort": "desc"},
               cache_key=f"txlist:{start}:{end}:{limit}").get("result")
    if not isinstance(res, list):
        return []
    ok = [r for r in res if r.get("input", "").startswith(SETTLE_SELECTOR)
          and r.get("isError") == "0"]
    return ok[:limit]


def latest_block() -> int:
    r = _get({"chainid": "1", "module": "proxy", "action": "eth_blockNumber"})
    return int(r["result"], 16)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--windows", type=int, default=1)
    ap.add_argument("--per-window", type=int, default=40)
    ap.add_argument("--spacing-days", type=int, default=45)
    args = ap.parse_args()

    if not available():
        raise SystemExit("Set ETHERSCAN_API_KEY (free tier is enough).")

    tip = latest_block()
    span = args.spacing_days * 7200  # ~7200 mainnet blocks per day
    rows: list[dict] = []
    for w in range(args.windows):
        end = tip - w * span
        start = end - 7200  # one day of blocks per window
        txs = fetch_settlements(start, end, args.per_window)
        got = [m for m in (measure_settlement(t) for t in txs) if m]
        rows += got
        print(f"  window {w + 1}/{args.windows}: blocks {start}-{end}, "
              f"{len(got)} settlements decoded")

    if not rows:
        raise SystemExit("no settlements decoded")

    ratios = sorted(r["ratio"] for r in rows)
    n = len(ratios)
    median = ratios[n // 2] if n % 2 else (ratios[n // 2 - 1] + ratios[n // 2]) / 2
    outside_all: dict[str, int] = {}
    for r in rows:
        for a in r["outside_addrs"]:
            outside_all[a] = outside_all.get(a, 0) + 1

    print(f"\nsettlements: {n}")
    print(f"median |T\\S|/|T|: {median:.3f}   (registered threshold: > 0.5)")
    print(f"mean:             {sum(ratios) / n:.3f}")
    print(f"all governing contracts absent from the order: {sum(1 for x in ratios if x == 1.0)}/{n}")
    print(f"none absent:                                   {sum(1 for x in ratios if x == 0.0)}/{n}")
    print(f"distinct contracts governing execution but named in no order: {len(outside_all)}")
    print(f"\nP1 {'CONFIRMED' if median > 0.5 else 'NOT confirmed'} against the registered threshold.")
    print(f"|T| is a lower bound: nested internal calls are invisible in calldata.")
    print(f"{STATS['live']} live lookups, {STATS['cache']} cached. {ATTRIBUTION}.")

    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "intent_gap.json"), "w") as f:
        json.dump({"settlements": rows, "outside_counts": outside_all,
                   "median_ratio": median}, f, indent=1)
    print(f"wrote {os.path.join(out_dir, 'intent_gap.json')}")


if __name__ == "__main__":
    main()
