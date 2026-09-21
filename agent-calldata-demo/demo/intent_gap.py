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


def block_at(timestamp: int) -> int:
    """The first block at or after `timestamp`. Lets a window be pinned to a
    date rather than to a chain tip that moves between runs."""
    r = _get({"chainid": "1", "module": "block", "action": "getblocknobytime",
              "timestamp": str(timestamp), "closest": "before"},
             cache_key=f"blockno:{timestamp}")
    return int(r["result"])


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


def _sample(tip: int, windows: int, per_window: int,
            spacing_days: int) -> tuple[list[dict], int]:
    """Returns (decoded rows, count dropped for an empty interaction set)."""
    rows: list[dict] = []
    dropped = 0
    for w in range(windows):
        end = tip - w * spacing_days * 7200
        txs = fetch_settlements(end - 7200, end, per_window)
        got = [m for m in (measure_settlement(t) for t in txs) if m]
        dropped += len(txs) - len(got)
        rows += got
    return rows, dropped


def _stats(rows: list[dict], dropped: int = 0) -> dict:
    r = sorted(x["ratio"] for x in rows)
    n = len(r)
    med = r[n // 2] if n % 2 else (r[n // 2 - 1] + r[n // 2]) / 2
    # A settlement whose decoded interaction set is EMPTY is dropped upstream,
    # and an empty T is trivially a subset of S: the signed orders did name
    # every contract that executed, vacuously. Those are therefore instances of
    # `none_absent`, and reporting `none_absent` without them understates the
    # only statistic in this section stable enough to carry a claim. Report the
    # conditioned figure and the unconditioned one side by side; never just the
    # first.
    return {"settlements": n, "median_ratio": med,
            "all_absent": sum(1 for x in r if x == 1.0),
            "none_absent": sum(1 for x in r if x == 0.0),
            "dropped_empty_interactions": dropped,
            "none_absent_unconditioned": sum(1 for x in r if x == 0.0) + dropped,
            "fetched": n + dropped,
            "distinct_outside": len({a for x in rows for a in x["outside_addrs"]})}


def anchor_sweep(args) -> None:
    """How much does each statistic depend on where the sample was anchored?

    The anchor is the chain tip at whatever moment the harness happened to run.
    Nothing about the phenomenon depends on it, so any statistic that moves
    with it is measuring the sample and not the protocol. This exists because
    that turned out to be most of them.
    """
    base = args.end_block or latest_block()
    runs = []
    for i in range(args.anchor_sweep):
        tip = base - i * args.anchor_step
        rows, dropped = _sample(tip, args.windows, args.per_window, args.spacing_days)
        st = _stats(rows, dropped)
        st["anchor_block"] = tip
        runs.append(st)
        print(f"  anchor {tip}: n={st['settlements']} median={st['median_ratio']:.3f} "
              f"all-absent={st['all_absent']} none-absent={st['none_absent']} "
              f"(+{dropped} dropped empty = {st['none_absent_unconditioned']} "
              f"unconditioned of {st['fetched']}) distinct={st['distinct_outside']}")

    print(f"\nacross {len(runs)} anchors spanning "
          f"{(len(runs) - 1) * args.anchor_step} blocks:")
    report = {}
    for k in ("settlements", "median_ratio", "all_absent", "none_absent",
              "none_absent_unconditioned", "dropped_empty_interactions",
              "distinct_outside"):
        v = [r[k] for r in runs]
        report[k] = {"min": min(v), "max": max(v)}
        stable = " STABLE" if min(v) == max(v) else ""
        print(f"  {k:18} min {min(v):<8} max {max(v)}{stable}")

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(os.path.join(root, "results"), exist_ok=True)
    path = os.path.join(root, "results", "intent_gap_sensitivity.json")
    with open(path, "w") as f:
        json.dump({"note": ("Each statistic re-measured at different sampling "
                            "anchors. Anything whose min differs from its max is "
                            "an artifact of where the sample happened to start."),
                   "params": {"windows": args.windows, "per_window": args.per_window,
                              "spacing_days": args.spacing_days,
                              "base_anchor": base, "step": args.anchor_step},
                   "range": report, "runs": runs}, f, indent=1)
    print(f"wrote {path}")
    print(f"{STATS['live']} live lookups, {STATS['cache']} cached. {ATTRIBUTION}.")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--windows", type=int, default=1)
    ap.add_argument("--per-window", type=int, default=40)
    ap.add_argument("--spacing-days", type=int, default=45)
    ap.add_argument("--end-block", type=int, default=None,
                    help="Block the most recent window ends at. PIN THIS. Without "
                         "it the windows are derived from the chain tip at run "
                         "time, so no two runs measure the same blocks and the "
                         "numbers cannot be checked by anyone else.")
    ap.add_argument("--anchor-sweep", type=int, default=0, metavar="N",
                    help="Re-run the whole sample at N different anchor blocks "
                         "and report how much each statistic moves. The anchor "
                         "is an arbitrary choice, so any statistic that is not "
                         "stable across it should not be quoted.")
    ap.add_argument("--anchor-step", type=int, default=100,
                    help="Blocks between anchors in --anchor-sweep (default 100).")
    args = ap.parse_args()

    if not available():
        raise SystemExit("Set ETHERSCAN_API_KEY (free tier is enough).")

    if args.anchor_sweep:
        return anchor_sweep(args)

    if args.end_block:
        tip = args.end_block
        pinned = True
    else:
        tip = latest_block()
        pinned = False
        print("WARNING: --end-block not given, so the windows are anchored to the")
        print("         current chain tip and this run is NOT reproducible. Any")
        print("         number quoted from it is quoted from a sample nobody else")
        print(f"        can fetch. Re-run with --end-block {tip} to pin it.")

    span = args.spacing_days * 7200  # ~7200 mainnet blocks per day
    rows: list[dict] = []
    windows: list[dict] = []
    for w in range(args.windows):
        end = tip - w * span
        start = end - 7200  # one day of blocks per window
        txs = fetch_settlements(start, end, args.per_window)
        decoded = [measure_settlement(t) for t in txs]
        got = [m for m in decoded if m]
        # The drop is not cosmetic: measure_settlement returns None for a
        # settlement with an empty decoded interaction set, which is exactly
        # the population that would falsify the prediction. Count it out loud
        # rather than letting the filter swallow it.
        dropped = len(decoded) - len(got)
        ratios = sorted(m["ratio"] for m in got)
        med = (ratios[len(ratios) // 2] if len(ratios) % 2
               else (ratios[len(ratios) // 2 - 1] + ratios[len(ratios) // 2]) / 2) \
            if ratios else None
        windows.append({"window": w + 1, "start_block": start, "end_block": end,
                        "fetched": len(txs), "decoded": len(got), "dropped": dropped,
                        "median_ratio": med,
                        "all_absent": sum(1 for m in got if m["ratio"] == 1.0),
                        "ts_first": min((m["ts"] for m in got), default=None),
                        "ts_last": max((m["ts"] for m in got), default=None)})
        rows += got
        print(f"  window {w + 1}/{args.windows}: blocks {start}-{end}, "
              f"{len(txs)} fetched, {len(got)} decoded, {dropped} dropped"
              + (f", median {med:.3f}" if med is not None else ""))

    if not rows:
        raise SystemExit("no settlements decoded")

    ratios = sorted(r["ratio"] for r in rows)
    n = len(ratios)
    median = ratios[n // 2] if n % 2 else (ratios[n // 2 - 1] + ratios[n // 2]) / 2
    outside_all: dict[str, int] = {}
    for r in rows:
        for a in r["outside_addrs"]:
            outside_all[a] = outside_all.get(a, 0) + 1

    def dist(key: str) -> dict:
        d: dict[int, int] = {}
        for r in rows:
            d[r[key]] = d.get(r[key], 0) + 1
        return dict(sorted(d.items()))

    s_dist, t_dist = dist("S"), dist("T")

    print(f"\nsettlements: {n}")
    print(f"median |T\\S|/|T|: {median:.3f}   (registered threshold: > 0.5)")
    print(f"mean:             {sum(ratios) / n:.3f}")
    print(f"all governing contracts absent from the order: {sum(1 for x in ratios if x == 1.0)}/{n}")
    print(f"none absent:                                   {sum(1 for x in ratios if x == 0.0)}/{n}")
    print(f"distinct contracts governing execution but named in no order: {len(outside_all)}")
    # |S| is not a constant. The registration assumed four addresses per order;
    # a settlement batching several trades yields more, which shrinks T\S.
    print(f"|S| distribution: " + ", ".join(f"{k}:{v}" for k, v in s_dist.items()))
    print(f"|T| distribution: " + ", ".join(f"{k}:{v}" for k, v in t_dist.items()))
    print(f"\nP1 {'clears' if median > 0.5 else 'does NOT clear'} the registered threshold "
          f"on the pooled sample.")
    print("|T| is a lower bound: nested internal calls are invisible in calldata.")
    print("|T\\S| is an upper bound: appData-committed hook targets are not decoded.")
    if not pinned:
        print("This run is NOT reproducible: re-run with --end-block to pin the windows.")
    print(f"{STATS['live']} live lookups, {STATS['cache']} cached. {ATTRIBUTION}.")

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir = os.path.join(root, "results" if pinned else "out")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "intent_gap.json")
    with open(path, "w") as f:
        json.dump({
            "note": ("Signed-order versus executed-contract gap in CoW Protocol "
                     "settlements. `outside_addrs` per settlement are the contracts "
                     "that executed and appear in no signed order. |T| is a lower "
                     "bound (nested internal calls are invisible in calldata) and "
                     "|T\\S| an upper bound (appData hook commitments are not "
                     "decoded)."),
            "reproducible": pinned,
            "params": {"windows": args.windows, "per_window": args.per_window,
                       "spacing_days": args.spacing_days, "end_block": tip,
                       "window_span_blocks": 7200,
                       "settlement_contract": SETTLEMENT},
            "window_ranges": windows,
            "settlements": n,
            "median_ratio": median,
            "mean_ratio": sum(ratios) / n,
            "all_absent": sum(1 for x in ratios if x == 1.0),
            "none_absent": sum(1 for x in ratios if x == 0.0),
            "S_distribution": s_dist,
            "T_distribution": t_dist,
            "distinct_outside_contracts": len(outside_all),
            "outside_counts": outside_all,
            "settlement_rows": rows,
        }, f, indent=1)
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
