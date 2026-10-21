"""Every upgrade of an OpenSea user proxy, found without any label.

The malicious set in upgrade_expand.py is seeded by six known drainer
implementations, and the benign set in upgrade_baseline.py is general
EIP-1967 administration, a different kind of proxy. Both choices bias the
history detectors: a kit nobody found is absent, and a benign proxy almost
never holds rights over its upgrader's tokens, so a drain through it cannot
happen. This module builds the population both sides should come from.

Every OpenSea user proxy (an OwnableDelegateProxy from the Wyvern registry)
emits `Upgraded(AuthenticatedProxy)` when it is created and shares one
runtime bytecode. So:

  1. collect every Upgraded event from START_BLOCK to the tip (eth_getLogs
     on topic0 only, in windows that halve on a too-many-results error);
  2. keep events whose implementation is not AuthenticatedProxy, i.e. later
     upgrades;
  3. keep those emitted by an address whose runtime code equals the OpenSea
     user proxy's;
  4. read each upgrade transaction: sender, destination, selector.

No label is used. Known kits are marked afterwards, for comparison only.

Uses ALCHEMY_ENDPOINT_URL only, with its own cache (cache/population.json),
so it can run while Etherscan-based modules run.

    python3 -m demo.upgrade_population

Writes results/upgrade_population.json.
"""

from __future__ import annotations

import atexit
import json
import os
import time
import urllib.request

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CACHE_FILE = os.path.join(_HERE, "cache", "population.json")
_OUT = os.path.join(_HERE, "results", "upgrade_population.json")
_EXPAND = os.path.join(_HERE, "results", "upgrade_expand.json")

UPGRADED = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"
AUTHENTICATED_PROXY = "0xf9e266af4bca5890e2781812cc6a6e89495a79f2"
# Any OpenSea user proxy; all share this runtime code.
REFERENCE_PROXY = "0xdfda474da220e477ed6111e3e55f7fe1c8ad64ef"
START_BLOCK = 15_000_000  # June 2022, before the first public warning (Oct 2022)
WINDOW = 2_000

_cache: dict | None = None
_last_save = 0.0


def _load() -> dict:
    global _cache
    if _cache is None:
        try:
            with open(_CACHE_FILE) as f:
                _cache = json.load(f)
        except (OSError, ValueError):
            _cache = {}
        atexit.register(_save)
    return _cache


def _save() -> None:
    global _last_save
    _last_save = time.monotonic()
    os.makedirs(os.path.dirname(_CACHE_FILE), exist_ok=True)
    tmp = _CACHE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(_cache, f)
    os.replace(tmp, _CACHE_FILE)


def rpc(method: str, params: list, key: str | None = None):
    cache = _load()
    if key and key in cache:
        return cache[key]
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    for attempt in range(6):
        try:
            req = urllib.request.Request(os.environ["ALCHEMY_ENDPOINT_URL"], data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=60) as r:
                out = json.load(r)
            break
        except (OSError, ValueError):  # 429s, resets, timeouts
            if attempt == 5:
                raise
            time.sleep(2 * (attempt + 1))
    if "error" in out:
        return out  # not cached: callers decide (e.g. split the window)
    if key:
        cache[key] = out["result"]
        if time.monotonic() - _last_save > 30:
            _save()
    return out["result"]


def upgraded_logs(lo: int, hi: int) -> list[list]:
    """Upgraded events in [lo, hi] as [block, tx, emitter, implementation]."""
    key = f"logs:{lo}:{hi}"
    cache = _load()
    if key in cache:
        return cache[key]
    out = rpc("eth_getLogs", [{"fromBlock": hex(lo), "toBlock": hex(hi), "topics": [UPGRADED]}])
    if isinstance(out, dict) and "error" in out:
        if hi == lo:
            raise SystemExit(f"eth_getLogs failed on one block {lo}: {out['error']}")
        mid = (lo + hi) // 2
        return upgraded_logs(lo, mid) + upgraded_logs(mid + 1, hi)
    rows = [[int(l["blockNumber"], 16), l["transactionHash"], l["address"].lower(),
             "0x" + l["topics"][1][-40:].lower()] for l in out if len(l["topics"]) > 1]
    cache[key] = rows
    return rows


def code(address: str) -> str:
    return rpc("eth_getCode", [address, "latest"], key="code:" + address)


def transaction(h: str) -> dict:
    t = rpc("eth_getTransactionByHash", [h], key="tx:" + h)
    return {"from": t["from"].lower(), "to": (t.get("to") or "").lower(), "selector": t["input"][:10]}


def main() -> None:
    tip = int(rpc("eth_blockNumber", []), 16)
    later: list[list] = []
    total = 0
    for lo in range(START_BLOCK, tip + 1, WINDOW):
        rows = upgraded_logs(lo, min(lo + WINDOW - 1, tip))
        total += len(rows)
        later += [r for r in rows if r[3] != AUTHENTICATED_PROXY]
        if (lo - START_BLOCK) // WINDOW % 250 == 0:
            print(f"  block {lo:,}: {total:,} Upgraded events, {len(later):,} not to AuthenticatedProxy",
                  flush=True)

    ref = code(REFERENCE_PROXY)
    emitters = sorted({r[2] for r in later})
    print(f"{len(emitters):,} distinct emitters to classify")
    opensea = {e for i, e in enumerate(emitters) if code(e) == ref}
    pop = [r for r in later if r[2] in opensea]
    print(f"{len(pop):,} upgrades of {len(opensea):,} OpenSea user proxies")

    kits = {r["implementation"] for r in json.load(open(_EXPAND))["rows"]}
    rows = []
    for block, h, proxy, impl in pop:
        t = transaction(h)
        rows.append({"tx": h, "block": block, "proxy": proxy, "implementation": impl,
                     "sender": t["from"], "to": t["to"], "selector": t["selector"],
                     "sent_to_proxy": t["to"] == proxy, "known_kit": impl in kits})
    _save()

    by_impl: dict[str, int] = {}
    for r in rows:
        by_impl[r["implementation"]] = by_impl.get(r["implementation"], 0) + 1
    summary = {
        "start_block": START_BLOCK, "tip": tip,
        "upgraded_events": total,
        "events_not_to_authenticated_proxy": len(later),
        "opensea_proxy_upgrades": len(rows),
        "opensea_proxies_upgraded": len({r["proxy"] for r in rows}),
        "implementations": len(by_impl),
        "upgrades_to_known_kits": sum(r["known_kit"] for r in rows),
        "upgrades_to_other_implementations": sum(not r["known_kit"] for r in rows),
        "selectors": {s: sum(r["selector"] == s for r in rows) for s in sorted({r["selector"] for r in rows})},
        "top_implementations": sorted(by_impl.items(), key=lambda kv: -kv[1])[:40],
    }
    with open(_OUT, "w") as f:
        json.dump({"note": __doc__.split("\n\n")[0], "summary": summary, "rows": rows}, f, indent=1)
        f.write("\n")
    print(json.dumps(summary, indent=1))
    print(f"wrote {_OUT}")


if __name__ == "__main__":
    main()
