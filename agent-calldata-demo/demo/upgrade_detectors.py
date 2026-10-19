"""Every upgrade detector on the same malicious and benign rows, with intervals.

Malicious: the 1,389 upgrades to a known drainer implementation from
upgrade_expand.py. Benign: the 781 EIP-1967 upgrades from upgrade_baseline.py
(99 of them wallet-relevant, i.e. an EOA sending the upgrade to the proxy
itself, which is the only kind a wallet is ever asked to sign).

Detectors, by defense category:

  rules        type rule          fires on any upgradeTo
               ptxphish rule      Chen et al. (NDSS 2025), Table III:
                                  `param = 'upgradeto' & tx.from != param.owner`.
                                  The paper does not define param.owner, so
                                  both readings are run, at the block before
                                  the upgrade:
                                    impl owner   owner() of the new
                                                 implementation; one with no
                                                 owner() is reported both
                                                 ways (no_owner_fires /
                                                 no_owner_passes)
                                    proxy owner  proxyOwner(), else owner(),
                                                 of the proxy being upgraded;
                                                 no getter counts as a pass
  reputation   goplus on proxy    the address the transaction is sent to
               goplus on impl     the address named in the argument
  label-free   reuse              this implementation was already the target
                                  of an earlier upgrade in the malicious set
               clone              opcode similarity >= CLONE to an
                                  implementation first used earlier
               deployer           deployer also deployed an implementation
                                  first used earlier
               age                implementation at least AGE_DAYS old; the
                                  cutoff is fitted on the 19 PTXPHISH rows
                                  only and tested on the rest
               any label-free     OR of the four

"Earlier" on the malicious side means an upgrade at a lower block in this set,
which is on-chain history a wallet could have indexed. The benign side is
compared against every drainer regardless of date, so its false-positive
counts are upper bounds. Intervals are Wilson 95%.

Needs ETHERSCAN_API_KEY, ALCHEMY_ENDPOINT_URL and GoPlus credentials. Calls
are cached.

    python3 -m demo.upgrade_detectors

Writes results/upgrade_detectors.json.
"""

from __future__ import annotations

import json
import math
import os
import time
import urllib.request

from . import goplus
from .upgrade_expand import tx
from .upgrade_signals import SECONDS_PER_BLOCK, block_of_tx, creation, opcodes, runtime_code, similarity

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RES = os.path.join(_HERE, "results")
_CACHE = os.path.join(_HERE, "cache", "upgrade_detectors.json")
_OUT = os.path.join(_RES, "upgrade_detectors.json")

CLONE = 0.90
OWNER_SELECTOR = "0x8da5cb5b"  # owner()
PROXY_OWNER_SELECTOR = "0x025313a2"  # proxyOwner(), OpenSea's OwnedUpgradeabilityProxy
REP_FIELDS = ("goplus_proxy", "goplus_impl")


def wilson(k: int, n: int, z: float = 1.96) -> list[float] | None:
    if n == 0:
        return None
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


_cache: dict | None = None


def _cached(key: str, fn):
    global _cache
    if _cache is None:
        _cache = json.load(open(_CACHE)) if os.path.exists(_CACHE) else {}
    if key not in _cache:
        _cache[key] = fn()
        os.makedirs(os.path.dirname(_CACHE), exist_ok=True)
        with open(_CACHE, "w") as f:
            json.dump(_cache, f)
    return _cache[key]


def owner_at(address: str, block: int, selector: str = OWNER_SELECTOR) -> str | None:
    """owner() (or another getter) of `address` at `block`, or None if it has none."""
    def call():
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_call",
                           "params": [{"to": address, "data": selector}, hex(block)]}).encode()
        for attempt in range(5):
            try:
                req = urllib.request.Request(os.environ["ALCHEMY_ENDPOINT_URL"], data=body,
                                             headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=40) as r:
                    return json.load(r)
            except (OSError, ValueError):
                if attempt == 4:
                    raise
                time.sleep(2 * (attempt + 1))
    key = f"owner:{address}:{block}" if selector == OWNER_SELECTOR else f"{selector}:{address}:{block}"
    out = _cached(key, call)
    res = out.get("result")
    if not res or len(res) < 66:
        return None  # reverted or returned nothing: no owner() to compare
    return "0x" + res[-40:].lower()


def proxy_owner(proxy: str, block: int) -> str | None:
    return owner_at(proxy, block, PROXY_OWNER_SELECTOR) or owner_at(proxy, block)


def reputation(address: str) -> bool:
    return bool(_cached(f"goplus:{address}", lambda: sorted(goplus.reputation(address))))


def tally(rows: list[dict], fields: list[str]) -> dict:
    n = len(rows)
    return {f: {"fires": sum(bool(r[f]) for r in rows), "of": n,
                "rate": round(sum(bool(r[f]) for r in rows) / n, 4) if n else None,
                "ci95": wilson(sum(bool(r[f]) for r in rows), n)} for f in fields}


def main() -> None:
    sig = json.load(open(os.path.join(_RES, "upgrade_signals.json")))
    expand = json.load(open(os.path.join(_RES, "upgrade_expand.json")))
    base = json.load(open(os.path.join(_RES, "upgrade_baseline.json")))
    pop = json.load(open(os.path.join(_RES, "type_rule_limit.json")))

    # Implementation facts for every drainer, including the sixth family.
    impl = {a: dict(v) for a, v in sig["implementations"].items()}
    for a in {r["implementation"] for r in expand["rows"]} - set(impl):
        c = creation([a])[a]
        impl[a] = {"deployer": c["contractCreator"].lower(), "creation_block": block_of_tx(c["txHash"])}
    ops = {a: opcodes(runtime_code(a)) for a in impl}
    sim = {(a, b): similarity(ops[a], ops[b]) for a in impl for b in impl if a < b}
    sim.update({(b, a): s for (a, b), s in list(sim.items())})

    # --- malicious rows, in block order, each judged on earlier history only
    mal = sorted(expand["rows"], key=lambda r: r["block"])
    first_use: dict[str, int] = {}
    for r in mal:
        first_use.setdefault(r["implementation"], r["block"])

    # First drain of each victim, and so the first block at which each kit had
    # visibly drained someone.
    drain_at, latency = {}, []
    for r in mal:
        blocks = [int(tx(h)["blockNumber"], 16) for h in r["drain_txs"]]
        drain_at[r["tx"]] = min(blocks) if blocks else None
        if blocks:
            latency.append(min(blocks) - r["block"])
    kit_drained_by: dict[str, int] = {}
    for r in mal:
        d = drain_at[r["tx"]]
        if d is not None:
            kit_drained_by[r["implementation"]] = min(d, kit_drained_by.get(r["implementation"], d))

    ptx = [r for r in mal if r["in_ptxphish"]]
    # Fit the age cutoff on PTXPHISH only: the youngest implementation any of
    # those 19 victims signed, rounded down to a whole day.
    age_cut = math.floor(min(r["age_days"] for r in ptx if r["age_days"] is not None))

    mrows = []
    for r in mal:
        a, b = r["implementation"], r["block"]
        earlier = [o for o, fb in first_use.items() if fb < b and o != a]
        age = (b - impl[a]["creation_block"]) * SECONDS_PER_BLOCK / 86400
        own = owner_at(a, b - 1)
        mrows.append({
            "tx": r["tx"], "block": b, "implementation": a, "in_ptxphish": r["in_ptxphish"],
            "drained": r["drained"],
            "type_rule": True,
            "ptxphish_no_owner_fires": own is None or own != r["victim"],
            "ptxphish_no_owner_passes": own is not None and own != r["victim"],
            "ptxphish_proxy_owner": (lambda po: po is not None and po != r["victim"])(
                proxy_owner(r["proxy"], b - 1)),
            "goplus_proxy": bool(r["reputation_on_proxy"]),
            "goplus_impl": bool(r["reputation_on_implementation"]),
            "reuse": first_use[a] < b,
            "drained_before": kit_drained_by.get(a, 1 << 62) < b,
            "clone": any(sim[(a, o)] >= CLONE for o in earlier),
            "deployer": any(impl[o]["deployer"] == impl[a]["deployer"] for o in earlier),
            "age": age >= age_cut,
            "age_days": round(age, 2),
        })
    for m in mrows:
        m["any_label_free"] = m["reuse"] or m["clone"] or m["deployer"] or m["age"]
        m["label_free_no_age"] = m["reuse"] or m["clone"] or m["deployer"]

    # --- benign rows
    drainer_deployers = {v["deployer"] for v in impl.values()}
    senders = {e["tx"]: e["from"].lower() for e in pop["sender_classification"]["per_event"]}
    cand = [a for a in impl if a not in sig["implementations"]]
    brows = []
    for r in base["rows"]:
        a = r["implementation"]
        bops = opcodes(runtime_code(a))
        best = max([r["max_sim_to_drainer"]] + [similarity(bops, ops[c]) for c in cand])
        own = owner_at(a, r["block"] - 1)
        sender = senders.get(r["tx"])
        brows.append({
            "tx": r["tx"], "block": r["block"], "implementation": a,
            "wallet_relevant": r["wallet_relevant"],
            "type_rule": True,
            "ptxphish_no_owner_fires": own is None or own != sender,
            "ptxphish_no_owner_passes": own is not None and own != sender,
            "ptxphish_proxy_owner": (lambda po: po is not None and po != sender)(
                proxy_owner(r["proxy"], r["block"] - 1)),
            "goplus_proxy": reputation(r["proxy"]),
            "goplus_impl": reputation(a),
            "reuse": False,  # benign implementations are not drainers by construction
            "drained_before": False,
            "clone": best >= CLONE,
            "deployer": bool(r["deployer_shipped_a_drainer"]),
            "age": r["age_days"] is not None and r["age_days"] >= age_cut,
            "age_days": r["age_days"],
        })
        b = brows[-1]
        b["deployer"] = b["deployer"] or (_deployer_of(a) in drainer_deployers)
        b["any_label_free"] = b["reuse"] or b["clone"] or b["deployer"] or b["age"]
        b["label_free_no_age"] = b["reuse"] or b["clone"] or b["deployer"]

    fields = ["type_rule", "ptxphish_no_owner_fires", "ptxphish_no_owner_passes",
              "ptxphish_proxy_owner", *REP_FIELDS,
              "reuse", "drained_before", "clone", "deployer", "age", "label_free_no_age", "any_label_free"]
    out_of_sample = [m for m in mrows if not m["in_ptxphish"]]
    first = [m for m in mrows if not m["reuse"]]
    latency.sort()
    summary = {
        "upgrade_to_first_drain_blocks": {
            "victims_drained": len(latency),
            "median": latency[len(latency) // 2],
            "p90": latency[int(0.9 * len(latency))],
            "max": latency[-1],
            "within_5_blocks": sum(x <= 5 for x in latency),
        },
        "age_fires_without_reuse": sum(m["age"] and not m["reuse"] for m in mrows),
        "clone_threshold": CLONE,
        "age_cutoff_days": age_cut,
        "age_cutoff_fitted_on": f"{len(ptx)} PTXPHISH rows",
        "malicious_all": tally(mrows, fields),
        "malicious_out_of_sample": tally(out_of_sample, fields),
        "malicious_first_use_of_each_kit": {"rows": [
            {k: m[k] for k in ("implementation", "block", "goplus_impl", "clone", "deployer", "age", "age_days")}
            for m in first]},
        "benign_all": tally(brows, fields),
        "benign_wallet_relevant": tally([b for b in brows if b["wallet_relevant"]], fields),
    }
    with open(_OUT, "w") as f:
        json.dump({"note": __doc__.split("\n\n")[0], "summary": summary,
                   "malicious": mrows, "benign": brows}, f, indent=1)
        f.write("\n")

    print(f"age cutoff {age_cut} d (fitted on PTXPHISH), clone >= {CLONE}")
    head = f"{'detector':26}" + "".join(f"{h:>22}" for h in
                                        ("malicious", "out-of-sample", "benign", "benign wallet"))
    print(head)
    for fld in fields:
        cells = []
        for key in ("malicious_all", "malicious_out_of_sample", "benign_all", "benign_wallet_relevant"):
            t = summary[key][fld]
            cells.append(f"{t['fires']}/{t['of']} [{t['ci95'][0]:.3f},{t['ci95'][1]:.3f}]")
        print(f"{fld:26}" + "".join(f"{c:>22}" for c in cells))
    print("first use of each kit:")
    for m in first:
        print(f"  {m['implementation'][:10]} block {m['block']} age {m['age_days']} d "
              f"goplus {m['goplus_impl']} clone {m['clone']} deployer {m['deployer']} age_rule {m['age']}")
    print(f"wrote {_OUT}")


def _deployer_of(address: str) -> str | None:
    c = creation([address]).get(address)
    return c["contractCreator"].lower() if c else None


if __name__ == "__main__":
    main()
