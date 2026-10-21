"""The detectors, frozen, on every upgrade of an OpenSea user proxy.

upgrade_population.py lists every later upgrade of an OpenSea user proxy
since block 15,000,000, with no label. This module:

  1. reads, for each upgrade, whether tokens left its sender within seven
     days in a transaction sent to the upgraded proxy by someone else. On an
     OpenSea user proxy a legitimate trade is sent to the exchange, not to the
     proxy, so this is the attack's own signature, and it needs no label;
  2. groups upgrades by implementation. An implementation none of whose
     upgraders was drained that way is the benign side; one with such a drain
     that is not among the six known kits is a kit nobody seeded, found
     without a label, and its upgrades are a held-out malicious side;
  3. runs the detectors exactly as defined in upgrade_benign_history.py and
     upgrade_detectors.py, unchanged, on both sides: the type rule scoped to
     OpenSea proxies, the implementation-deployer reading of the PTXPHISH
     rule, and drained-via-proxy-before.

drained-via-proxy-before is computed from one loss lookup per earlier
upgrade (the first block its sender lost tokens), not one per pair, which
gives the same answer as upgrade_benign_history.drained_before.

Needs ETHERSCAN_API_KEY; uses the shared Etherscan cache, so do not run it
alongside another Etherscan module.

    python3 -m demo.upgrade_population_eval

Writes results/upgrade_population_eval.json.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict

from .upgrade_benign_history import RECENT, earlier_upgrades, is_eoa
from .upgrade_detectors import UPGRADE_TO, UPGRADE_TO_AND_CALL, wilson
from .intent_gap import _get, _load_cache
from .upgrade_expand import LOSS_WINDOW, transfers_out, tx
from .upgrade_population import rpc_batch

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RES = os.path.join(_HERE, "results")
_POP = os.path.join(_RES, "upgrade_population.json")
_OUT = os.path.join(_RES, "upgrade_population_eval.json")

_first_loss: dict[tuple, dict] = {}


def prefetch(hashes: list[str]) -> None:
    """Fetch uncached transactions from the archive node in batches and store
    them in the Etherscan cache under tx()'s key, so tx() reads them from
    there. An active trader has hundreds of transfers, and one Etherscan call
    each at three a second is what makes this module slow otherwise."""
    cache = _load_cache()
    todo = sorted({h for h in hashes if "tx:" + h not in cache})
    for i in range(0, len(todo), 100):
        chunk = todo[i:i + 100]
        for h, t in zip(chunk, rpc_batch([("eth_getTransactionByHash", [h]) for h in chunk])):
            cache["tx:" + h] = {"result": t}


def first_loss(sender: str, block: int, proxy: str) -> dict:
    """First block in [block, block+LOSS_WINDOW] at which `sender` lost tokens
    in a transaction it did not send (`foreign`), and in one sent to `proxy`
    (`via_proxy`); None where there was none."""
    key = (sender, block, proxy)
    if key in _first_loss:
        return _first_loss[key]
    out = {"foreign": None, "via_proxy": None}
    moved = [t for action in ("tokennfttx", "tokentx")
             for t in transfers_out(sender, block, block + LOSS_WINDOW, action)]
    prefetch([t["hash"] for t in moved])
    for t in moved:
        sent = tx(t["hash"])
        if sent["from"].lower() == sender:
            continue
        b = int(t["blockNumber"])
        out["foreign"] = b if out["foreign"] is None else min(out["foreign"], b)
        if (sent.get("to") or "").lower() == proxy:
            out["via_proxy"] = b if out["via_proxy"] is None else min(out["via_proxy"], b)
    _first_loss[key] = out
    return out


def called_by_others(proxy: str, sender: str, lo: int, hi: int) -> bool:
    """Whether anyone but `sender` sent a transaction to `proxy` in [lo, hi].

    A via-proxy loss needs such a transaction, so when there is none the
    transfer lookups can be skipped with the same answer. A full page means
    the list may be cut off, so it counts as yes and the full check runs."""
    r = _get({"chainid": 1, "module": "account", "action": "txlist", "address": proxy,
              "startblock": lo, "endblock": hi, "page": 1, "offset": 10000, "sort": "asc"},
             cache_key=f"txlist:{proxy}:{lo}:{hi}")
    res = r.get("result")
    if not isinstance(res, list):
        if "no transactions" in str(r.get("message", "")).lower():
            return False
        raise SystemExit(f"txlist failed for {proxy} [{lo},{hi}]: {r}")
    if len(res) >= 10000:
        return True
    return any((t.get("to") or "").lower() == proxy and t["from"].lower() != sender for t in res)


def deployer_of(address: str) -> str | None:
    """Creator of `address`, or None when Etherscan has no creation record (an
    address with no code, or one created before its index begins). The
    deployer rule then fires, as in upgrade_detectors.py."""
    out = _get({"chainid": 1, "module": "contract", "action": "getcontractcreation",
                "contractaddresses": address}, cache_key="creation:" + address)
    res = out.get("result")
    if isinstance(res, list) and res:
        return res[0]["contractCreator"].lower()
    if "no data found" in str(out.get("message", "")).lower():
        return None
    raise SystemExit(f"getcontractcreation failed for {address}: {out}")


def drained_via_proxy_before(impl: str, before: int) -> bool:
    """Some EOA among the newest RECENT earlier upgraders of `impl` lost tokens
    through its own proxy before `before` (upgrade_benign_history's rule)."""
    ups, _ = earlier_upgrades(impl, before)
    prefetch([l["transactionHash"] for l in ups])
    for l in ups:
        sender = tx(l["transactionHash"])["from"].lower()
        b = int(l["blockNumber"], 16)
        proxy = l["address"].lower()
        if (sender, b, proxy) not in _first_loss and not called_by_others(proxy, sender, b, b + LOSS_WINDOW):
            continue
        v = first_loss(sender, b, proxy)["via_proxy"]
        if v is not None and v < before and is_eoa(sender):
            return True
    return False


def tally(rows: list[dict], field: str) -> dict:
    k, n = sum(bool(r[field]) for r in rows), len(rows)
    return {"fires": k, "of": n, "ci95": wilson(k, n)}


def main() -> None:
    pop = json.load(open(_POP))["rows"]
    print(f"{len(pop):,} upgrades of OpenSea user proxies")

    for i, r in enumerate(pop):
        loss = first_loss(r["sender"], r["block"], r["proxy"])
        r["drained_via_proxy_after"] = loss["via_proxy"] is not None
        r["drained_any_after"] = loss["foreign"] is not None
        if i % 25 == 0:
            print(f"  loss {i}/{len(pop)}", flush=True)

    by_impl: dict[str, list[dict]] = defaultdict(list)
    for r in pop:
        by_impl[r["implementation"]].append(r)
    drained_impls = {a for a, rs in by_impl.items() if any(r["drained_via_proxy_after"] for r in rs)}
    for r in pop:
        r["side"] = ("known_kit" if r["known_kit"] else
                     "unseeded_kit" if r["implementation"] in drained_impls else "benign")

    deployers = {a: deployer_of(a) for a in by_impl}
    for i, r in enumerate(pop):
        r["type_rule"] = r["selector"] == UPGRADE_TO
        r["type_rule_either"] = r["selector"] in (UPGRADE_TO, UPGRADE_TO_AND_CALL)
        r["ptxphish_impl_deployer"] = deployers[r["implementation"]] != r["sender"]
        r["drained_via_proxy_before"] = drained_via_proxy_before(r["implementation"], r["block"])
        if i % 25 == 0:
            print(f"  detectors {i}/{len(pop)}", flush=True)

    fields = ("type_rule", "type_rule_either", "ptxphish_impl_deployer", "drained_via_proxy_before")
    summary = {"recent_cap": RECENT, "upgrades": len(pop), "implementations": len(by_impl),
               "implementations_without_creation_record": sorted(a for a, d in deployers.items() if d is None)}
    for side in ("known_kit", "unseeded_kit", "benign"):
        rows = [r for r in pop if r["side"] == side]
        wallet = [r for r in rows if r["sent_to_proxy"]]
        summary[side] = {"rows": len(rows), "implementations": len({r["implementation"] for r in rows}),
                         "all": {f: tally(rows, f) for f in fields},
                         "sent_to_proxy": {f: tally(wallet, f) for f in fields}}
    summary["unseeded_kits"] = sorted(
        ({"implementation": a, "upgrades": len(by_impl[a]),
          "drained_via_proxy": sum(r["drained_via_proxy_after"] for r in by_impl[a]),
          "first_block": min(r["block"] for r in by_impl[a]), "deployer": deployers[a]}
         for a in drained_impls if not by_impl[a][0]["known_kit"]),
        key=lambda k: -k["upgrades"])
    with open(_OUT, "w") as f:
        json.dump({"note": __doc__.split("\n\n")[0], "summary": summary, "rows": pop}, f, indent=1)
        f.write("\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "unseeded_kits"}, indent=1))
    for k in summary["unseeded_kits"][:30]:
        print(" ", k)
    print(f"wrote {_OUT}")


if __name__ == "__main__":
    main()
