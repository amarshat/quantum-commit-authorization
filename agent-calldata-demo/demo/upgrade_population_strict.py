"""The OpenSea proxy census, attributed strictly.

upgrade_population_eval.py calls an implementation a kit when any one of its
upgraders lost tokens through the proxy within seven days. That window is not
ended at the proxy's next upgrade, so a drain under a later implementation is
credited to an earlier one, and the split admits targets that cannot be a
kit at all. This module re-derives the split:

  strict drain   the loss through the proxy comes before the proxy's next
                 upgrade, counting upgrades back to OpenSea's own
                 implementation (restorations), which upgrade_population.py
                 drops
  rig proxies    proxies upgraded to three or more implementations. One
                 sender cycling a proxy through many implementations, each
                 followed by a "drain", looks like a kit operator testing,
                 not a victim; rows on them are reported but do not make an
                 implementation a kit
  non-targets    an implementation that is itself an OpenSea user proxy, an
                 address that sent upgrades, or an address with no code and
                 no creation record cannot be a drainer kit

It reports kits and victims as distinct senders, the base rate of the
categorical warning with its full cost, and how many upgrades of each kit
come after its first strict drain, which is what drained-via-proxy-before
can at most catch.

    python3 -m demo.upgrade_population_strict

Reads the Etherscan cache through upgrade_population_eval.first_loss and the
population cache for restorations; uses Alchemy for code and restoration
senders. Writes results/upgrade_population_strict.json.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict

from .upgrade_detectors import wilson
from .upgrade_population import AUTHENTICATED_PROXY, _CACHE_FILE, rpc_batch
from .upgrade_population_eval import deployer_of, first_loss

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RES = os.path.join(_HERE, "results")
_EVAL = os.path.join(_RES, "upgrade_population_eval.json")
_LABELS = os.path.join(_RES, "upgrade_population_labels.json")
_OUT = os.path.join(_RES, "upgrade_population_strict.json")

RIG_IMPLEMENTATIONS = 3
WARNING_BLOCK = 15_850_000  # 29 October 2022, a day after the first public warnings


def restorations(proxies: set[str], first_later: dict[str, int]) -> list[list]:
    """Upgraded(AuthenticatedProxy) on an OpenSea proxy after its first later upgrade."""
    cache = json.load(open(_CACHE_FILE))
    out = []
    for k, rows in cache.items():
        if not k.startswith("logs:"):
            continue
        for block, h, emitter, impl in rows:
            if impl == AUTHENTICATED_PROXY and emitter in proxies and block > first_later[emitter]:
                out.append([block, h, emitter])
    return sorted(set(map(tuple, out)))


def rate(k: int, n: int) -> dict:
    return {"k": k, "n": n, "ci95": wilson(k, n)}


def main() -> None:
    rows = json.load(open(_EVAL))["rows"]
    labels = json.load(open(_LABELS))["per_implementation"]
    proxies = {r["proxy"] for r in rows}
    senders = {r["sender"] for r in rows}

    first_later = {}
    for r in rows:
        first_later[r["proxy"]] = min(first_later.get(r["proxy"], r["block"]), r["block"])
    restore = restorations(proxies, first_later)
    restore_tx = rpc_batch([("eth_getTransactionByHash", [h]) for _, h, _ in restore]) if restore else []

    # Every later event on each proxy, upgrades and restorations, to end windows.
    events = defaultdict(list)
    for r in rows:
        events[r["proxy"]].append(r["block"])
    for block, _, p in restore:
        events[p].append(block)
    for p in events:
        events[p].sort()

    def next_event(p: str, block: int) -> int | None:
        later = [b for b in events[p] if b > block]
        return later[0] if later else None

    impls_on = defaultdict(set)
    for r in rows:
        impls_on[r["proxy"]].add(r["implementation"])
    rigs = {p for p, s in impls_on.items() if len(s) >= RIG_IMPLEMENTATIONS}

    impls = sorted({r["implementation"] for r in rows})
    codes = {}
    for i in range(0, len(impls), 100):
        chunk = impls[i:i + 100]
        codes.update(zip(chunk, rpc_batch([("eth_getCode", [a, "latest"]) for a in chunk])))

    def non_target(a: str) -> str | None:
        if a in proxies:
            return "opensea_proxy"
        if a in senders:
            return "sender"
        if codes[a] in ("0x", "0x0") and deployer_of(a) is None:
            return "no_code_no_creation"
        return None

    for r in rows:
        v = first_loss(r["sender"], r["block"], r["proxy"])["via_proxy"]
        nxt = next_event(r["proxy"], r["block"])
        r["strict_drained"] = v is not None and (nxt is None or v < nxt)
        r["first_drain_block"] = v if r["strict_drained"] else None
        r["window_end"] = nxt
        r["rig"] = r["proxy"] in rigs
        r["loose_drained"] = v is not None

    by_impl = defaultdict(list)
    for r in rows:
        by_impl[r["implementation"]].append(r)
    reasons = {a: non_target(a) for a in by_impl}
    strict_kits = {a for a, rs in by_impl.items()
                   if not rows_known(rs) and reasons[a] is None
                   and any(r["strict_drained"] and not r["rig"] for r in rs)}
    loose_kits = {a for a, rs in by_impl.items() if rs[0]["side"] == "unseeded_kit"}

    def kits_under(window: bool, rig: bool, targets: bool) -> int:
        return sum(1 for a, rs in by_impl.items()
                   if not rows_known(rs) and (not targets or reasons[a] is None)
                   and any((r["strict_drained"] if window else r["loose_drained"]) and not (rig and r["rig"])
                           for r in rs))
    known = {a for a, rs in by_impl.items() if rows_known(rs)}

    def side(a: str) -> str:
        return "known_kit" if a in known else "unseeded_kit" if a in strict_kits else "other"

    for r in rows:
        r["strict_side"] = side(r["implementation"])

    def describe(rs: list[dict]) -> dict:
        return {"upgrades": len(rs), "implementations": len({r["implementation"] for r in rs}),
                "senders": len({r["sender"] for r in rs}),
                "drained_senders": len({r["sender"] for r in rs if r["strict_drained"]}),
                "drained_upgrades": sum(r["strict_drained"] for r in rs),
                "on_rig_proxies": sum(r["rig"] for r in rs),
                "before_warning": sum(r["block"] < WARNING_BLOCK for r in rs),
                "drained_before_warning": sum(r["block"] < WARNING_BLOCK and r["strict_drained"] for r in rs)}

    unseeded = [r for r in rows if r["strict_side"] == "unseeded_kit"]
    other = [r for r in rows if r["strict_side"] == "other"]
    known_rows = [r for r in rows if r["strict_side"] == "known_kit"]

    # What drained-via-proxy-before can at most catch: upgrades of a kit that
    # come after that kit's first strict drain.
    def after_first_drain(rs: list[dict]) -> int:
        n = 0
        for a in {r["implementation"] for r in rs}:
            mine = sorted(by_impl[a], key=lambda r: r["block"])
            drains = [r["first_drain_block"] for r in mine if r["strict_drained"]]
            if drains:
                n += sum(r["block"] > min(drains) for r in mine)
        return n

    # The history index rerun on the strict attribution: some earlier upgrade
    # of the same implementation, on a proxy that is not a rig, was drained
    # through its proxy before this upgrade and before that proxy's next one.
    drains = defaultdict(list)
    for r in rows:
        if r["strict_drained"] and not r["rig"]:
            drains[r["implementation"]].append(r["first_drain_block"])
    for r in rows:
        r["strict_index"] = any(b < r["block"] for b in drains[r["implementation"]])
        ds = [x["first_drain_block"] for x in by_impl[r["implementation"]] if x["strict_drained"]]
        r["after_first_drain"] = bool(ds) and r["block"] > min(ds)

    kit_rows = known_rows + unseeded
    warned = [r for r in rows if r["sent_to_proxy"]]
    upgraders = defaultdict(set)
    for r in rows:
        upgraders[r["proxy"]].add(r["sender"])
    other_norig = [r for r in other if not r["rig"]]

    def precision(kits: set[str]) -> dict:
        return rate(sum(r["sent_to_proxy"] and (r["known_kit"] or r["implementation"] in kits) for r in rows),
                    len(warned) + len(restore))
    summary = {
        "rig_threshold_implementations": RIG_IMPLEMENTATIONS,
        "rig_proxies": len(rigs),
        "restorations": len(restore),
        "restoration_proxies": len({p for _, _, p in restore}),
        "restorations_sent_by_that_proxys_upgrader": sum(
            (t.get("from") or "").lower() in upgraders[p] for (_, _, p), t in zip(restore, restore_tx)),
        "restorations_sent_to_the_proxy": sum(
            (t.get("to") or "").lower() == p for (_, _, p), t in zip(restore, restore_tx)),
        "kits_under_rules": {"loose": kits_under(False, False, False),
                             "window_only": kits_under(True, False, False),
                             "rig_only": kits_under(False, True, False),
                             "window_and_rig": kits_under(True, True, False),
                             "window_rig_and_non_target": kits_under(True, True, True)},
        "loose_unseeded_kits": len(loose_kits),
        "strict_unseeded_kits": len(strict_kits),
        "loose_kits_dropped": {
            "non_target": sorted((a, reasons[a]) for a in loose_kits if reasons[a]),
            "only_on_rigs_or_not_strictly_drained": sorted(
                a for a in loose_kits - strict_kits if not reasons[a])},
        "known_kit": describe(known_rows),
        "unseeded_kit": describe(unseeded),
        "other": describe(other),
        "unseeded_labelled_goplus": sum(bool(labels[a]["goplus"]) for a in strict_kits),
        "unseeded_labelled_scamsniffer": sum(labels[a]["scamsniffer"] for a in strict_kits),
        "unseeded_upgrades_labelled_goplus": sum(bool(labels[r["implementation"]]["goplus"]) for r in unseeded),
        "unseeded_first_block": min((r["block"] for r in unseeded), default=None),
        "known_first_uses_on_rigs": sorted(
            a for a in known if min(by_impl[a], key=lambda r: r["block"])["rig"]),
        "detector_ceiling": {"known_kit": rate(after_first_drain(known_rows), len(known_rows)),
                             "unseeded_kit": rate(after_first_drain(unseeded), len(unseeded))},
        "detector_fires": {"known_kit": rate(sum(r["drained_via_proxy_before"] for r in known_rows), len(known_rows)),
                           "unseeded_kit": rate(sum(r["drained_via_proxy_before"] for r in unseeded), len(unseeded)),
                           "other": rate(sum(r["drained_via_proxy_before"] for r in other), len(other))},
        "detector_matches_ceiling_rows": {
            s_: sum(r["drained_via_proxy_before"] == r["after_first_drain"] for r in rs)
            for s_, rs in (("known_kit", known_rows), ("unseeded_kit", unseeded))},
        "strict_index_fires": {"known_kit": rate(sum(r["strict_index"] for r in known_rows), len(known_rows)),
                               "unseeded_kit": rate(sum(r["strict_index"] for r in unseeded), len(unseeded)),
                               "other": rate(sum(r["strict_index"] for r in other), len(other)),
                               "other_not_rig": rate(sum(r["strict_index"] for r in other_norig), len(other_norig))},
        "other_not_rig": {f: rate(sum(r[f] for r in other_norig), len(other_norig))
                          for f in ("type_rule", "type_rule_either", "ptxphish_impl_deployer",
                                    "drained_via_proxy_before")},
        "other_implementations_only_on_rigs": len(
            {r["implementation"] for r in other} - {r["implementation"] for r in other_norig}),
        "kit_upgrades_followed_by_strict_drain": rate(sum(r["strict_drained"] for r in kit_rows), len(kit_rows)),
        "precision_sensitivity": {"seeded_only": precision(set()),
                                  "strict": precision(strict_kits),
                                  "loose": precision(loose_kits),
                                  "followed_by_strict_drain": rate(
                                      sum(r["sent_to_proxy"] and r["strict_drained"] for r in rows),
                                      len(warned) + len(restore))},
        "base_rate": {
            "upgrades_to_a_kit": rate(len(kit_rows), len(rows)),
            "upgrades_followed_by_strict_drain": rate(sum(r["strict_drained"] for r in rows), len(rows)),
            "categorical_warning_precision": rate(sum(r["sent_to_proxy"] for r in kit_rows),
                                                  len(warned) + len(restore)),
            "categorical_warning_benign_cost": len(warned) + len(restore) - sum(r["sent_to_proxy"] for r in kit_rows),
            "upgrades_to_a_kit_excluding_rigs": rate(sum(not r["rig"] for r in kit_rows),
                                                     sum(not r["rig"] for r in rows)),
        },
        "rules_on_other": {f: rate(sum(r[f] for r in other), len(other))
                           for f in ("type_rule", "type_rule_either", "ptxphish_impl_deployer")},
        "strict_unseeded_kits_list": sorted(
            ({"implementation": a, "upgrades": len(by_impl[a]),
              "senders": len({r["sender"] for r in by_impl[a]}),
              "drained_senders": len({r["sender"] for r in by_impl[a] if r["strict_drained"]}),
              "goplus": labels[a]["goplus"], "scamsniffer": labels[a]["scamsniffer"]}
             for a in strict_kits), key=lambda k: -k["upgrades"]),
    }
    with open(_OUT, "w") as f:
        json.dump({"note": __doc__.split("\n\n")[0], "summary": summary,
                   "restorations": [{"block": b, "tx": h, "proxy": p} for b, h, p in restore],
                   "rows": [{k: r[k] for k in ("tx", "block", "proxy", "implementation", "sender",
                                                "strict_side", "strict_drained", "first_drain_block",
                                                "window_end", "rig", "strict_index",
                                                "after_first_drain")} for r in rows]},
                  f, indent=1)
        f.write("\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "strict_unseeded_kits_list"}, indent=1))
    for k in summary["strict_unseeded_kits_list"]:
        print(" ", k)
    print(f"wrote {_OUT}")


def rows_known(rs: list[dict]) -> bool:
    return rs[0]["known_kit"]


if __name__ == "__main__":
    main()
