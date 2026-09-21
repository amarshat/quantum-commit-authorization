"""Does object selection change what a DEPLOYED defense says about a proxy upgrade?

Powered by Etherscan.io APIs and the GoPlus Security API.

Sections 2 to 4 of the paper locate the object that governs an outcome. They do
not test a defense. For three of the four drain classes that is fine, because
deployed wallets already read the object we resolve: an approval's spender and
an operator are read by Rabby's security engine and classified by Blockaid. The
exception is the proxy-upgrade class, and this module is the test for it.

The design is a within-subjects comparison, which is what makes it an
experiment rather than another count. The same deployed reputation service, on
the same transactions, is asked two questions:

    aimed at the TARGET           the proxy the transaction is addressed to
    aimed at the AUTHORITY OBJECT the implementation named in upgradeTo's
                                  argument

Nothing varies but the address handed over. If the verdicts agree, object
selection buys nothing here and the paper's remaining claim is empty. If they
diverge, the divergence is the finding, and it is a fact about a deployed
service rather than about our own harness.

Two honesty notes that belong with any number this prints.

  * `demo/rabby.py` does not parse `upgradeTo`, so a miss by that port is a
    property of the port and NOT evidence about shipped Rabby. The port is
    therefore excluded here. GoPlus is a live hosted service and is not.
  * Reputation is retrospective. A `catch` on an implementation today does not
    mean the service would have flagged it at signing time. This measures
    whether the signal is ATTACHED to the object, not whether it was available
    when it would have helped.

The competing explanation is tested too. If a user-signed `upgradeTo` on an
OpenSea `OwnableDelegateProxy` is essentially never legitimate, then a
categorical rule on the action type would stop the whole class without
resolving any argument, and object selection would be unnecessary rather than
merely unused. `--benign-scan` samples proxies that were NOT selected for
having been drained and reports how many ever received an upgrade at all.

    python3 -m demo.upgrade_tier                 # the within-subjects test
    python3 -m demo.upgrade_tier --benign-scan   # the type-level-rule check

Writes results/upgrade_tier.json.
"""

from __future__ import annotations

import argparse
import json
import os

from . import corpus, goplus, source_tier
from .intent_gap import _get

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(ROOT, "results")

# OpenSea's Wyvern ProxyRegistry. Each user's OwnableDelegateProxy is created
# by it, so its internal `create` traces enumerate proxies that were NOT
# selected for having been drained.
PROXY_REGISTRY = "0xa5409ec958c83c3f309868babaca7c86dcb077c1"
UPGRADE_SELECTORS = ("0x3659cfe6", "0x4f1ef286")

# Excluded from the analysis set: upgradeTo's argument is the sender's own EOA.
EXCLUDED = {"ptx-J-01"}


def upgrade_rows():
    return [c for c in corpus.real_cases()
            if c.malicious and c.label == "proxy-upgrade" and c.id not in EXCLUDED]


def within_subjects() -> dict:
    """Same service, same transactions, one variable: which address it is given."""
    rows = upgrade_rows()
    per_row = []
    for c in rows:
        impl, _ = source_tier.authority_object(c)
        proxy = (c.to or "").lower()
        impl = impl.lower()
        tgt_flags = sorted(goplus.reputation(proxy, c.chain_id))
        obj_flags = sorted(goplus.reputation(impl, c.chain_id))
        src = source_tier.source_info(impl, c.chain_id, getattr(c, "block", None))
        per_row.append({
            "id": c.id, "signing_block": c.block,
            "target": proxy, "authority_object": impl,
            "reputation_on_target": tgt_flags,
            "reputation_on_authority_object": obj_flags,
            "caught_aiming_at_target": bool(tgt_flags),
            "caught_aiming_at_authority_object": bool(obj_flags),
            "authority_object_verified_source": bool(src.get("verified")),
            "authority_object_name": src.get("name") or None,
        })

    n = len(per_row)
    on_t = sum(1 for r in per_row if r["caught_aiming_at_target"])
    on_o = sum(1 for r in per_row if r["caught_aiming_at_authority_object"])
    proxies = {r["target"] for r in per_row}
    objs = {r["authority_object"] for r in per_row}
    obj_caught = {r["authority_object"] for r in per_row
                  if r["caught_aiming_at_authority_object"]}
    return {
        "rows": n,
        "distinct_targets": len(proxies),
        "distinct_authority_objects": len(objs),
        "rows_flagged_aiming_at_target": on_t,
        "rows_flagged_aiming_at_authority_object": on_o,
        "objects_flagged": len(obj_caught),
        "per_row": per_row,
    }


def benign_scan(limit: int) -> dict:
    """How often is a user-signed upgradeTo on one of these proxies legitimate?

    Samples proxies from the registry's creation traces, i.e. chosen by when
    they were created and not by whether they were drained, and counts how many
    ever received an upgrade call.
    """
    proxies: list[str] = []
    for lo in (11000000, 11200000, 11400000, 11600000):
        r = _get({"chainid": "1", "module": "account", "action": "txlistinternal",
                  "address": PROXY_REGISTRY, "startblock": str(lo),
                  "endblock": str(lo + 200000), "page": "1", "offset": "300",
                  "sort": "asc"}, cache_key=f"reginternal:{lo}:{lo + 200000}")
        res = r.get("result")
        if isinstance(res, list):
            proxies += [t["contractAddress"].lower()
                        for t in res if t.get("type") == "create"]
    proxies = sorted(set(proxies))[:limit]

    resolved = with_direct_txs = with_upgrade = 0
    found = []
    for p in proxies:
        q = _get({"chainid": "1", "module": "account", "action": "txlist",
                  "address": p, "startblock": "0", "endblock": "99999999",
                  "page": "1", "offset": "100", "sort": "asc"},
                 cache_key=f"txlist-proxy:{p}")
        res = q.get("result")
        if not isinstance(res, list):
            continue
        resolved += 1
        if res:
            with_direct_txs += 1
        ups = [t for t in res if (t.get("input") or "")[:10] in UPGRADE_SELECTORS]
        if ups:
            with_upgrade += 1
            found += [{"proxy": p, "impl": "0x" + t["input"][34:74],
                       "hash": t["hash"]} for t in ups]
    return {
        "sampled": len(proxies), "resolved": resolved,
        # The meaningful denominator. Most user proxies are only ever reached
        # through OpenSea's exchange contract as internal calls, which txlist
        # does not index, so they show no directly-signed transactions at all.
        "with_directly_signed_txs": with_direct_txs,
        "with_any_upgrade": with_upgrade,
        "upgrades": found,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign-scan", action="store_true",
                    help="also sample proxies not selected for being drained")
    ap.add_argument("--benign-limit", type=int, default=1200)
    args = ap.parse_args()

    if not goplus.available() or not goplus.preflight():
        raise SystemExit("Needs GO_PLUS_APP_KEY and GO_PLUS_APP_SECRET, and a "
                         "reachable GoPlus API.")

    w = within_subjects()
    n = w["rows"]
    print(f"Within-subjects test on {n} proxy-upgrade rows "
          f"({w['distinct_targets']} proxies, {w['distinct_authority_objects']} "
          f"implementations). Same service, same transactions.\n")
    print(f"  GoPlus aimed at the transaction target (the proxy):")
    print(f"      flagged {w['rows_flagged_aiming_at_target']}/{n} rows")
    print(f"  GoPlus aimed at the authority object (the implementation):")
    print(f"      flagged {w['rows_flagged_aiming_at_authority_object']}/{n} rows "
          f"({w['objects_flagged']}/{w['distinct_authority_objects']} distinct)")
    print("\n  per implementation:")
    seen = set()
    for r in w["per_row"]:
        a = r["authority_object"]
        if a in seen:
            continue
        seen.add(a)
        k = sum(1 for x in w["per_row"] if x["authority_object"] == a)
        f = r["reputation_on_authority_object"]
        print(f"    {a}  rows={k:2}  {'verified' if r['authority_object_verified_source'] else 'no source'}"
              f"  flags={','.join(f) if f else '(none)'}")

    out = {
        "note": ("Within-subjects test: one deployed reputation service, the same "
                 "proxy-upgrade transactions, varying only which address it is "
                 "asked about. demo/rabby.py is excluded because that port does "
                 "not parse upgradeTo, so a miss by it would be a property of "
                 "the port rather than evidence about shipped Rabby."),
        "within_subjects": w,
    }

    if args.benign_scan:
        b = benign_scan(args.benign_limit)
        out["benign_scan"] = b
        print(f"\nType-level-rule check: {b['sampled']} proxies sampled by creation "
              f"order, not by having been drained.")
        print(f"  resolved {b['resolved']}, of which {b['with_directly_signed_txs']} "
              f"have any directly-signed transaction")
        print(f"  with any upgradeTo/upgradeToAndCall: {b['with_any_upgrade']}")
        for u in b["upgrades"]:
            print(f"    {u}")

    os.makedirs(RESULTS, exist_ok=True)
    path = os.path.join(RESULTS, "upgrade_tier.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=1)
    print(f"\nwrote {path}")


if __name__ == "__main__":
    main()
