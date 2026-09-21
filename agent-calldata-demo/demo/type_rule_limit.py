"""Where does a type-level rule stop working, and argument resolution keep working?

Powered by Etherscan.io APIs and the GoPlus Security API.

`demo/upgrade_tier.py` produces an uncomfortable result for this paper's
thesis. On the OpenSea `OwnableDelegateProxy` class, a categorical rule on the
action type ("warn on any user-signed upgrade of your own proxy") stops every
malicious row and fires on nothing else, so resolving the `upgradeTo` argument
is unnecessary there. If that were the whole story, object selection would be a
lens with no case in which it changes an outcome.

The claim it leaves behind is that object selection buys GENERALITY: a type
rule has to be written per action type, in advance, and it only works where the
action type is itself diagnostic. That claim is testable, and asserting it
without testing it is what an earlier draft did.

So: take proxy upgrades in general rather than OpenSea's legacy class. EIP-1967
proxies emit `Upgraded(address)` on every implementation change, and the vast
majority of those are ordinary administration of live protocols. On that
population:

    a TYPE RULE   ("warn on any proxy upgrade") fires on every event, so its
                  false-positive rate is whatever share of upgrades is benign
    ARGUMENT      resolving the implementation and asking a reputation service
    RESOLUTION    about IT should fire on the malicious ones and stay quiet on
                  the rest

If the second discriminates where the first cannot, the generality claim has a
case. If it does not, the paper should drop the claim. Either outcome is worth
having, and the module reports whichever occurs.

    python3 -m demo.type_rule_limit

Writes results/type_rule_limit.json.
"""

from __future__ import annotations

import argparse
import json
import os

from . import goplus, source_tier
from .intent_gap import _get

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(ROOT, "results")

# keccak256("Upgraded(address)"), the EIP-1967 implementation-change event.
# Every compliant proxy emits it, which is what makes this population
# enumerable without a selector search.
UPGRADED_TOPIC = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"


def fetch_upgrades(windows: list[tuple[int, int]], per_window: int) -> list[dict]:
    out = []
    for lo, hi in windows:
        r = _get({"chainid": "1", "module": "logs", "action": "getLogs",
                  "fromBlock": str(lo), "toBlock": str(hi), "topic0": UPGRADED_TOPIC,
                  "page": "1", "offset": str(per_window)},
                 cache_key=f"upgraded:{lo}:{hi}:{per_window}")
        res = r.get("result")
        if not isinstance(res, list):
            continue
        for l in res:
            if len(l.get("topics", [])) < 2:
                continue          # implementation not indexed; skip rather than guess
            out.append({
                "proxy": l["address"].lower(),
                "implementation": "0x" + l["topics"][1][-40:],
                "block": int(l["blockNumber"], 16) if isinstance(l["blockNumber"], str)
                         and l["blockNumber"].startswith("0x") else int(l["blockNumber"]),
                "tx": l.get("transactionHash", ""),
            })
    return out


def classify_senders(events: list[dict]) -> dict:
    """Who signs these upgrades, and would a wallet ever be asked to?

    The false-positive rate of a type rule is only meaningful over the
    population a wallet actually sees. Routine protocol administration is
    normally executed by a multisig, a timelock or a deployer script, none of
    which produces a consumer-wallet confirmation. An upgrade sent by a
    contract therefore never reaches the rule at all, and counting it as a
    false positive overstates what the rule would cost in the setting this
    paper is about.
    """
    rpc = os.environ.get("ALCHEMY_ENDPOINT_URL") or os.environ.get("MAINNET_RPC")
    if not rpc:
        return {"error": "no archive/RPC endpoint configured"}
    import urllib.request

    def call(method, params):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                           "params": params}).encode()
        req = urllib.request.Request(rpc, data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read()).get("result")
        except Exception:
            return None

    senders, per_event = {}, []
    for i, e in enumerate(events, 1):
        if not e.get("tx"):
            continue
        tx = call("eth_getTransactionByHash", [e["tx"]])
        if not isinstance(tx, dict):
            continue
        frm = (tx.get("from") or "").lower()
        to = (tx.get("to") or "").lower()
        if frm and frm not in senders:
            code = call("eth_getCode", [frm, "latest"])
            senders[frm] = bool(code and code not in ("0x", "0x0"))
        # `to` is what the signer was asked to confirm: the proxy itself, or a
        # multisig/timelock/factory standing in front of it.
        direct = (to == e["proxy"])
        per_event.append({"tx": e["tx"], "proxy": e["proxy"],
                          "implementation": e["implementation"],
                          "from": frm, "to": to,
                          "from_is_contract": senders.get(frm),
                          "sent_directly_to_proxy": direct})
        if i % 200 == 0:
            print(f"  ...{i}/{len(events)} senders resolved", flush=True)

    eoa = sum(1 for r in per_event if r["from_is_contract"] is False)
    ctr = sum(1 for r in per_event if r["from_is_contract"] is True)
    direct = sum(1 for r in per_event if r["sent_directly_to_proxy"])
    eoa_direct = sum(1 for r in per_event
                     if r["from_is_contract"] is False and r["sent_directly_to_proxy"])
    return {
        "events_resolved": len(per_event),
        "sent_by_eoa": eoa,
        "sent_by_contract": ctr,
        "sent_directly_to_the_proxy": direct,
        # The population a consumer wallet could ever be asked about: an EOA
        # signing a transaction addressed to the proxy itself.
        "wallet_relevant": eoa_direct,
        "distinct_senders": len(senders),
        "per_event": per_event,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-window", type=int, default=200)
    ap.add_argument("--classify-senders", action="store_true",
                    help="resolve who sent each upgrade, to bound the "
                         "population a consumer wallet would ever see")
    ap.add_argument("--max-implementations", type=int, default=0,
                    help="cap on distinct implementations looked up; 0 means all. "
                         "A cap takes the LEXICOGRAPHICALLY SMALLEST addresses, "
                         "not the earliest, because the set is sorted for "
                         "determinism. Vanity addresses with leading zeros sort "
                         "first and drainer kits mine those more often than "
                         "protocol implementations do, so a cap quietly enriches "
                         "the sample for kits. Prefer 0.")
    args = ap.parse_args()

    if not goplus.available() or not goplus.preflight():
        raise SystemExit("Needs GO_PLUS_APP_KEY and GO_PLUS_APP_SECRET.")

    # Four windows spread across two years, so the result is not one month of
    # one protocol's release cadence.
    windows = [(18000000, 18050000), (19000000, 19050000),
               (20000000, 20050000), (21000000, 21050000)]
    events = fetch_upgrades(windows, args.per_window)
    impls = sorted({e["implementation"] for e in events})
    proxies = sorted({e["proxy"] for e in events})
    print(f"{len(events)} EIP-1967 Upgraded events across {len(windows)} windows: "
          f"{len(proxies)} distinct proxies, {len(impls)} distinct implementations")

    if args.max_implementations:
        impls = impls[:args.max_implementations]
        print(f"  NOTE: capped to the {len(impls)} lexicographically smallest "
              f"of {len({e['implementation'] for e in events})}; this is not a "
              f"random or chronological sample")
    flagged_impl, verified_impl, rows = set(), set(), []
    for i, a in enumerate(impls, 1):
        flags = sorted(goplus.reputation(a, 1))
        info = source_tier.source_info(a, 1, None)
        if flags:
            flagged_impl.add(a)
        if info.get("verified"):
            verified_impl.add(a)
        rows.append({"implementation": a, "reputation_flags": flags,
                     "verified_source": bool(info.get("verified")),
                     "name": info.get("name") or None})
        if i % 50 == 0:
            print(f"  ...{i}/{len(impls)} implementations checked, "
                  f"{len(flagged_impl)} flagged")

    n = len(impls)
    # The type rule cannot discriminate by construction: every one of these IS
    # a proxy upgrade, so a rule keyed on the action type warns on all of them.
    type_rule_fires = n
    type_rule_fp = n - len(flagged_impl)

    print(f"\nOn {n} distinct implementations from general EIP-1967 upgrades:")
    print(f"  a type rule on the action fires on      {type_rule_fires}/{n} (all, by construction)")
    print(f"  reputation on the implementation fires  {len(flagged_impl)}/{n}")
    print(f"  implementations with verified source    {len(verified_impl)}/{n}")
    print(f"  type-rule false positives               {type_rule_fp}/{n} "
          f"({100 * type_rule_fp / n:.1f}%)")
    if flagged_impl:
        print("  flagged implementations:")
        for r in rows:
            if r["reputation_flags"]:
                print(f"    {r['implementation']}  {','.join(r['reputation_flags'])}")

    senders = classify_senders(events) if args.classify_senders else None
    if senders and "error" not in senders:
        w = senders["wallet_relevant"]
        print(f"\nWho actually sends these upgrades ({senders['events_resolved']} resolved):")
        print(f"  sent by an EOA                        {senders['sent_by_eoa']}")
        print(f"  sent by a contract (multisig/timelock){senders['sent_by_contract']:>6}")
        print(f"  addressed directly to the proxy       {senders['sent_directly_to_the_proxy']}")
        print(f"  EOA *and* direct to proxy             {w}  <- the only ones a "
              f"consumer wallet could ever be asked to confirm")

    os.makedirs(RESULTS, exist_ok=True)
    path = os.path.join(RESULTS, "type_rule_limit.json")
    with open(path, "w") as f:
        json.dump({
            "note": ("General EIP-1967 proxy upgrades, as against OpenSea's legacy "
                     "OwnableDelegateProxy class. A rule keyed on the action type "
                     "fires on every row here by construction, so its false-positive "
                     "rate is the benign share. Resolving the implementation and "
                     "asking a reputation service about it is the comparison."),
            "windows": windows,
            "events": len(events),
            "distinct_proxies": len(proxies),
            "distinct_implementations_seen": len({e["implementation"] for e in events}),
            "implementations_checked": n,
            "type_rule_fires": type_rule_fires,
            "type_rule_false_positives": type_rule_fp,
            "reputation_flags_implementation": len(flagged_impl),
            "implementations_with_verified_source": len(verified_impl),
            "sender_classification": senders,
            # N6: ship the events themselves, so the counts quoted in the paper
            # (proxies, implementations, and the per-kit event tallies) can be
            # recomputed rather than taken on trust.
            "upgrade_events": events,
            "rows": rows,
        }, f, indent=1)
    print(f"\nwrote {path}")


if __name__ == "__main__":
    main()
