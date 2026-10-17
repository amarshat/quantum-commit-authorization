"""Label-free signals on the proxy-upgrade implementations, as of signing time.

upgrade_tier.py shows a reputation service flags the upgradeTo implementation
and not the transaction target. Those flags are today's labels, so they say
nothing about what was knowable when each victim signed. This module asks
three questions that need no label, using only what was on chain before the
signing block:

  age        how many blocks (and days) old the implementation was when the
             victim signed
  clone      how close its runtime bytecode is to an implementation that had
             already been used in an earlier drain in this set; compared after
             stripping the Solidity metadata tail and the immediates of PUSH20
             (hardcoded addresses), which is where clones of one kit differ
  deployer   whether the same deployer had already shipped an implementation
             used in an earlier drain

"Earlier drain" means an earlier row in this same set, by signing block. That
is an on-chain event that preceded the signature, not a label applied later,
but it is also the only history this module looks at: a deployer with drains
outside PTXPHISH would be missed, so the deployer and clone counts are lower
bounds.

Needs ETHERSCAN_API_KEY. Responses are cached with the rest of the Etherscan
cache, so a re-run is free.

    python3 -m demo.upgrade_signals
"""

from __future__ import annotations

import difflib
import json
import os

from .intent_gap import _get

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROWS = os.path.join(_HERE, "results", "upgrade_tier.json")
_OUT = os.path.join(_HERE, "results", "upgrade_signals.json")

SECONDS_PER_BLOCK = 12  # post-merge slot time; every signing here is post-merge


def creation(addresses: list[str]) -> dict:
    out = _get({"chainid": 1, "module": "contract", "action": "getcontractcreation",
                "contractaddresses": ",".join(addresses)},
               cache_key="creation:" + ",".join(addresses))
    res = out.get("result")
    if not isinstance(res, list):
        raise SystemExit(f"getcontractcreation failed: {out}")
    return {r["contractAddress"].lower(): r for r in res}


def block_of_tx(tx_hash: str) -> int:
    out = _get({"chainid": 1, "module": "proxy", "action": "eth_getTransactionByHash",
                "txhash": tx_hash}, cache_key="tx:" + tx_hash)
    return int(out["result"]["blockNumber"], 16)


def runtime_code(address: str) -> str:
    out = _get({"chainid": 1, "module": "proxy", "action": "eth_getCode",
                "address": address, "tag": "latest"}, cache_key="code:" + address)
    return out.get("result") or "0x"


def opcodes(code: str) -> list[str]:
    """Opcode stream with PUSH20 immediates blanked and the metadata tail cut."""
    b = bytes.fromhex(code[2:]) if code.startswith("0x") else b""
    # Solidity appends CBOR metadata whose length is the final two bytes.
    if len(b) > 2:
        meta = int.from_bytes(b[-2:], "big") + 2
        if meta < len(b) and b[-meta] in (0xA1, 0xA2):
            b = b[:-meta]
    ops, i = [], 0
    while i < len(b):
        op = b[i]
        if 0x60 <= op <= 0x7F:  # PUSH1..PUSH32
            n = op - 0x5F
            imm = b[i + 1:i + 1 + n]
            ops.append(f"{op:02x}:" + ("<addr>" if n == 20 else imm.hex()))
            i += 1 + n
        else:
            ops.append(f"{op:02x}")
            i += 1
    return ops


def similarity(a: list[str], b: list[str]) -> float:
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def main() -> None:
    rows = json.load(open(_ROWS))["within_subjects"]["per_row"]
    impls = sorted({r["authority_object"].lower() for r in rows})
    created = creation(impls)

    info = {}
    for a in impls:
        c = created.get(a)
        code = runtime_code(a)
        info[a] = {
            "deployer": c["contractCreator"].lower() if c else None,
            "creation_tx": c["txHash"] if c else None,
            "creation_block": block_of_tx(c["txHash"]) if c else None,
            "code_bytes": (len(code) - 2) // 2,
            "ops": opcodes(code),
        }

    pair_sim = {}
    for i, a in enumerate(impls):
        for b in impls[i + 1:]:
            s = similarity(info[a]["ops"], info[b]["ops"])
            pair_sim[f"{a}|{b}"] = s
            pair_sim[f"{b}|{a}"] = s

    rows = sorted(rows, key=lambda r: r["signing_block"])
    out_rows = []
    for k, r in enumerate(rows):
        a = r["authority_object"].lower()
        me = info[a]
        earlier = rows[:k]
        seen_impls = {e["authority_object"].lower() for e in earlier
                      if e["signing_block"] < r["signing_block"]}
        prior_other = seen_impls - {a}
        best = max(((pair_sim[f"{a}|{o}"], o) for o in prior_other), default=(None, None))
        age = r["signing_block"] - me["creation_block"] if me["creation_block"] else None
        out_rows.append({
            "id": r["id"],
            "signing_block": r["signing_block"],
            "implementation": a,
            "age_blocks": age,
            "age_days": round(age * SECONDS_PER_BLOCK / 86400, 2) if age is not None else None,
            "same_impl_already_used": a in seen_impls,
            "closest_prior_other_impl": best[1],
            "closest_prior_similarity": round(best[0], 4) if best[0] is not None else None,
            "deployer_already_shipped_a_used_impl": any(
                info[o]["deployer"] == me["deployer"] for o in prior_other) if me["deployer"] else None,
            "flagged_today": r["caught_aiming_at_authority_object"],
        })

    summary = {
        "implementations": {a: {k: v for k, v in info[a].items() if k != "ops"} for a in impls},
        "pairwise_similarity": {k: round(v, 4) for k, v in pair_sim.items()
                                if k.split("|")[0] < k.split("|")[1]},
        "rows": out_rows,
    }
    with open(_OUT, "w") as f:
        json.dump(summary, f, indent=1)
        f.write("\n")

    print("implementations:")
    for a in impls:
        i = info[a]
        print(f"  {a}  deployer {i['deployer']}  created {i['creation_block']}  {i['code_bytes']} bytes")
    print("pairwise opcode similarity (PUSH20 and metadata stripped):")
    for k, v in summary["pairwise_similarity"].items():
        x, y = k.split("|")
        print(f"  {x[:10]} {y[:10]}  {v:.3f}")
    print("per row, by signing block:")
    for o in out_rows:
        print(f"  {o['id']:10} age {o['age_days']:>8} d  reused={o['same_impl_already_used']!s:5} "
              f"closest_prior={o['closest_prior_similarity']}  deployer_seen={o['deployer_already_shipped_a_used_impl']}  "
              f"flagged_today={o['flagged_today']}")
    print(f"wrote {_OUT}")


if __name__ == "__main__":
    main()
