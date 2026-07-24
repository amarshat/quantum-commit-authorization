"""Reconstruct the victim's SIGNING grant from an attacker's drain sweep.

PTXPHISH labels the drain *execution* (the attacker's `transferFrom` /
`safeTransferFrom` sweep), not the transaction the victim/agent actually signed. A
deployed wallet defense runs at the victim's signing moment, so to measure those
defenses honestly we must score the GRANT: the `approve` / `setApprovalForAll` the
victim signed that the sweep later spent. This module recovers that grant on-chain.

Given a sweep, the victim is the token owner (arg 0 of the sweep) and the attacker
is the spender/operator (the sweep's `from`, i.e. tx sender). The grant is then the
most recent Approval / ApprovalForAll the token emitted for (owner=victim,
spender=attacker) at or before the sweep block. We read that log, take its
transaction, and return it as the artifact a wallet would have rendered at signing.

Usage:
    ALCHEMY_ENDPOINT_URL=... python3 -m demo.reconstruct <in_corpus.json> <out.json>
"""

from __future__ import annotations

import json
import os
import sys

from . import cast
from .attacks import MAX_DEC

MAXV = int(MAX_DEC)
RPC = os.environ.get("ALCHEMY_ENDPOINT_URL") or os.environ.get("MAINNET_RPC") \
    or "https://ethereum-rpc.publicnode.com"

PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"

# event topic0 (keccak of the signature)
APPROVAL = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"       # Approval(address,address,uint256)
APPROVAL_FOR_ALL = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"  # ApprovalForAll(address,address,bool)

# sweep selector -> how to read (victim arg index, spender source, token source, event)
_TRANSFER_FROM = "0x23b872dd"
_SAFE_TF = ("0x42842e0e", "0xb88d4fde")
_PERMIT2_BATCH = "0x0d58b1db"

# on-chain grants a victim signs that a wallet defense would render at signing:
# approve / increaseAllowance (ERC20) and setApprovalForAll (ERC721/1155).
_GRANT_SELECTORS = {"0x095ea7b3", "0x39509351", "0xa22cb465"}


def _topic_addr(addr: str) -> str:
    return "0x" + "0" * 24 + addr.lower().replace("0x", "")


def _get_logs(address: str, topic0: str, owner: str, spender: str, to_block: int) -> list[dict]:
    filt = {
        "fromBlock": "0x0",
        "toBlock": hex(to_block),
        "address": address,
        "topics": [topic0, _topic_addr(owner), _topic_addr(spender)],
    }
    raw = cast.rpc(RPC, "eth_getLogs", json.dumps(filt))
    return json.loads(raw) if raw.strip().startswith("[") else []


def _first(tok: str) -> str:
    return tok.split()[0]


def find_grant(case: dict) -> dict | None:
    """Return the victim's grant tx as a dict {tx_hash, block, frm, to, input, ...}
    or None if no matching Approval/ApprovalForAll precedes the sweep."""
    sel = (case.get("input") or "")[:10].lower()
    token = case.get("to", "")
    attacker = case.get("frm", "")
    sweep_block = int(case.get("block", 0))
    if not (token and attacker and sweep_block):
        return None

    if sel == _TRANSFER_FROM:
        args = cast.decode_calldata("transferFrom(address,address,uint256)", case["input"])
        victim = _first(args[0]); spender = attacker; event = APPROVAL; addr = token
    elif sel in _SAFE_TF:
        sig = "safeTransferFrom(address,address,uint256,bytes)" if sel == "0xb88d4fde" \
              else "safeTransferFrom(address,address,uint256)"
        args = cast.decode_calldata(sig, case["input"])
        victim = _first(args[0]); spender = attacker; event = APPROVAL_FOR_ALL; addr = token
    elif sel == _PERMIT2_BATCH:
        args = cast.decode_calldata("transferFrom((address,address,uint160,address)[])", case["input"])
        # decoded blob: first tuple is (from, to, amount, token)
        import re
        addrs = re.findall(r"0x[0-9a-fA-F]{40}", " ".join(args))
        victim = addrs[0] if addrs else ""; token_drained = addrs[3] if len(addrs) > 3 else token
        spender = PERMIT2; event = APPROVAL; addr = token_drained
    else:
        return None
    if not victim:
        return None

    try:
        # exclude the sweep's own block: an ERC20 transferFrom emits Approval too
        # (the decremented allowance), so the log at the sweep block is the sweep,
        # not the grant we are after.
        logs = _get_logs(addr, event, victim, spender, sweep_block - 1)
    except Exception:
        return None
    # Walk candidates newest-first and take the actual approval the victim SIGNED.
    # transferFrom-emitted Approvals (attacker's partial spends) are skipped: their
    # tx is a transferFrom sent by the attacker, not an approve sent by the victim.
    for log in list(reversed(logs))[:20]:  # cap tx fetches; the approve is near the top
        grant_hash = log["transactionHash"]
        try:
            t = cast.tx(RPC, grant_hash)
        except Exception:
            continue
        gsel = (t.get("input") or t.get("data") or "")[:10].lower()
        gfrom = t.get("from", "")
        signed_by_victim = gfrom.lower() == victim.lower()
        if gsel in _GRANT_SELECTORS and signed_by_victim:
            return {
                "grant_tx": grant_hash,
                "victim": victim,
                "attacker": spender,
                "token": addr,
                "grant_from": gfrom,
                "grant_to": t.get("to", ""),
                "grant_input": t.get("input") or t.get("data") or "",
                "grant_selector": gsel,
                "grant_block": int(log["blockNumber"], 16),
            }
    return None


_VICTIM_SIGNED_OPAQUE = {"nft-bulk-transfer", "payable-airdrop", "payable-wallet", "proxy-upgrade"}
_SWEEP_SELECTORS = (_TRANSFER_FROM, _PERMIT2_BATCH, *_SAFE_TF)


def _grant_case(orig: dict, g: dict) -> dict:
    """Turn a recovered grant into a corpus Case: the victim (frm) signs an
    approve / setApprovalForAll to the attacker (counterparty). This is the
    artifact a wallet would render at signing, not the attacker's later sweep."""
    gsel = g["grant_selector"]
    inp = g["grant_input"]
    if gsel == "0xa22cb465":
        args = cast.decode_calldata("setApprovalForAll(address,bool)", inp)
        cp = _first(args[0]); atype = "approve"
        amount = "UNLIMITED" if _first(args[1]).lower() in ("true", "1") else "0"
    elif gsel == "0x39509351":
        args = cast.decode_calldata("increaseAllowance(address,uint256)", inp)
        cp = _first(args[0]); amount = _first(args[1]); atype = "approve"
    else:  # 0x095ea7b3 approve(address,uint256)
        args = cast.decode_calldata("approve(address,uint256)", inp)
        cp = _first(args[0]); amount = _first(args[1]); atype = "approve"
    if amount.isdigit() and int(amount) >= MAXV:
        amount = "UNLIMITED"
    try:
        cp_contract = cast.has_code(RPC, cp)
    except Exception:
        cp_contract = False
    return {
        "id": orig["id"] + "-grant", "source": "real", "label": orig["label"],
        "malicious": True, "kind": "onchain", "action_type": atype, "chain_id": 1,
        "frm": g["grant_from"], "to": g["grant_to"], "input": inp, "value": "0",
        "counterparty": cp, "recipient": cp, "amount": amount,
        "counterparty_is_contract": cp_contract, "recipient_is_contract": cp_contract,
        "counterparty_known": False, "recipient_known": False,
        "tx_hash": g["grant_tx"], "block": g["grant_block"],
        "note": f"victim-signed grant reconstructed from PTXPHISH drain {orig.get('tx_hash','')[:12]} "
                f"(sweep spender {g['attacker'][:10]}); the artifact a wallet renders at signing.",
    }


def build_corpus(in_path: str, out_path: str) -> None:
    d = json.load(open(in_path))
    out = []
    stat = {"reconstructed": 0, "kept_opaque": 0, "benign": 0, "dropped_offchain": 0}
    for x in d:
        if not x.get("malicious"):
            out.append(x); stat["benign"] += 1; continue
        sel = (x.get("input") or "")[:10].lower()
        if sel in _SWEEP_SELECTORS:
            g = find_grant(x)
            if g:
                out.append(_grant_case(x, g)); stat["reconstructed"] += 1
            else:
                stat["dropped_offchain"] += 1  # off-chain grant: lives in the constructed suite
            print(f"  {x['id']:<12} {'RECONSTRUCTED' if g else 'off-chain (dropped)'}")
        elif x.get("label") in _VICTIM_SIGNED_OPAQUE:
            out.append(x); stat["kept_opaque"] += 1
        else:
            stat["dropped_offchain"] += 1  # orders etc: constructed suite
            print(f"  {x['id']:<12} off-chain/order (dropped)")
    json.dump(out, open(out_path, "w"), indent=2)
    print(f"\nwrote {out_path}: {stat}")


def _demo(path: str) -> None:
    d = json.load(open(path))
    mal = [x for x in d if x.get("malicious")]
    hit = miss = 0
    for x in mal:
        sel = (x.get("input") or "")[:10].lower()
        if sel not in (_TRANSFER_FROM, _PERMIT2_BATCH, *_SAFE_TF):
            continue
        g = find_grant(x)
        if g:
            hit += 1
            gsel = g["grant_input"][:10]
            ok = g["grant_from"].lower() == g["victim"].lower()
            print(f"  {x['id']:<12} sweep {sel} -> grant {gsel} block {g['grant_block']} "
                  f"from==victim:{ok}")
        else:
            miss += 1
            print(f"  {x['id']:<12} sweep {sel} -> NO GRANT FOUND")
    print(f"\nreconstructed {hit}, missed {miss}")


if __name__ == "__main__":
    if len(sys.argv) == 3:
        build_corpus(sys.argv[1], sys.argv[2])
    elif len(sys.argv) == 2:
        _demo(sys.argv[1])
    else:
        print(__doc__)
