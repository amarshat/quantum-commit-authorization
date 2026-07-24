"""Turn labeled real transaction hashes into corpus records.

You provide a seeds file: a JSON list of labeled on-chain drainer / phishing (and
benign-control) transactions, each with at least a `tx_hash`, its ground-truth
`label` and `malicious` flag, and a source `note`. This script fetches each
transaction from a real RPC, decodes the common drain shapes (approve, transfer,
permit, transferFrom), reads contract-vs-EOA from chain state, and writes a
corpus/real/*.json file the measurement (demo/measure.py) then runs past the
hosted defenses (Tenderly, GoPlus).

This does NOT ship or invent a dataset. Populate the seeds from a labeled source
(the PTXPHISH release, arXiv 2409.02386; ScamSniffer / BlockSec drainer feeds;
on-chain-labeled addresses) and cite each row in its `note`.

Off-chain-signature phishing (EIP-2612 permit, Seaport orders) has no transaction
at signing time, so those cases are authored by hand from the signed message
fields, not hydrated here. This tool covers the on-chain artifacts.

Usage:
    MAINNET_RPC=https://your-endpoint python3 -m demo.hydrate seeds.json realdrains.json

Writes corpus/real/realdrains.json.
"""

from __future__ import annotations

import json
import os
import re
import sys

from . import cast
from .corpus import REAL_DIR, Case
from .attacks import MAX_DEC

MAXV = int(MAX_DEC)
DEFAULT_RPC = os.environ.get("MAINNET_RPC", "https://eth.llamarpc.com")

def _first(token: str) -> str:
    # cast decode-calldata may annotate values ("123 [1.2e2]"); take the first token.
    return token.split()[0]


# Each handler takes the decoded args and returns (action_type, counterparty, amount).
def _h_approve(a):        return "approve", _first(a[0]), _first(a[1])
def _h_transfer(a):       return "transfer", _first(a[0]), _first(a[1])
def _h_transferfrom(a):   return "transfer", _first(a[1]), _first(a[2])          # to, value
def _h_permit(a):         return "permit", _first(a[1]), _first(a[2])            # spender, value
def _h_increase(a):       return "approve", _first(a[0]), _first(a[1])
def _h_setapproveall(a):  return "approve", _first(a[0]), ("UNLIMITED" if _first(a[1]).lower() in ("true", "1") else "0")
def _h_safetransfer(a):   return "transfer", _first(a[1]), "1"                   # NFT to, one token

# selector -> (full signature, handler)
SELECTORS = {
    "0x095ea7b3": ("approve(address,uint256)", _h_approve),
    "0xa9059cbb": ("transfer(address,uint256)", _h_transfer),
    "0x23b872dd": ("transferFrom(address,address,uint256)", _h_transferfrom),
    "0xd505accf": ("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", _h_permit),
    "0x39509351": ("increaseAllowance(address,uint256)", _h_increase),
    "0xa22cb465": ("setApprovalForAll(address,bool)", _h_setapproveall),
    "0x42842e0e": ("safeTransferFrom(address,address,uint256)", _h_safetransfer),
    "0xb88d4fde": ("safeTransferFrom(address,address,uint256,bytes)", _h_safetransfer),
}

# Order / batch-wrapper selectors whose sink lives in a nested struct. We decode
# each with its full signature and pull one counterparty address out, so the case
# stops being opaque to the rule/reputation tiers. The extractor is anchored on
# each selector's verified tuple shape (see the per-handler comment); a mis-parse
# falls back to an empty counterparty rather than a wrong one.
_ADDR = re.compile(r"0x[0-9a-fA-F]{40}")


def _x_bulktransfer(s):
    # bulkTransfer(((type,token,id,amount)[], recipient, bool)[], bytes32): the
    # NFT sink is the outer-tuple address, anchored just before its trailing bool.
    m = re.search(r"\],\s*(0x[0-9a-fA-F]{40}),\s*(?:true|false)\)", s)
    return "transfer", (m.group(1) if m else ""), "0"


def _x_permit2_batch(s):
    # transferFrom((from,to,amount,token)[]): victim is `from` (1st address), the
    # sink is `to` (2nd address of the first tuple).
    a = _ADDR.findall(s)
    return "transfer", (a[1] if len(a) >= 2 else ""), "0"


def _x_order_maker(s):
    # Seaport matchOrders / Blur execute|bulkExecute: the order maker (Seaport
    # offerer / Blur trader) is the first address in the decoded struct. It is the
    # party bound by the signed order; we surface it and label the case "order".
    a = _ADDR.findall(s)
    return "order", (a[0] if a else ""), "0"


# selector -> (full signature, extractor). Signatures verified against real
# mainnet calldata in the PTXPHISH sample.
WRAPPERS = {
    "0x32389b71": ("bulkTransfer(((uint8,address,uint256,uint256)[],address,bool)[],bytes32)", _x_bulktransfer),
    "0x0d58b1db": ("transferFrom((address,address,uint160,address)[])", _x_permit2_batch),
    "0xa8174404": ("matchOrders(((address,address,(uint8,address,uint256,uint256,uint256)[],(uint8,address,uint256,uint256,uint256,address)[],uint8,uint256,uint256,bytes32,uint256,bytes32,uint256),bytes)[],((uint256,uint256)[],(uint256,uint256)[])[])", _x_order_maker),
    "0x9a1fc3a7": ("execute(((address,uint8,address,address,uint256,uint256,address,uint256,uint256,uint256,(uint16,address)[],uint256,bytes),uint8,bytes32,bytes32,bytes,uint8,uint256),((address,uint8,address,address,uint256,uint256,address,uint256,uint256,uint256,(uint16,address)[],uint256,bytes),uint8,bytes32,bytes32,bytes,uint8,uint256))", _x_order_maker),
    "0xb3be57f8": ("bulkExecute((((address,uint8,address,address,uint256,uint256,address,uint256,uint256,uint256,(uint16,address)[],uint256,bytes),uint8,bytes32,bytes32,bytes,uint8,uint256),((address,uint8,address,address,uint256,uint256,address,uint256,uint256,uint256,(uint16,address)[],uint256,bytes),uint8,bytes32,bytes32,bytes,uint8,uint256))[])", _x_order_maker),
}

# Seaport variants we recognize as orders but do not yet field-decode (their tuple
# layouts differ from matchOrders); left opaque to the field tiers, still visible
# to a selector-agnostic simulator.
SEAPORT = {
    "0xfb0f3ee1",  # fulfillBasicOrder
    "0x00000000",  # fulfillBasicOrder_efficient_6GL6yc (Seaport 1.5)
    "0xb3a34c4c",  # fulfillOrder
    "0xe7acab24",  # fulfillAdvancedOrder
    "0x87201b41",  # fulfillAvailableAdvancedOrders
    "0xed98a574",  # fulfillAvailableOrders
    "0x55944a42",  # matchAdvancedOrders
}


def hydrate_one(seed: dict, rpc: str) -> Case:
    t = cast.tx(rpc, seed["tx_hash"])
    frm = t.get("from", "")
    to = t.get("to", "") or ""
    inp = t.get("input") or t.get("data") or ""
    raw_val = t.get("value", "0x0")
    value = str(int(raw_val, 16)) if isinstance(raw_val, str) and raw_val.startswith("0x") else str(raw_val)

    sel = inp[:10].lower()
    counterparty = recipient = ""
    amount = "0"
    action_type = seed.get("action_type", "call")
    if sel in SELECTORS:
        sig, handler = SELECTORS[sel]
        try:
            action_type, counterparty, amount = handler(cast.decode_calldata(sig, inp))
            recipient = counterparty
            if amount.isdigit() and int(amount) >= MAXV:
                amount = "UNLIMITED"
        except Exception:  # a mis-guessed selector should not drop the case
            counterparty = recipient = ""
            amount = "0"
    elif sel in WRAPPERS:
        full_sig, extract = WRAPPERS[sel]
        try:
            decoded = " ".join(cast.decode_calldata(full_sig, inp))
            action_type, counterparty, amount = extract(decoded)
            recipient = counterparty
        except Exception:  # nested decode failed; keep the case, leave it opaque
            counterparty = recipient = ""
            amount = "0"
    elif sel in SEAPORT:
        action_type = "order"

    cp_contract = cast.has_code(rpc, counterparty) if counterparty else False
    return Case(
        id=seed["id"],
        source="real",
        label=seed["label"],
        malicious=bool(seed["malicious"]),
        kind=seed.get("kind", "onchain"),
        action_type=action_type,
        chain_id=int(seed.get("chain_id", 1)),
        frm=frm,
        to=to,
        input=inp,
        value=value,
        counterparty=counterparty,
        recipient=recipient,
        amount=amount,
        counterparty_is_contract=cp_contract,
        recipient_is_contract=cp_contract,
        counterparty_known=bool(seed.get("counterparty_known", False)),
        recipient_known=bool(seed.get("recipient_known", False)),
        tx_hash=seed["tx_hash"],
        block=int(t.get("blockNumber", "0x0"), 16) if str(t.get("blockNumber", "0")).startswith("0x") else int(t.get("blockNumber", 0)),
        note=seed.get("note", ""),
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    seeds_path, out_name = argv
    rpc = DEFAULT_RPC
    with open(seeds_path) as f:
        seeds = json.load(f)

    cases = []
    for seed in seeds:
        try:
            c = hydrate_one(seed, rpc)
            cases.append(c.to_dict())
            print(f"  {c.id:<28} {c.action_type:<10} cp={c.counterparty[:12]}… amount={c.amount}")
        except Exception as e:  # keep going; a bad hash should not sink the batch
            print(f"  {seed.get('id', '?'):<28} SKIPPED: {e}")

    os.makedirs(REAL_DIR, exist_ok=True)
    out_path = os.path.join(REAL_DIR, out_name)
    with open(out_path, "w") as f:
        json.dump(cases, f, indent=2)
    print(f"\nwrote {out_path} ({len(cases)}/{len(seeds)} hydrated)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
