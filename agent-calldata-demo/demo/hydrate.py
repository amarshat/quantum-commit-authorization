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
import sys

from . import cast
from .corpus import REAL_DIR, Case
from .attacks import MAX_DEC

MAXV = int(MAX_DEC)
DEFAULT_RPC = os.environ.get("MAINNET_RPC", "https://eth.llamarpc.com")

# selector -> (full signature, action_type, index of counterparty, index of amount)
SELECTORS = {
    "0x095ea7b3": ("approve(address,uint256)", "approve", 0, 1),
    "0xa9059cbb": ("transfer(address,uint256)", "transfer", 0, 1),
    "0x23b872dd": ("transferFrom(address,address,uint256)", "transfer", 1, 2),
    "0xd505accf": ("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", "permit", 1, 2),
}


def _first(token: str) -> str:
    # cast decode-calldata may annotate values ("123 [1.2e2]"); take the first token.
    return token.split()[0]


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
        sig, action_type, cp_i, amt_i = SELECTORS[sel]
        args = cast.decode_calldata(sig, inp)
        counterparty = recipient = _first(args[cp_i])
        amount = _first(args[amt_i])
        if amount.isdigit() and int(amount) >= MAXV:
            amount = "UNLIMITED"

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
