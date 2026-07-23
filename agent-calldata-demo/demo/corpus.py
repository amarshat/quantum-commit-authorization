"""Uniform case schema for the empirical coverage measurement (paper 2).

The modeled scorecard (demo/scorecard.py) scores eight synthetic drains against a
capability ladder we *model*. The measurement extends that: it runs a corpus of
cases past REAL deployed defenses (demo/measure.py) and records which defense
catches which drain. Two case sources feed those defenses:

  - synthetic: derived from the deterministic attack suite (demo/attacks.py), run
    on the local anvil chain. These cover the edge cases real corpora
    under-sample (EIP-7702 delegation, Permit2 SignatureTransfer, honeypot/TOCTOU
    armed after simulation). They carry ground-truth context (is the counterparty
    a contract, is it allowlisted) computed from the chain, so an open-rule
    defense can be evaluated against them faithfully.
  - real: labeled on-chain drainer / phishing transactions loaded from
    corpus/real/*.json. These are replayed against hosted defenses (Tenderly,
    GoPlus) that see real mainnet state. NOTE: this repo ships the loader and the
    schema, not a bundled dataset; populate corpus/real/ from a labeled source
    (e.g. the PTXPHISH release, arXiv 2409.02386, or on-chain-labelled drainer
    txns) before the hosted-defense measurement is meaningful.

A Case carries enough to (a) present the artifact to a real defense and (b) know
ground truth, so each verdict can be scored catch / miss / blind.
"""

from __future__ import annotations

import glob
import json
import os
from dataclasses import asdict, dataclass, field

from . import cast, reviewers
from .attacks import ATTACKS, MAX_DEC
from .chain import Chain

REAL_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "corpus", "real"
)
MAXV = int(MAX_DEC)


@dataclass
class Case:
    id: str
    source: str                     # "synthetic" | "real"
    label: str                      # ground-truth category (e.g. approval-drain, permit-phish, benign)
    malicious: bool                 # ground truth: is this actually a drain?
    kind: str                       # "onchain" | "offchain_sig"
    action_type: str                # approve|transfer|call|permit|order|delegation|permit2_approve
    chain_id: int = 1

    # the concrete artifact, for a hosted defense to inspect:
    frm: str = ""                   # signer / sender (the owner whose funds are at risk)
    to: str = ""                    # tx target (on-chain) or verifying contract (off-chain sig)
    input: str = ""                 # calldata (on-chain); "" for an off-chain signature (no tx)
    value: str = "0"                # wei value

    # decoded semantics + ground-truth context, as a clear-signer / rule engine sees:
    counterparty: str = ""
    recipient: str = ""
    amount: str = "0"               # token amount as a decimal string, or "UNLIMITED" / "account"
    counterparty_is_contract: bool = False
    recipient_is_contract: bool = False
    counterparty_known: bool = False   # allowlisted / known-good target
    recipient_known: bool = False

    # real cases only:
    tx_hash: str = ""
    block: int = 0
    note: str = ""

    @property
    def unlimited(self) -> bool:
        return self.amount == "UNLIMITED" or (self.amount.isdigit() and int(self.amount) >= MAXV)

    def to_dict(self) -> dict:
        return asdict(self)


def _amount_str(atype: str, amount: int) -> str:
    if atype == "delegation":
        return "account"
    return "UNLIMITED" if amount >= MAXV else str(amount)


def synthetic_cases(chain: Chain) -> list[Case]:
    """Build a Case per attack, on the live anvil chain, with ground-truth context
    (contract-vs-EOA, allowlisted-or-not) read from the chain. Mirrors the per-attack
    setup in scorecard.run so the artifacts are the real ones the attacks produce."""
    known = chain.allowlist_addrs  # bound method
    cases: list[Case] = []
    for atk in ATTACKS:
        chain.extra_allowlist = set()
        chain.deploy_usdc()
        chain.mint("agent", 1_000_000)

        action = atk.build(chain)
        atype, counterparty, recipient, amount = reviewers._decode(action, chain)
        allow = known(reviewers.ALLOWLIST_ROLES)

        to = action.to or chain.usdc
        cases.append(Case(
            id=atk.id,
            source="synthetic",
            label=atype,
            malicious=True,
            kind=action.kind,
            action_type=atype,
            chain_id=31337,
            frm=chain.addr("agent"),
            to=to,
            input=action.calldata,          # "" for off-chain signatures
            value="0",
            counterparty=counterparty,
            recipient=recipient,
            amount=_amount_str(atype, amount),
            counterparty_is_contract=cast.has_code(chain.rpc, counterparty),
            recipient_is_contract=cast.has_code(chain.rpc, recipient),
            counterparty_known=counterparty.lower() in allow,
            recipient_known=recipient.lower() in allow,
            note=atk.true_effect,
        ))
    return cases


# --- constructed pending simulator suite -----------------------------------
# Real calldata to real mainnet contracts, simulated live at latest state. This
# is the substrate the pre-sign simulator tier is measured on: a latest-state
# simulator cannot replay executed history, so drains are posed as pending
# transactions (what an agent is about to sign), which is what the simulator is
# built to inspect. Same taxonomy as the synthetic suite, real addresses.
USDC_MAINNET = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
UNIVERSAL_ROUTER = "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af"
WHALE = "0x28C6c06298d514Db089934071355E5743bf21d60"          # a large USDC holder (funds the transfer sim)
STRANGER = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"        # a fresh EOA standing in for the attacker
KNOWN_MERCHANT = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"  # an allowlisted payee


def _constructed(cid, atype, calldata, cp, amount, cp_contract, cp_known, malicious) -> Case:
    return Case(
        id=cid, source="constructed", label=atype, malicious=malicious, kind="onchain",
        action_type=atype, chain_id=1, frm=WHALE, to=USDC_MAINNET, input=calldata,
        counterparty=cp, recipient=cp, amount=amount,
        counterparty_is_contract=cp_contract, recipient_is_contract=cp_contract,
        counterparty_known=cp_known, recipient_known=cp_known,
        note="constructed pending drain: real calldata to real mainnet contracts",
    )


def constructed_sim_cases() -> list[Case]:
    """A small, fixed suite (real calldata, encoded offline). Kept tiny on purpose:
    the simulator is PAYG, and demo/alchemy.py caches every response, so this
    costs a handful of live calls once and nothing thereafter."""
    m = MAX_DEC
    ap = lambda spender, amt: cast.calldata("approve(address,uint256)", spender, amt)
    tr = lambda to, amt: cast.calldata("transfer(address,uint256)", to, amt)
    return [
        _constructed("c-approve-unlimited-stranger", "approve", ap(STRANGER, m), STRANGER, "UNLIMITED", False, False, True),
        _constructed("c-transfer-stranger", "transfer", tr(STRANGER, "1000000"), STRANGER, "1000000", False, False, True),
        _constructed("c-approve-unlimited-router", "approve", ap(UNIVERSAL_ROUTER, m), UNIVERSAL_ROUTER, "UNLIMITED", True, True, True),
        _constructed("c-permit2-approve", "permit2_approve", ap(PERMIT2, m), PERMIT2, "UNLIMITED", True, True, True),
        _constructed("c-benign-approve-router", "approve", ap(UNIVERSAL_ROUTER, "1000000"), UNIVERSAL_ROUTER, "1000000", True, True, False),
        _constructed("c-benign-transfer-known", "transfer", tr(KNOWN_MERCHANT, "1000000"), KNOWN_MERCHANT, "1000000", False, True, False),
    ]


def real_cases() -> list[Case]:
    """Load labeled real transactions from corpus/real/*.json. Each file is a JSON
    list of objects matching the Case fields (extra keys are ignored). Missing =
    empty list, which is fine until a dataset is dropped in."""
    out: list[Case] = []
    for path in sorted(glob.glob(os.path.join(REAL_DIR, "*.json"))):
        with open(path) as f:
            records = json.load(f)
        for rec in records:
            fields = {k: rec[k] for k in rec if k in Case.__dataclass_fields__}
            fields.setdefault("source", "real")
            out.append(Case(**fields))
    return out
