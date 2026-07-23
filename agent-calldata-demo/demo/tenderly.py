"""Live transaction simulation backed by Tenderly (real deployed API).

This is a genuinely hosted defense: it sends a real transaction to Tenderly's
Simulation API and reads back the asset changes and logs Tenderly computes against
real network state, the same engine wallets embed for pre-sign simulation. Tier =
"hosted".

Gated on TENDERLY_ACCESS_KEY + TENDERLY_ACCOUNT + TENDERLY_PROJECT (put them in a
.env; run.sh sources it). If unset, available() is False and the runner skips it.

Scope, stated honestly:
  - A hosted simulator can only run against networks it knows. It cannot see the
    local anvil chain the SYNTHETIC suite runs on, so synthetic cases return
    "na". Tenderly is meaningful for the REAL corpus (mainnet drainer txns).
  - An off-chain signature has no transaction to simulate at signing time, so
    such cases return "blind" (a structural limit, the paper's point, not a bug).

verdict(case) -> (state, reason), state in {"catch","miss","blind","na"}.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

API = "https://api.tenderly.co/api/v1"
NAME = "Tenderly simulation"
TIER = "hosted"


def available() -> bool:
    return bool(
        os.environ.get("TENDERLY_ACCESS_KEY")
        and os.environ.get("TENDERLY_ACCOUNT")
        and os.environ.get("TENDERLY_PROJECT")
    )


def simulate(case) -> dict:
    """Call Tenderly's Simulation API for `case`. Returns the parsed result dict,
    or {"error": ...} on any failure. Best-effort; never raises."""
    acct = os.environ["TENDERLY_ACCOUNT"]
    proj = os.environ["TENDERLY_PROJECT"]
    url = f"{API}/account/{acct}/project/{proj}/simulate"
    payload = {
        "network_id": str(case.chain_id),
        "from": case.frm,
        "to": case.to,
        "input": case.input or "0x",
        "value": case.value or "0",
        "save": False,
        "save_if_fails": True,
        "simulation_type": "full",
    }
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Access-Key", os.environ["TENDERLY_ACCESS_KEY"])
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            return json.loads(r.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        return {"error": str(e)}


# ERC-20 Approval(address indexed owner, address indexed spender, uint256)
_APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"


def _outgoing_transfer(result: dict, owner: str) -> tuple[bool, str]:
    """True if Tenderly's asset changes show value leaving `owner`."""
    info = (result.get("transaction", {}) or {}).get("transaction_info", {}) or {}
    for ch in info.get("asset_changes") or []:
        if str(ch.get("type", "")).lower() == "transfer":
            frm = str(ch.get("from", "")).lower()
            to = str(ch.get("to", "")).lower()
            if frm == owner.lower() and to != owner.lower():
                sym = (ch.get("token_info") or {}).get("symbol", "token")
                return True, f"simulation shows {ch.get('amount', '?')} {sym} leaving the owner to {to}"
    return False, ""


def _approval_to(result: dict, owner: str, allowlisted: set[str]) -> tuple[bool, str]:
    """True if the simulated logs grant an allowance from `owner` to a spender
    that is not allowlisted."""
    info = (result.get("transaction", {}) or {}).get("transaction_info", {}) or {}
    for log in info.get("logs") or []:
        raw = log.get("raw") or {}
        topics = raw.get("topics") or []
        if topics and str(topics[0]).lower() == _APPROVAL_TOPIC and len(topics) >= 3:
            log_owner = "0x" + str(topics[1])[-40:]
            spender = "0x" + str(topics[2])[-40:]
            if log_owner.lower() == owner.lower() and spender.lower() not in allowlisted:
                return True, f"simulation shows an approval from the owner to non-allowlisted {spender}"
    return False, ""


def verdict(case, allowlisted: set[str] | None = None) -> tuple[str, str]:
    allowlisted = {a.lower() for a in (allowlisted or set())}
    if case.kind == "offchain_sig":
        return "blind", "off-chain signature: there is no transaction to simulate at signing time"
    if case.source != "real":
        return "na", "synthetic local-chain case; a hosted simulator only runs against real networks"
    if not case.input:
        return "na", "no calldata to simulate"

    result = simulate(case)
    if "error" in result:
        return "na", f"simulation error: {result['error']}"

    out, why = _outgoing_transfer(result, case.frm)
    if out:
        return "catch", why
    appr, why = _approval_to(result, case.frm, allowlisted | ({case.counterparty.lower()} if case.counterparty_known else set()))
    if appr:
        return "catch", why
    return "miss", "simulation shows no adverse asset change from the owner (the harmful state is not reached at simulation time)"
