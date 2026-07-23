"""Live transaction simulation backed by Alchemy (real deployed API).

A genuinely hosted defense: it sends a real transaction to Alchemy's
`alchemy_simulateAssetChanges` and reads back the asset changes Alchemy computes
against real network state, the same pre-sign simulation wallets embed. Alchemy
labels each change TRANSFER or APPROVE with from/to, so approvals and outbound
transfers are both visible. Tier = "hosted".

Chosen over Tenderly because Tenderly's Simulation API is now paid / sales-gated
(the free tier is browser-only, no API), whereas Alchemy's simulation is
self-serve and free (up to 1,000 simulations/day). That obtainability gap, which
real simulators an independent researcher can actually call, is itself a finding
for the paper.

Gated on ALCHEMY_API_KEY (put it in a .env; run.sh sources it). If unset,
available() is False and the runner skips it.

Scope, stated honestly (same structural limits as any hosted simulator):
  - It simulates against real Alchemy-hosted networks, not the local anvil chain
    the SYNTHETIC suite runs on, so synthetic cases return "na". It is meaningful
    for the REAL corpus (mainnet drainer txns).
  - An off-chain signature has no transaction to simulate at signing time, so
    those cases return "blind".

verdict(case) -> (state, reason), state in {"catch","miss","blind","na"}.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

NAME = "Alchemy simulation"
TIER = "hosted"

# chain_id -> Alchemy network subdomain
NETWORKS = {
    1: "eth-mainnet", 8453: "base-mainnet", 42161: "arb-mainnet",
    10: "opt-mainnet", 137: "polygon-mainnet",
}


def available() -> bool:
    return bool(os.environ.get("ALCHEMY_API_KEY"))


def _url(chain_id: int) -> str:
    net = NETWORKS.get(chain_id, "eth-mainnet")
    return f"https://{net}.g.alchemy.com/v2/{os.environ['ALCHEMY_API_KEY']}"


def simulate(case) -> dict:
    """Call alchemy_simulateAssetChanges for `case`. Returns the parsed `result`
    dict, or {"error": ...} on any failure. Best-effort; never raises."""
    tx = {"from": case.frm, "to": case.to, "value": "0x0", "data": case.input or "0x"}
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1,
        "method": "alchemy_simulateAssetChanges", "params": [tx],
    }).encode()
    req = urllib.request.Request(_url(case.chain_id), data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            payload = json.loads(r.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        return {"error": str(e)}
    if "error" in payload:
        return {"error": payload["error"]}
    return payload.get("result", {}) or {}


def _adverse(result: dict, owner: str, allowlisted: set[str]) -> tuple[bool, str]:
    owner = owner.lower()
    for ch in result.get("changes") or []:
        ctype = str(ch.get("changeType", "")).upper()
        frm = str(ch.get("from", "")).lower()
        to = str(ch.get("to", "")).lower()
        sym = ch.get("symbol") or ch.get("assetType") or "asset"
        if ctype == "TRANSFER" and frm == owner and to and to != owner:
            return True, f"simulation shows {ch.get('amount', '?')} {sym} transferred from the owner to {to}"
        if ctype == "APPROVE" and frm == owner and to and to not in allowlisted:
            return True, f"simulation shows an approval from the owner to non-allowlisted {to}"
    return False, ""


def verdict(case, allowlisted: set[str] | None = None) -> tuple[str, str]:
    allow = {a.lower() for a in (allowlisted or set())}
    if case.counterparty_known and case.counterparty:
        allow.add(case.counterparty.lower())
    if case.kind == "offchain_sig":
        return "blind", "off-chain signature: there is no transaction to simulate at signing time"
    if case.source != "real":
        return "na", "synthetic local-chain case; a hosted simulator only runs against real networks"
    if not case.input:
        return "na", "no calldata to simulate"

    result = simulate(case)
    if "error" in result:
        return "na", f"simulation error: {result['error']}"
    adverse, why = _adverse(result, case.frm, allow)
    if adverse:
        return "catch", why
    return "miss", "simulation shows no adverse asset change from the owner (the harmful state is not reached at simulation time)"
