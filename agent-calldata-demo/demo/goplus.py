"""Live address-reputation lens backed by GoPlus Security (real deployed API).

This is the one part of the harness that queries a real, deployed scanning
service rather than modeling a capability. GoPlus is a REPUTATION service: given
an address it returns known-bad flags (phishing, stealing_attack, sanctioned,
mixer, ...). It is not a transaction/signature simulator, so it cannot stand in
for the L5/L6 simulation rungs; it adds a distinct capability the modeled ladder
does not have: real-world address reputation.

Gated on GO_PLUS_APP_KEY / GO_PLUS_APP_SECRET (put them in a .env; run.sh sources
it). If unset, `available()` is False and the harness skips the live lens.

The finding this surfaces: reputation only fires on addresses it already knows
are bad. The attacks here all send to fresh addresses, so live reputation flags
none of them; a positive control confirms the query works, so the null is real.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request

BASE = "https://api.gopluslabs.io/api/v1"

# flags in address_security that mean "known bad"; a "1" is a hit
_MALICIOUS = (
    "blacklist_doubt", "blackmail_activities", "cybercrime", "darkweb_transactions",
    "fake_kyc", "financial_crime", "honeypot_related_address",
    "malicious_mining_activities", "money_laundering", "phishing_activities",
    "sanctioned", "stealing_attack", "mixer",
)

_token_cache: dict[str, float | str] = {}


def available() -> bool:
    return bool(os.environ.get("GO_PLUS_APP_KEY") and os.environ.get("GO_PLUS_APP_SECRET"))


def _token() -> str:
    now = time.time()
    if _token_cache.get("value") and float(_token_cache.get("exp", 0)) > now + 30:
        return str(_token_cache["value"])
    key = os.environ["GO_PLUS_APP_KEY"]
    secret = os.environ["GO_PLUS_APP_SECRET"]
    t = str(int(now))
    sign = hashlib.sha1((key + t + secret).encode()).hexdigest()
    body = json.dumps({"app_key": key, "time": int(t), "sign": sign}).encode()
    req = urllib.request.Request(BASE + "/token", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=25) as r:
        res = json.loads(r.read())["result"]
    _token_cache["value"] = res["access_token"]
    _token_cache["exp"] = now + int(res.get("expires_in", 3600))
    return res["access_token"]


def reputation(address: str, chain_id: int = 1) -> set[str]:
    """Return the set of malicious flags GoPlus reports for `address`
    (empty set = no known-bad reputation). Best-effort; network errors -> empty."""
    try:
        req = urllib.request.Request(f"{BASE}/address_security/{address}?chain_id={chain_id}")
        req.add_header("Authorization", _token())
        with urllib.request.urlopen(req, timeout=25) as r:
            res = json.loads(r.read()).get("result", {}) or {}
    except (urllib.error.URLError, KeyError, json.JSONDecodeError, TimeoutError):
        return set()
    return {f for f in _MALICIOUS if str(res.get(f)) == "1"}


def approval_risk(address: str, chain_id: int = 1) -> dict:
    """GoPlus approval_security for a spender/contract: whether it is trusted,
    doubted, or exhibits malicious approval behaviour. Returns {} on error."""
    try:
        req = urllib.request.Request(
            f"{BASE}/approval_security/{chain_id}?contract_addresses={address}")
        req.add_header("Authorization", _token())
        with urllib.request.urlopen(req, timeout=25) as r:
            res = json.loads(r.read()).get("result", {}) or {}
    except (urllib.error.URLError, KeyError, json.JSONDecodeError, TimeoutError):
        return {}
    if not isinstance(res, dict):
        return {}
    mb = res.get("malicious_behavior") or []
    return {
        "is_contract": str(res.get("is_contract")) == "1",
        "trust_list": str(res.get("trust_list")) == "1",
        "doubt_list": str(res.get("doubt_list")) == "1",
        "malicious_behavior": list(mb) if isinstance(mb, list) else [],
        "tag": res.get("tag") or "",
    }
