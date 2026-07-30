"""Source-availability lens on the *authority object* (real deployed API).

Powered by Etherscan.io APIs.

Every other tier in this harness inspects the transaction: its fields, its
simulated asset diff, the reputation of its addresses. None of them reads the
*code* of the contract that will govern the outcome. This tier asks the prior
question a code-reading defense has to answer before it can read anything:

    which contract actually decides what happens here?

For the drain shapes in the corpus that is usually NOT the transaction target:

    approve(spender, unlimited)   the target is the token (BoredApeYachtClub,
                                  Tether, stETH). The token is legitimate and
                                  verified. The authority goes to `spender`,
                                  which is an EOA with no code at all.
    transfer(to, ids)             the target is OpenSea's Seaport TransferHelper,
                                  which is legitimate and verified. The assets go
                                  to `recipient`, again an EOA.
    upgradeTo(impl)               the target is the victim's own OpenSea
                                  OwnableDelegateProxy: verified, audited, benign.
                                  Every subsequent call is governed by `impl`,
                                  an address supplied in the calldata.
    opaque call                   here the target genuinely IS the attacker's
                                  contract, and reading it is the right move.

So this tier resolves the authority object first, then reports whether a code
reader would have anything to read. It deliberately does NOT judge whether the
code is malicious: hand-rolling a malice classifier here would be a strawman of
the agentic analysers this is meant to characterise. Judging the fetched source
is a separate step (see `--dump-sources`).

Read the states as availability, not detection:

    catch  the authority object has VERIFIED SOURCE. A code reader could decide
           here. This is an upper bound on what any code-reading tier achieves,
           in the same sense that the reputation tier's hits are an upper bound.
    blind  the authority object has code but no verified source: bytecode only.
    na     the authority object has no code (an EOA, or nothing deployed).
           Source analysis is inapplicable by construction, not merely unhelpful.

`reason` always names which object was chosen, and flags the case where the
transaction target is verified but is not the authority object. That divergence
is the finding: source availability on the target is nearly total and nearly
useless.

Timing caveat, stated because it bounds every number here: Etherscan exposes no
verification date, so we cannot establish whether a given contract's source was
public at the moment the victim signed. Sourcify's dates are bulk-import
artifacts and cannot answer it either. Availability is therefore measured as of
now, which is an upper bound.

Gated on ETHERSCAN_API_KEY (free tier: 5 calls/sec, 100k/day). If unset,
`available()` is False and the harness skips the lens.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = "Source availability (authority object)"
TIER = "hosted"

ATTRIBUTION = "Powered by Etherscan.io APIs"

BASE = "https://api.etherscan.io/v2/api"

# EIP-1967-era OpenSea proxy upgrade, and the OZ transparent-proxy variants.
# `upgradeTo(address)` / `upgradeToAndCall(address,bytes)`.
_UPGRADE_SELECTORS = ("0x3659cfe6", "0x4f1ef286")

# Free tier is 5 calls/sec. Stay under it rather than on it.
_RATE_SLEEP = float(os.environ.get("ETHERSCAN_RATE_SLEEP", "0.25"))
_MAX_CALLS = int(os.environ.get("ETHERSCAN_MAX_CALLS", "300"))

_CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cache")
_CACHE_FILE = os.path.join(_CACHE_DIR, "etherscan_src.json")

STATS = {"live": 0, "cache": 0, "capped": 0}
_cache: dict | None = None


def available() -> bool:
    return bool(os.environ.get("ETHERSCAN_API_KEY"))


def _load_cache() -> dict:
    global _cache
    if _cache is None:
        try:
            with open(_CACHE_FILE) as f:
                _cache = json.load(f)
        except (OSError, ValueError):
            _cache = {}
    return _cache


def _save_cache() -> None:
    os.makedirs(_CACHE_DIR, exist_ok=True)
    with open(_CACHE_FILE, "w") as f:
        json.dump(_cache, f)


def _get(params: dict) -> dict:
    q = urllib.parse.urlencode({**params, "apikey": os.environ["ETHERSCAN_API_KEY"]})
    req = urllib.request.Request(f"{BASE}?{q}", headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        out = json.loads(r.read())
    time.sleep(_RATE_SLEEP)
    return out


def source_info(address: str, chain_id: int = 1) -> dict:
    """Cached getsourcecode. Returns {has_code, verified, name}.

    A cache hit costs nothing. Results are keyed by chain and address, and the
    cache is gitignored, so a re-run is free and offline.
    """
    addr = (address or "").lower()
    if not addr.startswith("0x") or len(addr) != 42:
        return {"has_code": False, "verified": False, "name": "", "note": "not an address"}
    key = f"{chain_id}:{addr}"
    cache = _load_cache()
    if key in cache:
        STATS["cache"] += 1
        return cache[key]
    if STATS["live"] >= _MAX_CALLS:
        STATS["capped"] += 1
        return {"has_code": False, "verified": False, "name": "", "note": "call cap reached"}
    try:
        # getsourcecode cannot distinguish an EOA from an unverified contract:
        # both come back with empty SourceCode and an ABI of "Contract source code
        # not verified". So establish code presence first, and only ask about
        # source when there is code to have source for.
        code = _get({"chainid": str(chain_id), "module": "proxy",
                     "action": "eth_getCode", "address": addr, "tag": "latest"})
        raw = code.get("result") or "0x"
        has_code = raw not in ("0x", "0x0", "")
        if not has_code:
            info = {"has_code": False, "verified": False, "name": "", "note": ""}
        else:
            res = _get({"chainid": str(chain_id), "module": "contract",
                        "action": "getsourcecode", "address": addr})
            row = (res.get("result") or [{}])[0]
            src = row.get("SourceCode") or ""
            info = {"has_code": True, "verified": bool(src),
                    "name": row.get("ContractName") or "", "note": ""}
    except (urllib.error.URLError, ValueError, KeyError) as exc:
        return {"has_code": False, "verified": False, "name": "",
                "note": f"lookup failed: {type(exc).__name__}"}
    STATS["live"] += 1
    cache[key] = info
    _save_cache()
    return info


def authority_object(case) -> tuple[str, str]:
    """Resolve the contract whose code governs the outcome. Returns (address, why)."""
    data = (case.input or "").lower()
    if data[:10] in _UPGRADE_SELECTORS and len(data) >= 74:
        # the new implementation is the first argument, right-aligned in word 1
        return "0x" + data[34:74], "new implementation from the upgradeTo argument"
    if case.action_type in ("approve", "permit", "permit2_approve", "order", "delegation"):
        if case.counterparty:
            return case.counterparty, "the spender/operator receiving the authority"
    if case.action_type == "transfer" and case.recipient:
        return case.recipient, "the recipient receiving the assets"
    if case.kind == "onchain" and case.to:
        return case.to, "the transaction target (an opaque call to the callee's own code)"
    return "", "no resolvable authority object"


def verdict(case) -> tuple[str, str]:
    obj, why = authority_object(case)
    if not obj:
        return "na", why
    info = source_info(obj, case.chain_id)
    if info.get("note"):
        return "na", info["note"]

    # Is the transaction target itself verified? If it is, but it is not the
    # authority object, that is the wrong-object gap this tier exists to expose.
    divergence = ""
    same = case.to and obj.lower() == case.to.lower()
    if not same and case.to and case.kind == "onchain":
        tgt = source_info(case.to, case.chain_id)
        if tgt.get("verified"):
            divergence = (f"; the tx target {tgt['name'] or case.to[:10]} IS verified, "
                          f"but it is not the object that governs the outcome")

    if not info["has_code"]:
        return "na", (f"authority object {obj[:10]} ({why}) has no code: "
                      f"source analysis is inapplicable, not merely unhelpful{divergence}")
    if not info["verified"]:
        return "blind", (f"authority object {obj[:10]} ({why}) is a contract with no "
                         f"verified source: a reader gets bytecode only{divergence}")
    return "catch", (f"verified source available for the authority object "
                     f"{info['name'] or obj[:10]} ({why}){divergence}")


def summary() -> str:
    s = STATS
    return (f"source availability: {s['live']} live lookups, {s['cache']} cached, "
            f"{s['capped']} capped [cap {_MAX_CALLS}]. {ATTRIBUTION}.")
