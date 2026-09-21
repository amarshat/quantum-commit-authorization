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

An object that is an EOA carrying an EIP-7702 delegation designator is none of
those on its own reading, so the tier resolves through to the delegate and
reports the delegate's availability, naming the indirection in `reason`. The
account stays an EOA either way: since Pectra, a non-empty `eth_getCode` is not
evidence of a contract, and treating it as such misclassifies ordinary accounts.

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

# Etherscan's proxy endpoint is NOT backed by an archive node: any historical
# `tag` comes back as {"error": "historical state ... is not available"}. Code
# presence at the signing block therefore has to come from an archive RPC, and
# the repo already has one configured for the simulator. Without it we fall
# back to `latest` and label the row, rather than pretending to know.
_ARCHIVE_RPC = os.environ.get("ALCHEMY_ENDPOINT_URL") or os.environ.get("MAINNET_RPC") or ""

# EIP-1967-era OpenSea proxy upgrade, and the OZ transparent-proxy variants.
# `upgradeTo(address)` / `upgradeToAndCall(address,bytes)`.
_UPGRADE_SELECTORS = ("0x3659cfe6", "0x4f1ef286")

# EIP-7702 delegation designator: exactly 23 bytes, 0xef0100 followed by the
# 20-byte delegate address. Since Pectra a non-empty eth_getCode is NO LONGER
# sufficient evidence of a contract, because an ordinary externally owned
# account that has signed a delegation returns these 23 bytes. Reading that as
# "this is a contract" is wrong twice: the account can still originate
# transactions, and the code that would actually run lives at the delegate.
_DELEGATION_PREFIX = "0xef0100"
_DELEGATION_LEN = 2 + 2 * 23      # "0x" + 23 bytes as hex


def delegation_target(raw: str) -> str | None:
    """The delegate address if `raw` is an EIP-7702 designator, else None."""
    if not isinstance(raw, str):
        return None
    r = raw.lower()
    if len(r) == _DELEGATION_LEN and r.startswith(_DELEGATION_PREFIX):
        return "0x" + r[len(_DELEGATION_PREFIX):]
    return None

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


def _code_at(addr: str, tag: str) -> str | None:
    """Raw bytecode for `addr` at `tag` from the archive RPC, or None if the
    lookup could not be made. None means unknown; it never means "no code"."""
    if not _ARCHIVE_RPC:
        return None
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getCode",
                       "params": [addr, tag]}).encode()
    req = urllib.request.Request(_ARCHIVE_RPC, data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            out = json.loads(r.read())
    except (urllib.error.URLError, ValueError, OSError):
        return None
    res = out.get("result")
    return res if isinstance(res, str) and res.startswith("0x") else None


def source_info(address: str, chain_id: int = 1, block: int | None = None) -> dict:
    """Cached code-presence + verification lookup. Returns {has_code, verified, name}.

    `block` is the block the victim signed at. Code presence is queried AT that
    block, because an address that held code at signing and self-destructed
    afterwards is indistinguishable at `latest` from one that never had code,
    and that distinction is exactly what the n/a class claims. Passing None
    falls back to `latest` and records it, so a row measured that way is
    visible rather than silently mixed in.

    Verification status has no historical equivalent: Etherscan exposes no
    "was this verified at block N" query, so `verified` remains a measurement
    of today and stays an upper bound. Only code presence is fixed here.

    The cache key includes the tag. Without that, block-specific queries would
    be served stale `latest` answers from an earlier run, which would silently
    undo the whole point of this change.

    The key is also versioned. v1 entries stored only the derived flags, so an
    address cached before EIP-7702 designators were recognised would be served
    back as `has_code: True` forever and never re-examined. v2 stores the raw
    `eth_getCode` result alongside the flags, which both fixes that and lets the
    shipped per-row output show what was actually read.
    """
    addr = (address or "").lower()
    if not addr.startswith("0x") or len(addr) != 42:
        return {"has_code": False, "verified": False, "name": "", "note": "not an address"}
    tag = hex(block) if isinstance(block, int) and block > 0 else "latest"
    key = f"v2:{chain_id}:{addr}:{tag}"
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
        if tag == "latest":
            code = _get({"chainid": str(chain_id), "module": "proxy",
                         "action": "eth_getCode", "address": addr, "tag": "latest"})
            raw = code.get("result")
        else:
            raw = _code_at(addr, tag)
        # An archive-less backend answers a historical tag with an error object
        # rather than a result. Treat that as unknown, never as "no code":
        # silently reading it as "no code" would inflate the n/a class, which is
        # the exact number this block-accurate lookup exists to establish.
        if not isinstance(raw, str) or not raw.startswith("0x"):
            return {"has_code": False, "verified": False, "name": "",
                    "note": f"code presence at {tag} unknown (no archive result)"}
        has_code = raw not in ("0x", "0x0", "")
        delegate = delegation_target(raw)
        if delegate:
            # An EOA that has signed an EIP-7702 delegation. The account holds
            # no code of its own; the delegate's code is what executes. Record
            # both, and let the caller decide which one its question is about.
            info = {"has_code": False, "verified": False, "name": "",
                    "note": "", "at": tag, "delegated_to": delegate,
                    "raw": raw}
        elif not has_code:
            info = {"has_code": False, "verified": False, "name": "",
                    "note": "", "at": tag, "raw": raw}
        else:
            res = _get({"chainid": str(chain_id), "module": "contract",
                        "action": "getsourcecode", "address": addr})
            # On a rate limit or an error the endpoint returns `result` as a
            # bare STRING ("Max rate limit reached"), not a list of records.
            # Indexing that gives a character, and asking a character for
            # .get() raises. Worse, a silent except here would record the
            # address as unverified, turning throttling into a finding. Treat
            # a malformed shape as unknown and say so.
            result = res.get("result")
            if not isinstance(result, list) or not result or not isinstance(result[0], dict):
                return {"has_code": True, "verified": False, "name": "",
                        "note": f"source lookup returned no usable record "
                                f"({res.get('message') or result!r:.60})",
                        "at": tag, "raw": raw}
            row = result[0]
            src = row.get("SourceCode") or ""
            info = {"has_code": True, "verified": bool(src),
                    "name": row.get("ContractName") or "", "note": "", "at": tag,
                    "raw": raw}
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
    """Resolve the authority object and report what a code reader would have.

    States: catch / blind / na / unknown.

    `unknown` exists because the three are not the same thing and collapsing
    them is how a measurement lies. `na` is a positive finding: we asked, and
    the address held no code at the signing block. `unknown` means we could not
    ask, because the archive lookup failed or the call cap was hit. Folding
    `unknown` into `na` would make a run with no archive RPC report "no code at
    all" for every row, which is exactly the number this tier exists to
    establish. Callers must not aggregate `unknown` into any reported rate.
    """
    obj, why = authority_object(case)
    if not obj:
        return "na", why
    # Code presence is asked at the block the victim signed at, not at latest.
    blk = getattr(case, "block", None)
    info = source_info(obj, case.chain_id, blk)
    if info.get("note"):
        # Distinguish "we could not ask" from "we asked and there was no code".
        return "unknown", info["note"]

    # Is the transaction target itself verified? If it is, but it is not the
    # authority object, that is the wrong-object gap this tier exists to expose.
    divergence = ""
    same = case.to and obj.lower() == case.to.lower()
    if not same and case.to and case.kind == "onchain":
        tgt = source_info(case.to, case.chain_id, blk)
        if tgt.get("verified"):
            divergence = (f"; the tx target {tgt['name'] or case.to[:10]} IS verified, "
                          f"but it is not the object that governs the outcome")

    # EIP-7702: the object is an EOA whose executing code lives at a delegate.
    # It is NOT a contract, so this is not a `blind`/`catch` on the account
    # itself, but a source reader does have somewhere to look. Resolve through
    # and say so, rather than either crediting the EOA with code it does not
    # have or reporting "no code" when code will in fact run.
    dele = info.get("delegated_to")
    if dele:
        d = source_info(dele, case.chain_id, blk)
        if d.get("note"):
            return "unknown", (f"authority object {obj[:10]} ({why}) is an EOA with an "
                               f"EIP-7702 delegation to {dele[:10]}, whose code could not "
                               f"be resolved: {d['note']}")
        if d.get("verified"):
            return "catch", (f"authority object {obj[:10]} ({why}) is an EOA with an "
                             f"EIP-7702 delegation to {d['name'] or dele[:10]}, which has "
                             f"verified source{divergence}")
        if d.get("has_code"):
            return "blind", (f"authority object {obj[:10]} ({why}) is an EOA with an "
                             f"EIP-7702 delegation to {dele[:10]}, which has no verified "
                             f"source: a reader gets bytecode only{divergence}")
        return "na", (f"authority object {obj[:10]} ({why}) is an EOA with an EIP-7702 "
                      f"delegation to {dele[:10]}, which itself holds no code{divergence}")

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


# --------------------------------------------------------------------------
# Per-row emitter.
#
# The paper reports aggregate counts (catch/blind/na, and the divergence) and
# asserts that `unknown` is zero. Neither claim is checkable from an aggregate,
# so this writes the row-level record the aggregates are computed from: for
# each case, the authority object that was resolved and why, the block the
# query was made at, the RAW eth_getCode result, and the resulting state.
#
#     python3 -m demo.source_tier            # -> results/source_tier_rows.json
#
# Re-running with the shipped cache costs zero API calls and zero network.
# --------------------------------------------------------------------------

_RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "results")

# Excluded from the paper's analysis set: its upgradeTo argument is the
# sender's own EOA, so it is probably a proxy owner disabling their own proxy
# rather than a drain. Emitted here anyway, flagged, so the exclusion can be
# checked instead of taken on trust.
EXCLUDED = {"ptx-J-01": "probably mislabelled: upgradeTo argument is the sender's own EOA"}


def emit_rows(cases) -> dict:
    rows = []
    for case in cases:
        obj, why = authority_object(case)
        blk = getattr(case, "block", None)
        info = source_info(obj, case.chain_id, blk) if obj else {}
        state, reason = verdict(case)
        rows.append({
            "id": case.id,
            "class": case.label,
            "signing_block": blk,
            "tx_target": (case.to or "").lower(),
            "authority_object": obj.lower(),
            "resolution": why,
            "code_at_signing_block": info.get("raw"),
            "queried_at": info.get("at"),
            "delegated_to": info.get("delegated_to"),
            "verified_source": info.get("verified"),
            "contract_name": info.get("name") or None,
            "state": state,
            "target_verified_but_not_authority":
                "IS verified, but it is not the object" in reason,
            "excluded_from_analysis_set": EXCLUDED.get(case.id),
            "reason": reason,
        })
    counted = [r for r in rows if not r["excluded_from_analysis_set"]]
    tally = {s: sum(1 for r in counted if r["state"] == s)
             for s in ("catch", "blind", "na", "unknown")}
    return {
        "note": ("Per-row record behind the Section 4 counts. `code_at_signing_block` "
                 "is the raw eth_getCode result at `queried_at`, from an archive RPC. "
                 "Rows with `excluded_from_analysis_set` set are reported but not "
                 "counted in `totals`."),
        "analysis_set_rows": len(counted),
        "corpus_malicious_rows": len(rows),
        "totals": tally,
        "divergence": sum(1 for r in counted if r["target_verified_but_not_authority"]),
        "distinct_authority_objects": len({r["authority_object"] for r in counted}),
        "rows": rows,
    }


def main() -> None:
    from . import corpus
    if not available():
        raise SystemExit("Set ETHERSCAN_API_KEY (the shipped cache covers the "
                         "reported run, but the key gates the lens).")
    cases = [c for c in corpus.real_cases() if c.malicious]
    out = emit_rows(cases)
    os.makedirs(_RESULTS_DIR, exist_ok=True)
    path = os.path.join(_RESULTS_DIR, "source_tier_rows.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=1)
    t = out["totals"]
    print(f"{out['analysis_set_rows']} rows in the analysis set "
          f"({out['corpus_malicious_rows']} malicious in the corpus)")
    print(f"  catch {t['catch']}  blind {t['blind']}  na {t['na']}  unknown {t['unknown']}")
    print(f"  tx target verified but not the authority object: {out['divergence']}")
    print(f"  distinct authority objects: {out['distinct_authority_objects']}")
    print(f"wrote {path}")
    print(summary())


if __name__ == "__main__":
    main()
