"""Thin stdlib-only wrappers over Foundry's `cast` / `forge`.

Everything the demo does on-chain goes through these helpers, so the rest of the
code never shells out directly. No web3/eth-account dependency: if you have
Foundry installed you can run this repo.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass


class CastError(RuntimeError):
    pass


def _run(args: list[str], cwd: str | None = None) -> str:
    proc = subprocess.run(
        args, capture_output=True, text=True, cwd=cwd
    )
    if proc.returncode != 0:
        raise CastError(
            f"command failed: {' '.join(args)}\n"
            f"stdout: {proc.stdout.strip()}\n"
            f"stderr: {proc.stderr.strip()}"
        )
    return proc.stdout.strip()


# --- read-side ---------------------------------------------------------------

def block_number(rpc: str) -> int:
    return int(_run(["cast", "block-number", "--rpc-url", rpc]))


def is_up(rpc: str) -> bool:
    try:
        block_number(rpc)
        return True
    except CastError:
        return False


def calldata(sig: str, *args: str) -> str:
    """ABI-encode a call: the bytes a tool would hand the wallet to sign."""
    return _run(["cast", "calldata", sig, *[str(a) for a in args]])


def decode_calldata(sig: str, data: str) -> list[str]:
    """Decode calldata to its arguments: what clear-signing / ERC-7730 renders."""
    out = _run(["cast", "decode-calldata", sig, data])
    return [line.strip() for line in out.splitlines() if line.strip()]


def call(rpc: str, to: str, sig: str, *args: str) -> str:
    return _run(["cast", "call", to, sig, *[str(a) for a in args], "--rpc-url", rpc])


def call_uint(rpc: str, to: str, sig: str, *args: str) -> int:
    # cast may append a human annotation like "123 [1.2e2]"; take the first token.
    return int(call(rpc, to, sig, *args).split()[0])


# --- write-side --------------------------------------------------------------

@dataclass
class Receipt:
    status: int
    block: int
    tx_hash: str


def send(rpc: str, key: str, to: str, data: str) -> Receipt:
    out = _run(
        ["cast", "send", to, data, "--rpc-url", rpc, "--private-key", key, "--json"]
    )
    d = json.loads(out)
    return Receipt(
        status=int(d["status"], 16),
        block=int(d["blockNumber"], 16),
        tx_hash=d["transactionHash"],
    )


def send_sig(rpc: str, key: str, to: str, sig: str, *args: str) -> Receipt:
    out = _run(
        ["cast", "send", to, sig, *[str(a) for a in args],
         "--rpc-url", rpc, "--private-key", key, "--json"]
    )
    d = json.loads(out)
    return Receipt(
        status=int(d["status"], 16),
        block=int(d["blockNumber"], 16),
        tx_hash=d["transactionHash"],
    )


def deploy(rpc: str, key: str, contract: str, cwd: str) -> str:
    """forge create -> deployed address. `contract` is e.g. src/MockUSDC.sol:MockUSDC."""
    out = _run(
        ["forge", "create", contract, "--rpc-url", rpc,
         "--private-key", key, "--broadcast", "--json"],
        cwd=cwd,
    )
    return json.loads(out)["deployedTo"]


# --- hashing / signing primitives (for EIP-712 / EIP-2612 permit) ------------

def abi_encode(sig: str, *args: str) -> str:
    return _run(["cast", "abi-encode", sig, *[str(a) for a in args]])


def keccak(data: str) -> str:
    return _run(["cast", "keccak", data])


def sign_hash(key: str, digest: str) -> tuple[int, str, str]:
    """Sign a raw 32-byte digest (no EIP-191 prefix). Returns (v, r, s)."""
    sig = _run(["cast", "wallet", "sign", "--no-hash", digest, "--private-key", key])
    body = sig[2:] if sig.startswith("0x") else sig
    r = "0x" + body[0:64]
    s = "0x" + body[64:128]
    v = int(body[128:130], 16)
    return v, r, s


# --- fork simulation (snapshot / revert) -------------------------------------

def rpc(rpc_url: str, method: str, *params: str) -> str:
    args = ["cast", "rpc", method, *[str(p) for p in params], "--rpc-url", rpc_url]
    return _run(args).strip().strip('"')


def snapshot(rpc_url: str) -> str:
    return rpc(rpc_url, "evm_snapshot")


def revert(rpc_url: str, snap_id: str) -> None:
    rpc(rpc_url, "evm_revert", snap_id)
