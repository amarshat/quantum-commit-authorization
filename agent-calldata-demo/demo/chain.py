"""Chain fixture: named accounts, the value token, and EIP-2612 permit signing.

Uses anvil's deterministic dev accounts so runs are reproducible. Assumes an
anvil node is already listening on `rpc` (run.sh boots it); reuses whatever is
there so you can also point this at a long-lived local node during development.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from . import cast

# anvil's standard dev accounts (mnemonic "test test ... junk"). Public keys.
ACCOUNTS = {
    "agent":    ("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
                 "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"),
    "router":   ("0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
                 "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"),
    "merchant": ("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
                 "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"),
    "attacker": ("0x90F79bf6EB2c4f870365E785982E1f101E93b906",
                 "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"),
}

# keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
PERMIT_TYPEHASH = "0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9"
MAX_UINT = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"


@dataclass
class Chain:
    rpc: str = "http://127.0.0.1:8545"
    cwd: str = field(default_factory=lambda: os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    usdc: str = ""
    # extra addresses the policy treats as allowlisted (e.g. a deployed router
    # contract the agent legitimately uses); reset between attacks.
    extra_allowlist: set[str] = field(default_factory=set)

    def addr(self, role: str) -> str:
        return ACCOUNTS[role][0]

    def key(self, role: str) -> str:
        return ACCOUNTS[role][1]

    def allowlist_addrs(self, roles: list[str]) -> set[str]:
        return {self.addr(r).lower() for r in roles} | {a.lower() for a in self.extra_allowlist}

    # --- setup ---------------------------------------------------------------

    def require_anvil(self) -> None:
        if not cast.is_up(self.rpc):
            raise RuntimeError(
                f"no anvil node at {self.rpc}. Start one: `anvil --silent` (run.sh does this)."
            )

    def deploy_usdc(self) -> str:
        self.usdc = cast.deploy(self.rpc, self.key("agent"), "src/MockUSDC.sol:MockUSDC", self.cwd)
        return self.usdc

    def mint(self, role: str, amount: int) -> None:
        cast.send_sig(self.rpc, self.key("agent"), self.usdc,
                      "mint(address,uint256)", self.addr(role), str(amount))

    def deploy_honeypot(self, attacker_role: str) -> str:
        return cast.deploy(self.rpc, self.key("agent"), "src/Honeypot.sol:Honeypot",
                           self.cwd, self.usdc, self.addr(attacker_role))

    def deploy_settlement(self) -> str:
        return cast.deploy(self.rpc, self.key("agent"), "src/Settlement.sol:Settlement",
                           self.cwd, self.usdc)

    def deploy_aahelper(self) -> str:
        return cast.deploy(self.rpc, self.key("agent"), "src/AAHelper.sol:AAHelper", self.cwd)

    def deploy_permit2(self) -> str:
        return cast.deploy(self.rpc, self.key("agent"), "src/Permit2.sol:Permit2", self.cwd)

    # --- Permit2 SignatureTransfer: the universal-approval rail ---------------

    def sign_permit2(self, permit2: str, owner: str, spender_addr: str, token: str,
                     amount: str, nonce: int, deadline: int) -> tuple[int, str, str]:
        """Owner signs a Permit2 permitTransferFrom message. As with any
        signature, nothing is broadcast when the agent signs it, so there is no
        transaction to simulate at signing time."""
        tp_th = cast.call(self.rpc, permit2, "TOKEN_PERMISSIONS_TYPEHASH()(bytes32)")
        pt_th = cast.call(self.rpc, permit2, "PERMIT_TRANSFER_TYPEHASH()(bytes32)")
        ds = cast.call(self.rpc, permit2, "DOMAIN_SEPARATOR()(bytes32)")
        token_perm = cast.keccak(cast.abi_encode(
            "f(bytes32,address,uint256)", tp_th, token, amount))
        struct_hash = cast.keccak(cast.abi_encode(
            "f(bytes32,bytes32,address,uint256,uint256)",
            pt_th, token_perm, spender_addr, str(nonce), str(deadline)))
        digest = cast.keccak("0x1901" + ds[2:] + struct_hash[2:])
        return cast.sign_hash(self.key(owner), digest)

    def permit_transfer_from(self, filler: str, permit2: str, token: str, amount: str,
                             nonce: int, deadline: int, to_addr: str, owner: str,
                             v: int, r: str, s: str) -> cast.Receipt:
        return cast.send_sig(
            self.rpc, self.key(filler), permit2,
            "permitTransferFrom(address,uint256,uint256,uint256,address,address,uint8,bytes32,bytes32)",
            token, amount, str(nonce), str(deadline), to_addr, self.addr(owner), str(v), r, s,
        )

    # --- EIP-7702 account delegation -----------------------------------------

    def sign_delegation(self, authority: str, delegate: str) -> str:
        """Authority signs an EIP-7702 authorization delegating its whole account
        to `delegate`. The signature is the entire artifact; nothing is broadcast
        when the agent signs, so there is no transaction to simulate."""
        n = cast.nonce(self.rpc, self.addr(authority))
        return cast.sign_auth(self.rpc, self.key(authority), delegate, n)

    def submit_delegation(self, submitter: str, signed_auth: str) -> cast.Receipt:
        # a neutral `to`; the authorization, not the call, sets the delegation
        burn = "0x000000000000000000000000000000000000dEaD"
        return cast.send_auth(self.rpc, self.key(submitter), burn, signed_auth)

    def approve_contract(self, owner_role: str, spender_addr: str, amount: str) -> None:
        cast.send_sig(self.rpc, self.key(owner_role), self.usdc,
                      "approve(address,uint256)", spender_addr, amount)

    # --- reads ---------------------------------------------------------------

    def balance(self, role: str) -> int:
        return cast.call_uint(self.rpc, self.usdc, "balanceOf(address)(uint256)", self.addr(role))

    def allowance(self, owner: str, spender: str) -> int:
        return cast.call_uint(self.rpc, self.usdc, "allowance(address,address)(uint256)",
                              self.addr(owner), self.addr(spender))

    def nonce(self, owner: str) -> int:
        return cast.call_uint(self.rpc, self.usdc, "nonces(address)(uint256)", self.addr(owner))

    def domain_separator(self) -> str:
        return cast.call(self.rpc, self.usdc, "DOMAIN_SEPARATOR()(bytes32)")

    # --- EIP-2612 permit: the off-chain-signature surface --------------------

    def sign_permit(self, owner: str, spender: str, value: str, deadline: int) -> tuple[int, str, str]:
        """Owner signs an approval as a message. No transaction is broadcast here:
        the returned (v, r, s) is the entire artifact, and there is nothing for a
        transaction simulator to inspect at signing time."""
        nonce = self.nonce(owner)
        struct_hash = cast.keccak(cast.abi_encode(
            "f(bytes32,address,address,uint256,uint256,uint256)",
            PERMIT_TYPEHASH, self.addr(owner), self.addr(spender), value, str(nonce), str(deadline),
        ))
        ds = self.domain_separator()
        digest = cast.keccak("0x1901" + ds[2:] + struct_hash[2:])
        return cast.sign_hash(self.key(owner), digest)

    def submit_permit(self, submitter: str, owner: str, spender: str, value: str,
                      deadline: int, v: int, r: str, s: str) -> cast.Receipt:
        """Anyone holding the signature can submit it. In the attack, the attacker
        submits the permit the agent signed, then pulls the funds."""
        return cast.send_sig(
            self.rpc, self.key(submitter), self.usdc,
            "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
            self.addr(owner), self.addr(spender), value, str(deadline), str(v), r, s,
        )

    # --- EIP-712 order signing: the intent/order-signing surface --------------

    def sign_order(self, settlement: str, maker: str, taker_addr: str, token: str,
                   amount: str, deadline: int) -> tuple[int, str, str]:
        """Maker signs an EIP-712 trade order. As with a permit, the artifact is
        just a signature: nothing is broadcast, so there is no transaction to
        simulate at signing time."""
        typehash = cast.call(self.rpc, settlement, "ORDER_TYPEHASH()(bytes32)")
        nonce = cast.call_uint(self.rpc, settlement, "nonces(address)(uint256)", self.addr(maker))
        struct_hash = cast.keccak(cast.abi_encode(
            "f(bytes32,address,address,address,uint256,uint256,uint256)",
            typehash, self.addr(maker), taker_addr, token, amount, str(nonce), str(deadline),
        ))
        ds = cast.call(self.rpc, settlement, "DOMAIN_SEPARATOR()(bytes32)")
        digest = cast.keccak("0x1901" + ds[2:] + struct_hash[2:])
        return cast.sign_hash(self.key(maker), digest)

    def fill_order(self, filler: str, settlement: str, maker: str, taker_addr: str,
                   token: str, amount: str, deadline: int, v: int, r: str, s: str) -> cast.Receipt:
        return cast.send_sig(
            self.rpc, self.key(filler), settlement,
            "fill(address,address,address,uint256,uint256,uint8,bytes32,bytes32)",
            self.addr(maker), taker_addr, token, amount, str(deadline), str(v), r, s,
        )
