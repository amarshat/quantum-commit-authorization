"""Rabby's pre-sign security rules, ported and evaluated against ground truth.

HONESTY / TIER. This is NOT the hosted Rabby engine. Rabby's shipped decision runs
its rule engine (`@rabby-wallet/rabby-security-engine`) over a context produced by
DeBank's closed pre-execution / OpenAPI backend (contract verification, popularity,
address history). That backend is not available to an independent researcher, so
"run real Rabby" is not reproducible solo. What is reproducible is Rabby's
published rule LOGIC: the categorical alerts it raises on a signing request. This
module ports those documented rules and evaluates them against context we know
from ground truth (contract-vs-EOA, allowlisted-or-not, unlimited-amount,
signed-recipient). Tier = "open-rules-port".

What is faithfully reproduced: the rule triggers below. What is NOT: the
DeBank-sourced signals (is the contract verified / popular, has the address a
transaction history) and their exact thresholds. Rules that depend only on those
are therefore not fired here, which can only make this port MORE conservative
(fewer catches) than shipped Rabby, never less. That direction is stated in the
paper so the port cannot flatter itself.

Rule sources: RabbyHub/Rabby security engine + action parser (rabby-action), and
the Least Authority Rabby extension audit (2025), which documents partial EIP-7702
delegation support. Each verdict names the rule it fired.

verdict(case) -> (state, reason), state in {"catch","miss","blind","na"}:
  catch = a rule flags this signing request; miss = Rabby's rules see it but do
  not flag it; blind = Rabby structurally cannot see the artifact (none here, it
  renders both transactions and typed data); na = not a case Rabby handles.
"""

from __future__ import annotations

NAME = "Rabby (open-rules port)"
TIER = "open-rules-port"

APPROVAL_TYPES = ("approve", "permit", "permit2_approve")


def available() -> bool:
    # Pure logic port, no key or network: always available.
    return True


def verdict(case) -> tuple[str, str]:
    at = case.action_type

    # A rule engine needs decoded fields. If the artifact's selector was not
    # decoded (no counterparty and no recipient), Rabby's rules have nothing to
    # evaluate. A hosted simulator, by contrast, still runs the raw calldata.
    if at != "delegation" and not case.counterparty and not case.recipient:
        return "na", "action could not be decoded (unsupported selector); a rule engine has no fields to evaluate"

    # --- approvals: approve / EIP-2612 permit / Permit2 approve --------------
    if at in APPROVAL_TYPES:
        # Rabby recognizes Permit2 as an approval router: a max approve TO Permit2
        # is rendered as the standard setup, not flagged as a drain. The risk is a
        # later Permit2 signature, a separate signing request.
        if at == "permit2_approve" and case.counterparty_known:
            return "miss", "Permit2 is a recognized approval contract; the max approve to it is not itself flagged"
        # Rabby danger: approving/permitting an EOA (a spender that is not a contract).
        if not case.counterparty_is_contract:
            return "catch", "rule: approval to an EOA spender (high risk)"
        # Rabby warning: unlimited allowance.
        if case.unlimited:
            return "catch", "rule: unlimited approval amount"
        return "miss", "bounded approval to a contract spender; no rule fires (verification/popularity signals are DeBank-hosted, not reproduced)"

    # --- direct transfer ----------------------------------------------------
    if at == "transfer":
        # Rabby warns on sending to an address the user has no relationship with.
        if not case.recipient_known:
            return "catch", "rule: transfer to an unfamiliar / non-allowlisted address"
        return "miss", "transfer to a known address"

    # --- EIP-712 order (Seaport / intent signing) ---------------------------
    if at == "order":
        # Rabby's action parser renders the order's receiver; a receiver that is
        # not the signer and not known is flagged.
        if case.recipient and case.recipient.lower() != case.frm.lower() and not case.recipient_known:
            return "catch", "rule: signed order routes funds to a party that is neither the signer nor known"
        return "miss", "order recipient is the signer or a known party"

    # --- EIP-7702 account delegation ----------------------------------------
    if at == "delegation":
        # Rabby raises a delegation/set-code alert on any 7702 authorization
        # (partial support, per the audit). It cannot resolve what the delegate's
        # code does internally, only that the account is being delegated.
        return "catch", "rule: EIP-7702 authorization delegates account control (categorical alert; the delegate's internal behavior is not resolved)"

    # --- opaque contract call (honeypot / TOCTOU) ---------------------------
    if at == "call":
        # Rabby's danger signal here comes from DeBank pre-execution, which we do
        # not have; the calldata itself is a benign no-op at inspection and the
        # drain is armed only after any check. So the ported rules do not fire.
        return "miss", "the reviewed call is benign at inspection; the drain is armed after the check (pre-exec simulation is DeBank-hosted, not reproduced)"

    return "na", f"no ported rule for action_type={at}"
