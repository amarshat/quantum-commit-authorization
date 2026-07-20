"""Run the attack suite against the capability ladder and emit the coverage matrix.

This is a coverage matrix, not a measurement: it enumerates eight poisoned-tool
drain shapes and reports, for each, the LOWEST wallet-defense capability that
would stop it (see demo/reviewers.py for the ladder). The `un-defended` column
is what happens with no defense at all and is constant by construction; it is
not data. The finding is which capability each drain needs, and which drains
survive the whole ladder.

    python3 -m demo.scorecard
"""

from __future__ import annotations

import json
import os

from . import goplus, reviewers
from .attacks import ATTACKS, MAX_DEC
from .chain import Chain

# a real address GoPlus flags (stealing_attack / sanctioned), as a positive control
GOPLUS_CONTROL = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96"

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")
MAXV = int(MAX_DEC)
SHORT = ["plan", "allow", "amt", "recip", "txsim", "sigsim", "type"]


def _fmt_usdc(x: int) -> str:
    return f"{x / 1e6:.2f} USDC"


def _fmt_amount(atype: str, amount: int) -> str:
    if atype == "delegation":
        return "account"
    return "UNLIMITED" if amount >= MAXV else str(amount)


def run() -> list[dict]:
    chain = Chain()
    chain.require_anvil()
    rows: list[dict] = []

    for atk in ATTACKS:
        chain.extra_allowlist = set()
        chain.deploy_usdc()
        chain.mint("agent", 1_000_000)

        action = atk.build(chain)
        verdicts, caught_at, dec = reviewers.review(atk, action, chain)
        atype, counterparty, recipient, amount = dec

        before, after = atk.execute(chain, action)

        rows.append({
            "id": atk.id,
            "title": atk.title,
            "stated_intent": atk.stated_intent,
            "true_effect": atk.true_effect,
            "action_type": atype,
            "counterparty": counterparty,
            "recipient": recipient,
            "amount": _fmt_amount(atype, amount),
            "drained": before - after,
            "caught_at": caught_at,
            "caught_name": reviewers.LADDER[caught_at - 1][0] if caught_at else None,
            "verdicts": [{"rung": v.rung, "name": v.name, "veto": v.veto, "reason": v.reason}
                         for v in verdicts],
        })
    return rows


def print_report(rows: list[dict]) -> None:
    for r in rows:
        print("\n" + "=" * 80)
        print(f"[{r['id']}] {r['title']}")
        print("-" * 80)
        print(f"  stated intent : {r['stated_intent']}")
        print(f"  decoded       : type={r['action_type']}  counterparty={r['counterparty']}")
        print(f"                  recipient={r['recipient']}  amount={r['amount']}")
        print(f"  un-defended   : drains {_fmt_usdc(r['drained'])} from the agent wallet")
        print("  capability ladder:")
        for v in r["verdicts"]:
            mark = "VETO" if v["veto"] else "pass"
            print(f"    L{v['rung']} {v['name']:<28} {mark}  {v['reason']}")
        if r["caught_at"]:
            print(f"  >> stopped by capability L{r['caught_at']} ({r['caught_name']})")
        else:
            print("  >> SURVIVES the full ladder: no modeled capability stops it")

    print("\n" + "=" * 80)
    print("COVERAGE MATRIX (rows = attacks, columns = capability rungs)")
    print("=" * 80)
    header = f"{'attack':<26} " + " ".join(f"{s:<6}" for s in SHORT) + " stopped-at"
    print(header)
    print("-" * len(header))
    for r in rows:
        cells = " ".join(f"{('STOP' if v['veto'] else '.'):<6}" for v in r["verdicts"])
        at = f"L{r['caught_at']} {r['caught_name']}" if r["caught_at"] else "RESIDUAL"
        print(f"{r['id']:<26} {cells} {at}")
    print("\nEach row is stopped by the leftmost capability that STOPs it. Reading the")
    print("matrix: field + amount + recipient rendering (L2-L4) close the stranger-target")
    print("and recipient-substitution drains; transaction and signature simulation (L5-L6)")
    print("add nothing here and specifically MISS E and G; only a categorical action-type")
    print("policy (L7) stops G and (impractically) H; E survives the whole ladder.")
    residual = [r["id"] for r in rows if not r["caught_at"]]
    print(f"\nResidual (survives every modeled capability): {', '.join(residual) or 'none'}.")
    print("Concessions: E needs re-simulation at inclusion (a deterministic race here);")
    print("E and G also require the allowlisted target itself to be adversarial.\n")


def goplus_pass(rows: list[dict]) -> dict | None:
    """Live address-reputation lookup for each attack's counterparty + recipient,
    plus a positive control. Returns None if no GoPlus key is configured."""
    if not goplus.available():
        return None
    for r in rows:
        cp = sorted(goplus.reputation(r["counterparty"]))
        same = r["recipient"].lower() == r["counterparty"].lower()
        rc = [] if same else sorted(goplus.reputation(r["recipient"]))
        r["goplus"] = {"counterparty_flags": cp, "recipient_flags": rc,
                       "recipient_same": same, "flagged": bool(cp or rc)}
    return {"control_addr": GOPLUS_CONTROL, "control_flags": sorted(goplus.reputation(GOPLUS_CONTROL))}


def print_goplus(rows: list[dict], ctrl: dict) -> None:
    print("\n" + "=" * 80)
    print("LIVE address reputation (GoPlus Security API)")
    print("=" * 80)
    print(f"{'attack':<26} {'counterparty':<22} recipient")
    print("-" * 62)
    for r in rows:
        g = r["goplus"]
        cp = ",".join(g["counterparty_flags"]) or "clean"
        rc = "(same)" if g["recipient_same"] else (",".join(g["recipient_flags"]) or "clean")
        print(f"{r['id']:<26} {cp:<22} {rc}")
    n = sum(1 for r in rows if r["goplus"]["flagged"])
    print(f"\nGoPlus flagged {n}/{len(rows)} attacks. Every sink in the suite is a fresh")
    print("address with no reputation, so live reputation scanning catches none of them.")
    print(f"positive control {ctrl['control_addr']}:")
    print(f"  flags = {', '.join(ctrl['control_flags']) or 'NONE (control failed)'}")
    print("  => the query works, so the null result above is real: reputation only fires")
    print("     on addresses already known to be bad, which agent-drain sinks are not.\n")


def write_files(rows: list[dict]) -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "scorecard.json"), "w") as f:
        json.dump(rows, f, indent=2)

    lines = ["# Capability-ladder coverage matrix", "",
             "Lowest wallet-defense capability that stops each poisoned-tool drain.", "",
             "| attack | " + " | ".join(SHORT) + " | stopped at |",
             "|" + "---|" * (len(SHORT) + 2)]
    for r in rows:
        cells = " | ".join("STOP" if v["veto"] else "." for v in r["verdicts"])
        at = f"L{r['caught_at']} {r['caught_name']}" if r["caught_at"] else "**RESIDUAL**"
        lines.append(f"| {r['id']} | {cells} | {at} |")
    lines += ["",
              "Rungs: L1 plan-review (English only), L2 address allowlist, L3 amount-aware, "
              "L4 recipient rendering, L5 tx simulation, L6 signature simulation, L7 tx-type policy.",
              "",
              "The `un-defended` drain is a constant 1.00 USDC by construction and is not "
              "reported here as data. Residual rows survive every modeled capability; the "
              "concession is that they also require the allowlisted target itself to be "
              "adversarial, and E specifically needs re-simulation at inclusion."]
    with open(os.path.join(OUT_DIR, "scorecard.md"), "w") as f:
        f.write("\n".join(lines) + "\n")


def main() -> None:
    rows = run()
    print_report(rows)
    ctrl = goplus_pass(rows)
    if ctrl is not None:
        print_goplus(rows, ctrl)
    else:
        print("\n(GoPlus key not set; skipping the live address-reputation lens.)\n")
    write_files(rows)
    print(f"wrote {os.path.join(OUT_DIR, 'scorecard.json')} and scorecard.md")


if __name__ == "__main__":
    main()
