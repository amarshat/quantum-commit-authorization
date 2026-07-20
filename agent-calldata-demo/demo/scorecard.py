"""Run the attack suite past every defense arm and emit the scorecard.

For each attack we show the three things side by side that make the point:
the stated intent (English), the actual effect (decoded from calldata or the
signed message), and the on-chain result (value actually moved). Then the arm
matrix: which layer, if any, vetoed it.

    python3 -m demo.scorecard
"""

from __future__ import annotations

import json
import os

from . import reviewers
from .attacks import ATTACKS
from .chain import Chain

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")

MARK = {"VETO": "VETO  (caught)", "MISS": "MISS  (waved through)", "BLIND": "BLIND (nothing to inspect)"}
CELL = {"VETO": "VETO", "MISS": "miss", "BLIND": "blind"}


def _fmt_usdc(x: int) -> str:
    return f"{x / 1e6:.2f} USDC"


def run() -> list[dict]:
    chain = Chain()
    chain.require_anvil()
    rows: list[dict] = []

    for atk in ATTACKS:
        # isolate each attack on a freshly deployed token with a funded agent
        chain.extra_allowlist = set()
        chain.deploy_usdc()
        chain.mint("agent", 1_000_000)

        action = atk.build(chain)
        target, amount = reviewers._effect(action, chain)
        verdicts = reviewers.review(atk, action, chain)

        before, after = atk.execute(chain, action)
        drained = before - after
        stopped = any(v.caught for v in verdicts)

        rows.append({
            "id": atk.id,
            "title": atk.title,
            "kind": atk.kind,
            "stated_intent": atk.stated_intent,
            "true_effect": atk.true_effect,
            "authorized": action.calldata if action.kind == "onchain"
                          else f"(off-chain signature over {action.sig}; no transaction to simulate)",
            "decoded_target": target,
            "decoded_amount": (
                "FULL ACCOUNT" if action.sig.startswith("EIP-7702")
                else "UNLIMITED" if amount >= 2**255 else str(amount)
            ),
            "drained": drained,
            "stopped": stopped,
            "verdicts": [{"arm": v.arm, "decision": v.decision, "reason": v.reason} for v in verdicts],
        })

    return rows


def print_report(rows: list[dict]) -> None:
    for r in rows:
        print("\n" + "=" * 78)
        print(f"[{r['id']}] {r['title']}")
        print("-" * 78)
        print(f"  stated intent : {r['stated_intent']}")
        print(f"  true effect   : {r['true_effect']}")
        print(f"  authorized    : {r['authorized']}")
        print(f"  decoded       : target={r['decoded_target']}  amount={r['decoded_amount']}")
        print(f"  on-chain result: drained {_fmt_usdc(r['drained'])} from the agent wallet")
        print("  defense arms:")
        for v in r["verdicts"]:
            print(f"    - {v['arm']:<9}: {MARK[v['decision']]:<28} {v['reason']}")
        print(f"  >> {'STOPPED by a defense arm' if r['stopped'] else 'NOT STOPPED: every arm missed or was blind'}")

    print("\n" + "=" * 78)
    print("SCORECARD (rows = attacks, columns = defense arms)")
    print("=" * 78)
    arms = [v["arm"] for v in rows[0]["verdicts"]]
    header = f"{'attack':<26} " + " ".join(f"{a:<7}" for a in arms) + "  drained   stopped"
    print(header)
    print("-" * len(header))
    for r in rows:
        cells = " ".join(f"{CELL[v['decision']]:<7}" for v in r["verdicts"])
        print(f"{r['id']:<26} {cells}  {_fmt_usdc(r['drained']):<9} {'yes' if r['stopped'] else 'NO'}")
    print("\nOnly VETO stops the drain. `blind` = the arm has no transaction to inspect")
    print("(off-chain signature). The false floor, reached by five routes:")
    print("  D = off-chain permit (simulation blind) to an allowlisted target, unlimited")
    print("  E = on-chain call to an allowlisted contract, simulated benign then armed after the dry-run")
    print("  F = off-chain signed order to the allowlisted exchange; normal bounded amount,")
    print("      recipient routes to the attacker (defeats an amount-aware policy too)")
    print("  G = off-chain EIP-7702 authorization to an allowlisted helper: not one")
    print("      allowance but the whole account, and no amount for any policy to catch")
    print("  H = on-chain max approval to the allowlisted Permit2 contract (the one")
    print("      every policy must allowlist); the balance is then drained by signature")
    print("All reach an allowlisted-looking target, and nothing stops any of them.\n")


def write_files(rows: list[dict]) -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "scorecard.json"), "w") as f:
        json.dump(rows, f, indent=2)

    arms = [v["arm"] for v in rows[0]["verdicts"]]
    lines = ["# Defense scorecard", "",
             "| attack | " + " | ".join(arms) + " | drained | stopped |",
             "|" + "---|" * (len(arms) + 3)]
    for r in rows:
        cells = " | ".join(CELL[v["decision"]] for v in r["verdicts"])
        lines.append(f"| {r['id']} | {cells} | {_fmt_usdc(r['drained'])} | {'yes' if r['stopped'] else '**no**'} |")
    lines += ["", "`blind` = the arm has no transaction to inspect (off-chain signature).",
              "Rows D, E, F and G all drain to an allowlisted-looking target: D via "
              "off-chain-signature blindness (unlimited permit), E via on-chain "
              "simulation evasion (armed after the dry-run), F via an off-chain signed "
              "order whose bounded amount and allowlisted counterparty pass every policy "
              "while the recipient field routes to the attacker, G via an EIP-7702 "
              "authorization that signs the whole account over to an allowlisted helper, "
              "and H via the on-chain max approval to the always-allowlisted Permit2 "
              "contract, drained afterwards by signature."]
    with open(os.path.join(OUT_DIR, "scorecard.md"), "w") as f:
        f.write("\n".join(lines) + "\n")


def main() -> None:
    rows = run()
    print_report(rows)
    write_files(rows)
    print(f"wrote {os.path.join(OUT_DIR, 'scorecard.json')} and scorecard.md")


if __name__ == "__main__":
    main()
