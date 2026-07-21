"""Quantify the E residual: the TOCTOU race an agent wallet loses.

E is the only drain that survives the capability ladder, and its survival is
conditional: the attacker must land the arming transaction between the wallet's
simulation and the victim transaction's inclusion. This module models and
simulates how often that succeeds, so the residual is a number rather than a
hand-wave.

Two defense regimes:

  R0  no re-simulation at inclusion. The wallet checked once, at signing time,
      against unarmed state. The victim tx executes later regardless, so the
      attacker only needs arm() included at any point before the victim tx is
      mined. With a public pending tx to watch, that window is ample: success
      ~= 1 per attempt.

  R1  re-simulation at inclusion (the natural defense). The wallet re-simulates
      the victim tx against the state just before it is mined. To still win, the
      attacker must place arm() immediately before the victim tx with no
      re-check in between: a same-block ordering the attacker controls only with
      probability beta (its block-ordering-win rate: a builder or priority-fee
      searcher targeting the victim has beta -> 1; a public-mempool attacker has
      a small per-attempt beta).

The agent-specific term is K, the number of times the agent signs a
vulnerable action. A human signs occasionally; an autonomous agent signs at
machine speed across many actions, and the attacker may target each one. So the
per-attempt probability beta compounds:

  P_success(R1) = 1 - (1 - beta)^K

Even a weak attacker (small beta) wins with near-certainty over an active
agent's many actions. This file corroborates that closed form with a Monte
Carlo and emits the curve used in the paper.
"""

from __future__ import annotations

import os

# deterministic LCG so results reproduce without importing random (which the
# workflow/runtime may restrict); this is a plain Park-Miller generator.
class _Rng:
    def __init__(self, seed: int = 1):
        self.s = seed % 2147483647 or 1

    def next(self) -> float:
        self.s = (self.s * 16807) % 2147483647
        return self.s / 2147483647.0


def analytic(beta: float, K: int) -> float:
    """P(attacker wins at least one of K attempts) under re-simulation (R1)."""
    return 1.0 - (1.0 - beta) ** K


def simulate(beta: float, K: int, trials: int = 20000, seed: int = 1) -> float:
    """Monte-Carlo the same quantity: over `trials` independent agents, each
    signing K vulnerable actions, fraction for which the attacker wins at least
    one same-block ordering race (each race won independently with prob beta)."""
    rng = _Rng(seed)
    drained = 0
    for _ in range(trials):
        won = False
        for _ in range(K):
            if rng.next() < beta:
                won = True
                break
        if won:
            drained += 1
    return drained / trials


def table() -> list[dict]:
    betas = [0.01, 0.05, 0.20, 0.50]
    ks = [1, 2, 5, 10, 25, 50, 100]
    rows = []
    for beta in betas:
        for K in ks:
            rows.append({
                "beta": beta, "K": K,
                "analytic": analytic(beta, K),
                "monte_carlo": simulate(beta, K),
            })
    return rows


def main() -> None:
    rows = table()
    print("E residual: attacker success under inclusion-time re-simulation (R1)")
    print("beta = per-attempt ordering-win rate; K = agent's vulnerable actions")
    print(f"{'beta':>6} {'K':>5} {'analytic':>10} {'monte-carlo':>12}")
    for r in rows:
        print(f"{r['beta']:>6.2f} {r['K']:>5} {r['analytic']:>10.4f} {r['monte_carlo']:>12.4f}")
    print("\nRegime R0 (no re-simulation at inclusion): P_success = 1 for every "
          "attacker who observes the pending victim tx.")
    print("Regime R1 (re-simulation at inclusion): P_success = 1 - (1-beta)^K, "
          "so an active agent (large K) is drained even by a weak attacker.")

    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "race.csv"), "w") as f:
        f.write("beta,K,analytic,monte_carlo\n")
        for r in rows:
            f.write(f"{r['beta']},{r['K']},{r['analytic']:.6f},{r['monte_carlo']:.6f}\n")
    print(f"\nwrote {os.path.join(out, 'race.csv')}")


if __name__ == "__main__":
    main()
