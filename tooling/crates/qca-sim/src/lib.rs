//! Monte Carlo engine for the authorization game in docs/GAME.md.
//!
//! Every quantity here mirrors a symbol in that document: `age` is
//! minCommitAge (`a`), `beta` the adversary's per-block production share,
//! `q` the honest-block inclusion probability for the victim's pending
//! transaction. Theorem 1's closed-form bounds (`beta^a` and `beta^(a+1)`)
//! are implemented alongside the simulation so tests can assert the Monte
//! Carlo estimate lands between them under the i.i.d. builder model; the
//! simulator's reason to exist is everything the theorems do not cover
//! (tie-block auctions, autocorrelated builders, TTL expiry paths, burn
//! responses), each of which relaxes one assumption at a time.
//!
//! Determinism: every run derives from a caller-supplied 64-bit seed via
//! ChaCha8. Same seed, same parameters, same result, byte for byte; the
//! committed result vectors rely on this the same way the golden vectors
//! rely on the fixed test seed.

use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};

pub mod forcing;
pub use forcing::{run_forcing, Defenses, ForcingOutcome, ForcingParams, ForcingResult};

/// Who gets ordering priority in the first block where both the victim's
/// reveal and the adversary's theft reveal are eligible and included by an
/// honest builder. Theorem 1 leaves this to the fee market; the two fixed
/// rules bracket it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TieRule {
    AdversaryWins,
    VictimWins,
}

/// Block production model. `Iid` is the game's builder lottery. `Markov`
/// adds one-step autocorrelation: the adversary's share is still `beta`
/// in steady state, but adversary blocks arrive in runs, which is what
/// real builder concentration looks like and what makes censorship
/// cheaper than independence predicts.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "model")]
pub enum BuilderModel {
    Iid { beta: f64 },
    /// `persistence` is P(adversary builds block n+1 | adversary built n).
    /// Steady-state share stays `beta`; requires `persistence >= beta` for
    /// a valid chain (equality recovers Iid).
    Markov { beta: f64, persistence: f64 },
}

impl BuilderModel {
    pub fn beta(&self) -> f64 {
        match *self {
            BuilderModel::Iid { beta } => beta,
            BuilderModel::Markov { beta, .. } => beta,
        }
    }

    /// Sample whether the adversary builds the next block, given whether it
    /// built the previous one.
    fn next(&self, rng: &mut ChaCha8Rng, prev_adversary: bool) -> bool {
        match *self {
            BuilderModel::Iid { beta } => rng.gen::<f64>() < beta,
            BuilderModel::Markov { beta, persistence } => {
                // P(adv | prev honest) chosen so the stationary share is beta:
                // beta = beta*persistence + (1-beta)*p_switch.
                let p_switch = beta * (1.0 - persistence) / (1.0 - beta);
                let p = if prev_adversary { persistence } else { p_switch };
                rng.gen::<f64>() < p
            }
        }
    }
}

/// AUTH-RACE(a, T, beta, q) with an explicit remaining-TTL budget for the
/// victim's commitment at broadcast time. `remaining_ttl` is how many more
/// blocks the victim's reveal stays valid; expiry moves the leaf to
/// LEAKED-LIVE instead of an immediate adversary win, and `burn_response`
/// controls whether the wallet then plays Theorem 2's move.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct RaceParams {
    pub age: u32,
    pub q: f64,
    pub tie: TieRule,
    pub remaining_ttl: u32,
    pub burn_response: bool,
}

/// Terminal outcomes of one played game, GAME.md's leaf state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Victim's committed action executed.
    VictimExecutes,
    /// Adversary's theft action executed.
    AdversarySteals,
    /// Leaf nullified defensively after expiry; action lost, funds safe.
    Burned,
    /// Leaf leaked with no burn response and the adversary never landed a
    /// theft within the horizon either; a live bearer instrument, an
    /// eventual loss in expectation, counted separately from safety.
    LeakedUnresolved,
}

#[derive(Clone, Debug, Serialize)]
pub struct RaceResult {
    pub params: RaceParams,
    pub trials: u64,
    pub victim_executes: u64,
    pub adversary_steals: u64,
    pub burned: u64,
    pub leaked_unresolved: u64,
    /// Monte Carlo estimate of P(AdversarySteals).
    pub p_steal: f64,
    /// 95% normal-approximation half-width for p_steal.
    pub ci95: f64,
    /// Theorem 1 closed-form brackets under Iid, for cross-checking.
    pub bound_upper: f64,
    pub bound_lower: f64,
}

/// Play one AUTH-RACE game. Returns the terminal outcome.
///
/// Block 0 is the broadcast block (secret becomes public, adversary
/// commits; its commit lands in block 1 regardless of who builds it,
/// because commits are indistinguishable spam that honest builders also
/// include). The victim's reveal is eligible from block 1; the adversary's
/// theft reveal from block 1 + age.
pub fn play_race(params: &RaceParams, model: &BuilderModel, rng: &mut ChaCha8Rng) -> Outcome {
    let mut prev_adversary = false;
    let mut block: u32 = 0;
    loop {
        block += 1;
        if block > params.remaining_ttl {
            // Victim's commitment expired with the reveal unincluded:
            // LEAKED-LIVE. With a burn response the subgame of Theorem 2
            // starts; without one the leaf stays a live bearer instrument.
            return if params.burn_response {
                play_burn_recovery(params.age, params.q, params.tie, model, rng, prev_adversary)
            } else {
                resolve_leaked_live(params.age, params.q, model, rng, prev_adversary)
            };
        }
        let adversary_block = model.next(rng, prev_adversary);
        prev_adversary = adversary_block;
        let theft_eligible = block > params.age;
        if adversary_block {
            // Adversary censors the victim's reveal and lands its own the
            // first block it can.
            if theft_eligible {
                return Outcome::AdversarySteals;
            }
            continue;
        }
        // Honest block: victim's reveal included with probability q; the
        // theft reveal (if eligible) likewise, fee-sufficient by assumption.
        let victim_in = rng.gen::<f64>() < params.q;
        let theft_in = theft_eligible && rng.gen::<f64>() < params.q;
        match (victim_in, theft_in) {
            (true, false) => return Outcome::VictimExecutes,
            (false, true) => return Outcome::AdversarySteals,
            (true, true) => {
                return match params.tie {
                    TieRule::AdversaryWins => Outcome::AdversarySteals,
                    TieRule::VictimWins => Outcome::VictimExecutes,
                }
            }
            (false, false) => continue,
        }
    }
}

/// Theorem 2's subgame after the burn-griefing fix: the leaf is LEAKED-LIVE
/// and burn is age-gated exactly like reveal. So the wallet must itself
/// commit-to-burn and wait `age` blocks, and the adversary must commit-to-
/// steal and wait `age` blocks. Both commitments land in block 1 (honest
/// builders include either as ordinary spam), so both become eligible at
/// block 1 + age and the outcome is a symmetric race from there: whoever's
/// transaction lands first in an eligible block wins, the tie rule breaking
/// same-block coincidence. This is the honest, weaker recovery bound; the
/// old model that let burn land instantly was exactly the exploitable
/// no-age-gate the contract no longer has.
fn play_burn_recovery(
    age: u32,
    q: f64,
    tie: TieRule,
    model: &BuilderModel,
    rng: &mut ChaCha8Rng,
    mut prev_adversary: bool,
) -> Outcome {
    const HORIZON: u32 = 100_000;
    for block in 1..=HORIZON {
        let eligible = block > age;
        let adversary_block = model.next(rng, prev_adversary);
        prev_adversary = adversary_block;
        if !eligible {
            continue;
        }
        if adversary_block {
            // Adversary builds an eligible block: it orders its theft reveal
            // and excludes the burn.
            return Outcome::AdversarySteals;
        }
        // Honest eligible block: both the burn and the theft reveal are
        // pending and fee-sufficient; ordering decides.
        let burn_in = rng.gen::<f64>() < q;
        let theft_in = rng.gen::<f64>() < q;
        match (burn_in, theft_in) {
            (true, false) => return Outcome::Burned,
            (false, true) => return Outcome::AdversarySteals,
            (true, true) => {
                return match tie {
                    TieRule::AdversaryWins => Outcome::AdversarySteals,
                    TieRule::VictimWins => Outcome::Burned,
                }
            }
            (false, false) => continue,
        }
    }
    Outcome::LeakedUnresolved
}

/// LEAKED-LIVE with no wallet response: the adversary commits and takes the
/// leaf as soon as its commitment ages; honest builders include the theft
/// reveal too, since it is a valid fee-sufficient transaction. Nothing
/// races it.
fn resolve_leaked_live(
    age: u32,
    q: f64,
    model: &BuilderModel,
    rng: &mut ChaCha8Rng,
    mut prev_adversary: bool,
) -> Outcome {
    const HORIZON: u32 = 100_000;
    for block in 1..=HORIZON {
        let adversary_block = model.next(rng, prev_adversary);
        prev_adversary = adversary_block;
        if block > age {
            if adversary_block || rng.gen::<f64>() < q {
                return Outcome::AdversarySteals;
            }
        }
    }
    Outcome::LeakedUnresolved
}

/// Run `trials` independent games and aggregate.
pub fn run_race(params: &RaceParams, model: &BuilderModel, trials: u64, seed: u64) -> RaceResult {
    // A Markov chain with the given steady-state share exists only if the
    // adversary is at least as likely to stay as its share; otherwise the
    // implied switch-in probability exceeds 1 and the chain is invalid.
    // Reject rather than silently produce garbage.
    if let BuilderModel::Markov { beta, persistence } = *model {
        assert!(
            persistence >= beta,
            "invalid Markov builder: persistence {persistence} < beta {beta} (no such chain)"
        );
    }
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut counts = [0u64; 4];
    for _ in 0..trials {
        let idx = match play_race(params, model, &mut rng) {
            Outcome::VictimExecutes => 0,
            Outcome::AdversarySteals => 1,
            Outcome::Burned => 2,
            Outcome::LeakedUnresolved => 3,
        };
        counts[idx] += 1;
    }
    let p = counts[1] as f64 / trials as f64;
    let beta = model.beta();
    RaceResult {
        params: *params,
        trials,
        victim_executes: counts[0],
        adversary_steals: counts[1],
        burned: counts[2],
        leaked_unresolved: counts[3],
        p_steal: p,
        ci95: 1.96 * (p * (1.0 - p) / trials as f64).sqrt(),
        bound_upper: beta.powi(params.age as i32),
        bound_lower: beta.powi(params.age as i32 + 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iid(beta: f64) -> BuilderModel {
        BuilderModel::Iid { beta }
    }

    /// Theorem 1 cross-check: with q = 1 and a long TTL the Monte Carlo
    /// estimate must land on the bracket edge the tie rule selects.
    #[test]
    fn race_matches_theorem1_brackets() {
        for &(beta, age) in &[(0.3_f64, 2_u32), (0.5, 4), (0.7, 3)] {
            for &(tie, expect_edge) in &[
                (TieRule::AdversaryWins, beta.powi(age as i32)),
                (TieRule::VictimWins, beta.powi(age as i32 + 1)),
            ] {
                let params = RaceParams {
                    age,
                    q: 1.0,
                    tie,
                    remaining_ttl: 10_000,
                    burn_response: false,
                };
                let r = run_race(&params, &iid(beta), 200_000, 42);
                let tol = 4.0 * r.ci95.max(1e-4);
                assert!(
                    (r.p_steal - expect_edge).abs() < tol,
                    "beta={beta} age={age} tie={tie:?}: sim {} vs closed form {expect_edge}",
                    r.p_steal
                );
            }
        }
    }

    /// Corollary 1a shape check at the degenerate end: a victim who can
    /// never land (q = 0) always loses the leaf eventually.
    #[test]
    fn passive_victim_degrades() {
        let params = RaceParams {
            age: 4,
            q: 0.0,
            tie: TieRule::VictimWins,
            remaining_ttl: 10_000,
            burn_response: false,
        };
        let r = run_race(&params, &iid(0.5), 20_000, 7);
        assert_eq!(r.adversary_steals, r.trials);
    }

    /// Theorem 2 after the burn-griefing fix. A LEAKED-LIVE leaf has lost the
    /// victim's aging head start, so age-gated burn recovery is a symmetric
    /// single-block ordering race, not the clean beta^a bound the main race
    /// enjoys. The honest facts the sim must reproduce:
    ///   - no response: the leaf is lost with near certainty;
    ///   - burn response, victim wins ordering ties: steal drops to ~beta
    ///     (adversary wins only if it builds the first eligible block);
    ///   - burn response, adversary wins ordering ties: near-certain loss.
    /// Real fee auctions land between the two tie edges; the takeaway is that
    /// burn converts certain loss into a coin-flip you influence with fees,
    /// which is strictly weaker than avoiding LEAKED-LIVE in the first place.
    #[test]
    fn burn_recovery_is_a_symmetric_race() {
        let beta = 0.3;
        let base = RaceParams {
            age: 4,
            q: 1.0,
            tie: TieRule::VictimWins,
            remaining_ttl: 0, // expired at broadcast: pure LEAKED-LIVE start
            burn_response: false,
        };
        let no_burn = run_race(&base, &iid(beta), 100_000, 11);
        assert!(
            no_burn.p_steal > 0.9,
            "leaked leaf without burn should be lost: {}",
            no_burn.p_steal
        );

        let burn_victim_ties = run_race(
            &RaceParams {
                burn_response: true,
                tie: TieRule::VictimWins,
                ..base
            },
            &iid(beta),
            200_000,
            11,
        );
        assert!(
            (burn_victim_ties.p_steal - beta).abs() < 0.01,
            "burn recovery with favorable ordering should sit near beta={beta}: {}",
            burn_victim_ties.p_steal
        );

        let burn_adv_ties = run_race(
            &RaceParams {
                burn_response: true,
                tie: TieRule::AdversaryWins,
                ..base
            },
            &iid(beta),
            200_000,
            11,
        );
        assert!(
            burn_adv_ties.p_steal > 0.95,
            "burn recovery with hostile ordering is near-certain loss: {}",
            burn_adv_ties.p_steal
        );
    }

    /// Markov with persistence == beta must reproduce Iid in distribution.
    #[test]
    fn markov_reduces_to_iid() {
        let params = RaceParams {
            age: 3,
            q: 1.0,
            tie: TieRule::AdversaryWins,
            remaining_ttl: 10_000,
            burn_response: false,
        };
        let a = run_race(&params, &iid(0.4), 200_000, 3);
        let b = run_race(
            &params,
            &BuilderModel::Markov {
                beta: 0.4,
                persistence: 0.4,
            },
            200_000,
            3,
        );
        assert!((a.p_steal - b.p_steal).abs() < 4.0 * a.ci95.max(b.ci95));
    }

    /// Concentrated builders make censorship cheaper: persistence above
    /// beta must raise the steal probability at equal steady-state share.
    #[test]
    fn persistence_raises_steal_probability() {
        let params = RaceParams {
            age: 4,
            q: 1.0,
            tie: TieRule::AdversaryWins,
            remaining_ttl: 10_000,
            burn_response: false,
        };
        let iid_r = run_race(&params, &iid(0.3), 200_000, 5);
        let markov_r = run_race(
            &params,
            &BuilderModel::Markov {
                beta: 0.3,
                persistence: 0.8,
            },
            200_000,
            5,
        );
        assert!(
            markov_r.p_steal > 2.0 * iid_r.p_steal,
            "autocorrelation should materially raise censorship success: iid {} vs markov {}",
            iid_r.p_steal,
            markov_r.p_steal
        );
    }
}
