//! Cancellation game for paper 3 (internal/paper3-cancellation.md): the residual
//! of the time-lock-then-revoke construction, the mirror of the AUTH-RACE theft
//! game in docs/GAME.md.
//!
//! The construction queues an authorized action X with a Delta-block veto window
//! (`unlock = enqueue + Delta`); before unlock the owner may cancel by publishing
//! a revoke signature on an UNUSED one-time key. The adversary cannot forge the
//! revoke (no seed, and an unused leaf has never been signed = the R2a
//! unforgeability) and cannot forge a queue entry, so its ONLY move is to CENSOR
//! the owner's revoke across the veto window. Cancellation therefore fails only if
//! the adversary suppresses the revoke for all Delta blocks:
//!
//!   P(cancel fails) = [ beta + (1 - beta)(1 - q) ]^Delta         (i.i.d.)
//!                   = beta^Delta                                 (attentive owner, q = 1)
//!
//! This is Corollary 1a's censorship geometry (GAME.md), pointed the OWNER's way:
//! paper 1's theft race is beta^a against the victim; here the same exponent works
//! FOR the owner over the veto window, which is exactly why a latency budget Delta
//! buys trustless cancellation. Under fair ordering the revoke cannot be censored
//! at all, so cancellation is race-free (P(fail) = 0); beta^Delta is the honest
//! (adversarial-builder) number and the fair-ordering case is the best case.
//!
//! There is no tie rule: the revoke is only valid strictly BEFORE unlock and the
//! execute is only valid AT/AFTER unlock, so the two live in disjoint block ranges
//! and never contend within one block. This makes the cancellation race strictly
//! simpler than the theft race (no competing aged instrument, no intra-block tie).
//!
//! The reorg coupling (why Delta and finality are one knob): a landed revoke that
//! is still sub-final can be stranded by a reorg, but the owner just re-broadcasts
//! the same revoke signature (no re-sign of the one-time leaf). Choosing Delta >=
//! finality guarantees the queued action is final before it can execute, so a
//! reorg can only delay the revoke inside the window, never carry the action past
//! a revoke the owner already intends. The sim measures this frontier directly.
//!
//! Determinism: seeded ChaCha8, byte-stable, as the rest of qca-sim.

use crate::BuilderModel;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct CancelParams {
    /// Veto window in blocks (the latency price of trustless cancellation). The
    /// owner may land a revoke in blocks [1, delta]; the action executes at
    /// block delta + 1 if not revoked.
    pub delta: u32,
    /// Honest-block inclusion probability for the owner's revoke (GAME.md `q`).
    /// q = 1 is the attentive fee-escalating owner (the beta^delta headline);
    /// q < 1 is a passive owner.
    pub q: f64,
    /// Blocks a landed revoke must survive un-reorged to be final. A sub-final
    /// revoke can be stranded (adversary reorg) and must re-land. 0 disables the
    /// reorg model (the pure censorship game).
    pub finality_depth: u32,
    /// Per-adversary-block probability of stranding a sub-final revoke.
    pub p_reorg: f64,
}

/// Terminal outcome of one cancellation game.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelOutcome {
    /// The owner's revoke landed and finalized before unlock: action cancelled.
    Cancelled,
    /// The revoke never finalized in the window: the queued action executed.
    ActionExecuted,
}

#[derive(Clone, Debug, Serialize)]
pub struct CancelResult {
    pub params: CancelParams,
    pub trials: u64,
    pub cancelled: u64,
    pub action_executed: u64,
    /// Monte Carlo estimate of P(cancellation succeeds).
    pub p_cancel: f64,
    /// 95% normal-approximation half-width for p_cancel.
    pub ci95: f64,
    /// Closed-form P(cancel) under i.i.d. with no reorg model, for cross-check:
    /// 1 - [beta + (1-beta)(1-q)]^delta. Valid when finality_depth == 0.
    pub bound_iid: f64,
}

/// Play one cancellation game. The owner wants to revoke a queued action before
/// its unlock at block `delta + 1`; the adversary censors (and, sub-final, may
/// reorg) the revoke.
pub fn play_cancel(p: &CancelParams, model: &BuilderModel, rng: &mut ChaCha8Rng) -> CancelOutcome {
    let mut prev_adversary = false;
    // The revoke's inclusion state: None = pending; Some(age) = landed `age`
    // blocks ago and finalizing.
    let mut revoke_age: Option<u32> = None;

    for _block in 1..=p.delta {
        let adversary_block = model.next(rng, prev_adversary);
        prev_adversary = adversary_block;

        // A landed-but-sub-final revoke can be stranded by an adversary reorg.
        if let Some(age) = revoke_age {
            if age + 1 >= p.finality_depth {
                // Finalized before unlock: the queued action can never execute.
                return CancelOutcome::Cancelled;
            }
            if adversary_block && p.p_reorg > 0.0 && rng.gen::<f64>() < p.p_reorg {
                revoke_age = None; // stranded; back to pending, owner re-broadcasts
            } else {
                revoke_age = Some(age + 1);
            }
            continue;
        }

        // Pending revoke: an adversary block censors it; an honest block includes
        // it with probability q. (finality_depth == 0 means a landed revoke is
        // final immediately, i.e. the pure censorship game.)
        if adversary_block {
            continue;
        }
        if rng.gen::<f64>() < p.q {
            if p.finality_depth == 0 {
                return CancelOutcome::Cancelled;
            }
            revoke_age = Some(0);
        }
    }

    // Unlock reached. A revoke that landed but is not yet final loses the race:
    // the action's unlock has arrived and it can execute this block. (With
    // Delta >= finality this is unreachable for a revoke that landed early
    // enough; it is the honest edge for a revoke that landed too late.)
    if let Some(age) = revoke_age {
        if age >= p.finality_depth {
            return CancelOutcome::Cancelled;
        }
    }
    CancelOutcome::ActionExecuted
}

/// Run `trials` cancellation games and aggregate.
pub fn run_cancel(p: &CancelParams, model: &BuilderModel, trials: u64, seed: u64) -> CancelResult {
    if let BuilderModel::Markov { beta, persistence } = *model {
        assert!(persistence >= beta, "invalid Markov builder: persistence {persistence} < beta {beta}");
    }
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut cancelled = 0u64;
    for _ in 0..trials {
        if play_cancel(p, model, &mut rng) == CancelOutcome::Cancelled {
            cancelled += 1;
        }
    }
    let t = trials as f64;
    let pc = cancelled as f64 / t;
    let beta = model.beta();
    let fail_per_block = beta + (1.0 - beta) * (1.0 - p.q);
    CancelResult {
        params: *p,
        trials,
        cancelled,
        action_executed: trials - cancelled,
        p_cancel: pc,
        ci95: 1.96 * (pc * (1.0 - pc) / t).sqrt(),
        bound_iid: 1.0 - fail_per_block.powi(p.delta as i32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iid(beta: f64) -> BuilderModel {
        BuilderModel::Iid { beta }
    }

    /// The headline: with an attentive owner (q=1) and no reorg model, cancellation
    /// fails with exactly beta^delta, so P(cancel) = 1 - beta^delta. Monte Carlo
    /// must match the closed form.
    #[test]
    fn matches_beta_delta_closed_form() {
        for &(beta, delta) in &[(0.3_f64, 2_u32), (0.5, 4), (0.7, 3), (0.9, 6)] {
            let p = CancelParams {
                delta,
                q: 1.0,
                finality_depth: 0,
                p_reorg: 0.0,
            };
            let r = run_cancel(&p, &iid(beta), 200_000, 42);
            let expect = 1.0 - beta.powi(delta as i32);
            assert!(
                (r.p_cancel - expect).abs() < 4.0 * r.ci95.max(1e-4),
                "beta={beta} delta={delta}: sim {} vs closed form {expect}",
                r.p_cancel
            );
            assert!(
                (r.bound_iid - expect).abs() < 1e-12,
                "closed-form field wrong: {} vs {expect}",
                r.bound_iid
            );
        }
    }

    /// A larger veto window buys more cancellation safety: P(cancel) is strictly
    /// increasing in delta (the latency/cancellability tradeoff, the trilemma's
    /// priced corner). At delta high enough, cancellation is near-certain.
    #[test]
    fn larger_window_buys_cancellation() {
        let beta = 0.5;
        let mk = |delta| CancelParams {
            delta,
            q: 1.0,
            finality_depth: 0,
            p_reorg: 0.0,
        };
        let small = run_cancel(&mk(2), &iid(beta), 200_000, 7).p_cancel;
        let big = run_cancel(&mk(10), &iid(beta), 200_000, 7).p_cancel;
        assert!(big > small, "more latency must buy more cancellation: d2={small} d10={big}");
        assert!(big > 0.999, "delta=10 at beta=0.5 should be near-certain cancel: {big}");
    }

    /// Passive owner (q<1) degrades cancellation: a revoke that honest builders
    /// only sometimes include is easier to keep out of the window.
    #[test]
    fn passive_owner_degrades() {
        let p_active = CancelParams { delta: 4, q: 1.0, finality_depth: 0, p_reorg: 0.0 };
        let p_passive = CancelParams { q: 0.5, ..p_active };
        let active = run_cancel(&p_active, &iid(0.4), 200_000, 11).p_cancel;
        let passive = run_cancel(&p_passive, &iid(0.4), 200_000, 11).p_cancel;
        assert!(active > passive, "attentive owner should cancel more often: {active} vs {passive}");
    }

    /// The reorg coupling: with a finality requirement, a too-short window fails to
    /// finalize the revoke even against a modest adversary, while a window that
    /// clears finality with margin restores near-certain cancellation. This is the
    /// Delta >= finality frontier the paper measures.
    #[test]
    fn finality_requires_window_margin() {
        let beta = 0.3;
        // Window barely above finality: the revoke must land AND survive
        // finality_depth blocks inside delta, so effective room is delta-finality.
        let tight = CancelParams { delta: 5, q: 1.0, finality_depth: 4, p_reorg: 0.3 };
        let loose = CancelParams { delta: 20, q: 1.0, finality_depth: 4, p_reorg: 0.3 };
        let t = run_cancel(&tight, &iid(beta), 200_000, 5).p_cancel;
        let l = run_cancel(&loose, &iid(beta), 200_000, 5).p_cancel;
        assert!(l > t, "a window with finality margin must cancel more: tight={t} loose={l}");
        assert!(l > 0.99, "delta=20 >> finality=4 should be near-certain: {l}");
    }

    /// Concentrated builders (Markov persistence > beta) make censorship of the
    /// revoke easier at equal share, lowering cancellation success. Honest headline
    /// should use this, not i.i.d.
    #[test]
    fn concentration_lowers_cancellation() {
        let p = CancelParams { delta: 6, q: 1.0, finality_depth: 0, p_reorg: 0.0 };
        let iid_r = run_cancel(&p, &iid(0.3), 200_000, 9).p_cancel;
        let markov_r = run_cancel(
            &p,
            &BuilderModel::Markov { beta: 0.3, persistence: 0.8 },
            200_000,
            9,
        )
        .p_cancel;
        assert!(markov_r < iid_r, "concentration should lower cancellation: iid={iid_r} markov={markov_r}");
    }

    #[test]
    fn deterministic() {
        let p = CancelParams { delta: 5, q: 1.0, finality_depth: 2, p_reorg: 0.2 };
        let a = run_cancel(&p, &iid(0.4), 50_000, 3);
        let b = run_cancel(&p, &iid(0.4), 50_000, 3);
        assert_eq!(a.cancelled, b.cancelled);
    }
}
