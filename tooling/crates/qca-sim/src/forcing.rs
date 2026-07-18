//! Forcing-adversary simulator for docs/STATE_MODEL.md (QCA 3 milestone M4).
//!
//! docs/GAME.md's adversary manipulates transaction *ordering* to steal a public
//! secret; this module models the forcing adversary one layer earlier, which
//! manipulates *inclusion and the wallet's view of it* to try to force a second
//! public signature on a one-time key (a forgery), or, failing that, to force
//! fresh-leaf consumption or liveness delay.
//!
//! The sim is the empirical cross-check of the structural claims in
//! STATE_MODEL.md, as the AUTH-RACE sim cross-checks Theorem 1's `beta^a` bracket:
//!
//!   R2a (safety, unconditional): under D2 (write-ahead) + Lemma-S1 (same nonce
//!   key), with no restore accident, NO trace signs any leaf more than once and NO
//!   nonce lane executes twice, for every builder/reorg/censor schedule. The tests
//!   assert an exact 0 over a wide sweep; the code is the proof (no path signs a
//!   consumed leaf when `write_ahead` is on, and competing ops share one lane when
//!   `same_key_nonce` is on).
//!
//!   PoC-per-defense (necessity): remove `write_ahead` and an intent-change
//!   re-signs the same leaf (forgery reachable); remove `same_key_nonce` and the
//!   first fresh-key retry runs an independent lane (double-execution reachable);
//!   remove `rebroadcast_dont_burn` and a real reorg strand burns a fresh leaf;
//!   remove `randomizer_R` and index-steering collapses the few-time tail so a
//!   second exposure forges regardless of `r_max`.
//!
//!   R2b (residual): with full defenses the only path to a forgery is the off-chain
//!   restore accident (rate `restore_rate`, NOT an adversary move). FORS few-time
//!   absorbs `r_max` exposures INCLUDING the original signature, so a forgery needs
//!   `>= r_max` restores on one leaf; the measured rate is bounded above by the
//!   exact binomial tail `P(Binomial(horizon, restore_rate) >= r_max)` (all restores
//!   on one leaf, full-horizon exposure), cross-checked in a test that exercises the
//!   low-q / long-horizon regime where a Poisson approximation broke. The
//!   reorg/censor residual (fresh-leaf consumption, delay, MEV-coupling) is measured
//!   as distributions, not proved to a floor.
//!
//! Honest limits (folded from the M1 and M4 red-team; a reader must not over-read):
//!   - No cost axis. `p_reorg` is the conditional strand probability GIVEN the
//!     adversary builds the block; the sim measures residual-given-strand-rate, it
//!     does NOT price a reorg, so it cannot itself validate "reorg is near-free"
//!     (that is M1's external post-Capella argument). `finality_depth` is an
//!     abstraction, not consensus finality.
//!   - The forgery model is count-based and valid only for NON-steered reuse, which
//!     is exactly what `randomizer_R` buys; with `randomizer_R` off the sim models
//!     the steering break as an effective `r_max = 1`. The step function is
//!     conservative for FORS (beyond `r_max`, real 256-set forgery work is still
//!     ~2^130 quantum for another exposure or two, not certain), so it undersells
//!     FORS graceful degradation. `r_max` here is a security-floor crossover, not a
//!     forgery-certainty threshold.
//!   - The restore path assumes every accident re-signs a DISTINCT message, so the
//!     restore residual is a ceiling, not an estimate (a same-message re-sign is
//!     idempotent under deterministic `R` and harmless).
//!   - Not modeled, each of which would only make the residual look cheaper/safer:
//!     the fee-spike / maxPvgCeil / L2-pubdata re-sign channels (folded into the
//!     exogenous `p_intent_change`), nonce-view RPC equivocation (the trusted-nonce
//!     assumption behind same_key_nonce), and bundler withhold-then-late-release.
//!     I3/I8 (the permanent on-chain nullifier) are out of the sim's state.
//!
//! Determinism: every draw derives from a caller seed via ChaCha8 (verified
//! byte-identical across debug/release), so committed result vectors are stable.

use crate::{BuilderModel, TieRule};
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};

/// Wallet defenses, individually toggleable so each can be shown necessary by
/// removing it. `full()` is the deployed set.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Defenses {
    /// D2 write-ahead burn: a leaf is marked consumed in durable local storage
    /// BEFORE its (single) signature is released, and a consumed leaf is never
    /// re-signed. Off: an intent change re-signs the same leaf.
    pub write_ahead: bool,
    /// Lemma S1: a retry reuses the same 2D-nonce key, so a stranded op and its
    /// replacement share one lane and the account nonce serializes them. Off: the
    /// first fresh-key retry runs an independent lane and both can execute.
    pub same_key_nonce: bool,
    /// mev finding 2: on a real strand with unchanged intent, rebroadcast the
    /// stored signed op (no new signature, no fresh leaf). Off: burn a fresh leaf
    /// on every actual strand.
    pub rebroadcast_dont_burn: bool,
    /// D3(ii): when the intent must change, wait for the stranded attempt to be
    /// final before signing the correction (a `finality_depth` cooldown). Shapes
    /// the delay/leaf residual; not a safety defense.
    pub retry_after_finality: bool,
    /// SPEC-HASHSIG blocking rule 2: the secret-keyed message randomizer `R` makes
    /// the FORS indices unpredictable, so honest reuse spreads over random index
    /// sets and the `k(a-log2 r)` few-time tail holds. Off: an intent-influencing
    /// adversary steers the indices (M1 pq-F1), collapsing the tail so a SECOND
    /// exposure forges regardless of `r_max` (modeled as effective `r_max = 1`).
    pub randomizer_r: bool,
}

impl Defenses {
    pub fn full() -> Self {
        Self {
            write_ahead: true,
            same_key_nonce: true,
            rebroadcast_dont_burn: true,
            retry_after_finality: true,
            randomizer_r: true,
        }
    }
    /// The few-time budget the wallet actually gets. Without `R`, index-steering
    /// defeats the tail and only the single original signature is safe.
    fn effective_r_max(&self, r_max: u32) -> u32 {
        if self.randomizer_r {
            r_max.max(1)
        } else {
            1
        }
    }
}

/// One forcing game's parameters.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ForcingParams {
    /// Probability that, GIVEN the adversary builds this block, it strands the
    /// not-yet-final ops included in the block it orphans. Tied to the builder
    /// model (a strand needs the adversary to propose the reorging slot), so the
    /// effective strand rate is ~ `beta * p_reorg`. Near-free reorgs are the
    /// `p_reorg -> 1` regime; the sim does not price them.
    pub p_reorg: f64,
    /// Depth in blocks an op must survive un-stranded to be final (abstraction,
    /// not consensus finality). An op is reorgeable only while sub-final.
    pub finality_depth: u32,
    /// Honest-block inclusion probability for a pending op (GAME.md `q`).
    pub q: f64,
    /// Per-block probability the wallet's intent must change (a correction on a
    /// fresh leaf, not a rebroadcast). Also the fold-in point for adversary-driven
    /// re-sign channels the sim does not model separately (fee-spike, pubdata).
    pub p_intent_change: f64,
    /// Of intent changes, the fraction whose stale action is MEV-sensitive, so an
    /// adversarial builder profits by landing the stale op over the correction.
    pub mev_sensitive_frac: f64,
    /// If set, the adversary also lands stale NON-mev ops when it builds, to
    /// consume the victim's nonce and force fresh-leaf exhaustion (pure griefing).
    pub adversary_griefs: bool,
    /// Disposition of the same-block race between a stale op and its correction
    /// when both reach finality together (the MEV-coupling tie), bracketed like
    /// the AUTH-RACE sim's TieRule rather than left to iteration order.
    pub coupling_tie: TieRule,
    /// Blocks an op stays valid while pending before its signed `validUntil`
    /// lapses; a lapsed current op forces a fresh-leaf re-attempt (censorship ->
    /// consumption). `u32::MAX` models no expiry.
    pub valid_until: u32,
    /// Notional value of an MEV-sensitive action, for the adversary-profit proxy.
    pub action_value: f64,
    /// Exogenous per-block probability of a local-state restore accident that
    /// re-signs one already-used leaf over a (distinct) intent. NOT an adversary
    /// capability; the sole path to a second signature under full defenses.
    pub restore_rate: f64,
    /// FORS few-time budget. A forgery needs the leaf's total public signatures to
    /// exceed `r_max`; since the original signature counts, that is `>= r_max`
    /// restores. WOTS baseline is `r_max = 1`.
    pub r_max: u32,
    /// Per-device leaf budget `2^depth`; exhausting it is the bounded DoS ceiling.
    pub leaf_budget: u32,
    /// Block horizon before the lineage is declared stuck.
    pub horizon: u32,
}

/// Terminal outcome of one played forcing game.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForcingOutcome {
    /// The wallet's currently-intended action executed once.
    ActionLanded,
    /// CATASTROPHE: more than the effective `r_max` public signatures on one leaf.
    /// Unreachable under full defenses with `restore_rate = 0` (R2a).
    ForgeryWindow,
    /// The owner's action executed twice via independent nonce lanes. Unreachable
    /// under `same_key_nonce` (Lemma S1).
    DoubleExecution,
    /// A stale MEV-sensitive op was landed BY THE ADVERSARY over the correction;
    /// the correction is denied and the adversary profits (MEV-coupling loss).
    MevCouplingLoss,
    /// The device leaf budget was exhausted before the action landed.
    LeafExhausted,
    /// The horizon was reached without landing, short of exhaustion.
    Stuck,
}

/// One live op. A bearer instrument once signed; `incl_age = None` means pending,
/// `Some(k)` means included and `k` blocks from finality.
#[derive(Clone, Copy, Debug)]
struct Op {
    leaf: u32,
    lane: u64,
    stale: bool,
    mev_sensitive: bool,
    incl_age: Option<u32>,
    /// Blocks this op has spent pending, for the `validUntil` lapse check.
    blocks_pending: u32,
    /// Set once the op has ever been included (so a strand is distinguishable from
    /// a never-included op; the burn residual keys off real strands only).
    was_included: bool,
    /// Set when the op's current inclusion was by an adversary-built block (for
    /// MEV-coupling attribution: an honest-landed stale op is a benign self-race).
    adv_included: bool,
    /// Cooldown blocks before this op may be broadcast (retry-after-finality).
    cooldown: u32,
}

impl Op {
    fn fresh(leaf: u32, lane: u64, cooldown: u32) -> Self {
        Op {
            leaf,
            lane,
            stale: false,
            mev_sensitive: false,
            incl_age: None,
            blocks_pending: 0,
            was_included: false,
            adv_included: false,
            cooldown,
        }
    }
}

/// Full aggregate over `trials` games.
#[derive(Clone, Debug, Serialize)]
pub struct ForcingResult {
    pub params: ForcingParams,
    pub defenses: Defenses,
    pub trials: u64,
    pub action_landed: u64,
    pub forgery_window: u64,
    pub double_execution: u64,
    /// MEV-coupling losses attributed to the adversary landing the stale op.
    pub mev_coupling_loss: u64,
    /// Benign self-races where an honest builder landed a stale op (the beta=0
    /// floor); NOT an attack, reported so the adversary delta is readable.
    pub honest_stale_landed: u64,
    pub leaf_exhausted: u64,
    pub stuck: u64,
    /// Fraction of games whose intended action ever landed (report ALONGSIDE the
    /// delay, which is conditional on landing; avoids survivorship bias).
    pub land_rate: f64,
    /// Monte Carlo estimate of the forged-action probability.
    pub p_forgery: f64,
    /// One-sided 95% upper bound on p_forgery. Uses the rule of three (~3/trials)
    /// at a zero count, where a symmetric normal CI degenerates to 0 and would
    /// falsely imply "measured zero to within zero".
    pub p_forgery_upper: f64,
    /// Probability the owner double-spends its own action.
    pub p_double_execution: f64,
    /// Mean fresh leaves consumed per game (exhaustion pressure).
    pub mean_leaves_consumed: f64,
    /// Mean / median / 95th-percentile blocks from first attempt to landing, over
    /// games that landed. `None` when nothing landed (not a 0.0 sentinel).
    pub mean_land_delay: Option<f64>,
    pub p50_land_delay: Option<u32>,
    pub p95_land_delay: Option<u32>,
    /// Mean adversary profit per game from MEV-coupling wins (value proxy).
    pub mean_adversary_profit: f64,
    /// Exact binomial-tail upper bound on p_forgery from the restore accident:
    /// `P(Binomial(horizon, restore_rate) >= effective_r_max)`. The measured
    /// p_forgery must lie at or below this.
    pub forgery_restore_bound: f64,
}

struct Play {
    outcome: ForcingOutcome,
    leaves_consumed: u32,
    delay: u32,
    adversary_profit: f64,
    honest_stale_landed: bool,
}

/// Play one forcing game to a terminal outcome. See the module header for the
/// invariants the code makes true by construction.
fn play_forcing(
    p: &ForcingParams,
    d: &Defenses,
    model: &BuilderModel,
    rng: &mut ChaCha8Rng,
) -> Play {
    let r_eff = d.effective_r_max(p.r_max);
    let mut sig_count: Vec<u32> = Vec::new();
    let mut next_leaf: u32 = 0;
    // Lane 0 is the primary nonce key; advance the allocator past it so the first
    // cross-key retry (under !same_key) gets a genuinely independent lane.
    let mut next_lane: u64 = 1;
    let mut leaves_consumed: u32 = 0;
    let mut executions: u32 = 0;
    let mut adversary_profit: f64 = 0.0;
    let mut honest_stale_landed = false;
    let mut prev_adversary = false;

    let alloc_and_sign =
        |sig_count: &mut Vec<u32>, next_leaf: &mut u32, leaves_consumed: &mut u32| -> u32 {
            let leaf = *next_leaf;
            *next_leaf += 1;
            sig_count.push(1);
            *leaves_consumed += 1;
            leaf
        };

    let mut ops: Vec<Op> = Vec::new();
    let first_leaf = alloc_and_sign(&mut sig_count, &mut next_leaf, &mut leaves_consumed);
    ops.push(Op::fresh(first_leaf, 0, 0));

    // Allocate a fresh current op (a re-attempt); returns None on exhaustion.
    macro_rules! reattempt {
        () => {{
            if leaves_consumed >= p.leaf_budget {
                return Play {
                    outcome: ForcingOutcome::LeafExhausted,
                    leaves_consumed,
                    delay: 0,
                    adversary_profit,
                    honest_stale_landed,
                };
            }
            let leaf = alloc_and_sign(&mut sig_count, &mut next_leaf, &mut leaves_consumed);
            ops.push(Op::fresh(leaf, 0, 0));
            // A deliberate re-attempt at a fresh nonce is a new intent-instance, so
            // it resets the concurrent-execution count: a stale execution followed
            // by a re-attempt is sequential (owner in the loop), NOT the Lemma-S1
            // double. Two executions with no re-attempt between them (concurrent
            // independent lanes under !same_key) remain a genuine double.
            executions = 0;
        }};
    }

    for block in 1..=p.horizon {
        prev_adversary = model.next(rng, prev_adversary);
        let adversary_block = prev_adversary;

        // (1) Restore accident: re-sign a random used leaf over a distinct intent.
        if p.restore_rate > 0.0 && next_leaf > 0 && rng.gen::<f64>() < p.restore_rate {
            let victim = rng.gen_range(0..next_leaf) as usize;
            sig_count[victim] += 1;
            if sig_count[victim] > r_eff {
                return Play {
                    outcome: ForcingOutcome::ForgeryWindow,
                    leaves_consumed,
                    delay: block,
                    adversary_profit,
                    honest_stale_landed,
                };
            }
            let lane = if d.same_key_nonce {
                0
            } else {
                let l = next_lane;
                next_lane += 1;
                l
            };
            let mut op = Op::fresh(victim as u32, lane, 0);
            op.stale = false;
            ops.push(op);
        }

        // (2) validUntil: age pending ops; a lapsed op leaves the mempool. A lapsed
        // CURRENT op forces a fresh-leaf re-attempt (censorship -> consumption).
        let mut current_lapsed = false;
        for op in ops.iter_mut() {
            if op.incl_age.is_none() {
                op.blocks_pending += 1;
            }
        }
        let before = ops.len();
        let mut lapsed_current = false;
        ops.retain(|op| {
            let lapse = op.incl_age.is_none() && op.blocks_pending > p.valid_until;
            if lapse && !op.stale {
                lapsed_current = true;
            }
            !lapse
        });
        if before != ops.len() {
            current_lapsed = lapsed_current;
        }

        // (3) Reorg, tied to the builder: only an adversary block strands, and it
        // orphans ALL not-yet-final included ops together.
        if adversary_block && rng.gen::<f64>() < p.p_reorg {
            let mut stranded_current = false;
            for op in ops.iter_mut() {
                if let Some(age) = op.incl_age {
                    if age < p.finality_depth {
                        op.incl_age = None; // stranded; nonce for its lane rolls back
                        op.adv_included = false;
                        if !op.stale {
                            stranded_current = true;
                        }
                    }
                }
            }
            // Without rebroadcast-don't-burn, the wallet wastefully advances the
            // current op to a fresh leaf on the actual strand.
            if stranded_current && !d.rebroadcast_dont_burn {
                if let Some(idx) = ops
                    .iter()
                    .position(|o| !o.stale && o.incl_age.is_none() && o.was_included)
                {
                    if leaves_consumed >= p.leaf_budget {
                        return Play {
                            outcome: ForcingOutcome::LeafExhausted,
                            leaves_consumed,
                            delay: block,
                            adversary_profit,
                            honest_stale_landed,
                        };
                    }
                    let leaf = alloc_and_sign(&mut sig_count, &mut next_leaf, &mut leaves_consumed);
                    ops[idx].leaf = leaf; // fresh leaf, sig_count = 1, cannot forge
                    ops[idx].was_included = false;
                }
            }
        }

        // (4) Aging and execution. Age included ops; collect those reaching
        // finality this block, then execute one, serialized by nonce lane.
        let mut finalized: Vec<usize> = Vec::new();
        for (i, op) in ops.iter_mut().enumerate() {
            if let Some(age) = op.incl_age {
                let na = age + 1;
                if na >= p.finality_depth {
                    finalized.push(i);
                } else {
                    op.incl_age = Some(na);
                }
            }
        }
        if !finalized.is_empty() {
            // Pick the executing op. If a stale op and the current correction both
            // finalize this block, the coupling tie rule decides; otherwise take
            // the first finalized.
            let has_stale = finalized.iter().any(|&i| ops[i].stale);
            let has_current = finalized.iter().any(|&i| !ops[i].stale);
            let pick = if has_stale && has_current {
                match p.coupling_tie {
                    TieRule::AdversaryWins => *finalized.iter().find(|&&i| ops[i].stale).unwrap(),
                    TieRule::VictimWins => *finalized.iter().find(|&&i| !ops[i].stale).unwrap(),
                }
            } else {
                finalized[0]
            };
            let ex = ops[pick];
            executions += 1;
            // Nonce serialization: consuming this lane kills its siblings. Under
            // same_key everything is lane 0, so exactly one op can ever execute.
            ops.retain(|o| o.lane != ex.lane);
            if executions >= 2 {
                return Play {
                    outcome: ForcingOutcome::DoubleExecution,
                    leaves_consumed,
                    delay: block,
                    adversary_profit,
                    honest_stale_landed,
                };
            }
            if ex.stale {
                if ex.mev_sensitive && ex.adv_included {
                    adversary_profit += p.action_value;
                    return Play {
                        outcome: ForcingOutcome::MevCouplingLoss,
                        leaves_consumed,
                        delay: block,
                        adversary_profit,
                        honest_stale_landed,
                    };
                }
                // Honest-landed stale (benign self-race) or an adversary grief on a
                // non-mev action: the old/wrong action ran and consumed its lane. If
                // a correction survives in another lane (only possible under
                // !same_key), it stays live and a second execution there is the
                // Lemma-S1 double (caught above). If no current op remains (same_key
                // killed it), the wallet deliberately re-attempts at a fresh nonce.
                if !ex.mev_sensitive {
                    honest_stale_landed = honest_stale_landed || !ex.adv_included;
                }
                if !ops.iter().any(|o| !o.stale) {
                    reattempt!();
                }
            } else {
                return Play {
                    outcome: ForcingOutcome::ActionLanded,
                    leaves_consumed,
                    delay: block,
                    adversary_profit,
                    honest_stale_landed,
                };
            }
        }

        // (5) Inclusion of pending ops.
        if adversary_block {
            // The adversary includes a stale op it profits from (mev) or, if
            // griefing, any stale op to consume the nonce; it censors everything
            // else, including the victim's current op.
            if let Some(idx) = ops.iter().position(|o| {
                o.stale
                    && o.incl_age.is_none()
                    && o.cooldown == 0
                    && (o.mev_sensitive || p.adversary_griefs)
            }) {
                ops[idx].incl_age = Some(0);
                ops[idx].was_included = true;
                ops[idx].adv_included = true;
            }
        } else {
            for op in ops.iter_mut() {
                if op.incl_age.is_none() && op.cooldown == 0 && rng.gen::<f64>() < p.q {
                    op.incl_age = Some(0);
                    op.was_included = true;
                    op.adv_included = false;
                }
            }
        }

        // Tick cooldowns for still-pending ops.
        for op in ops.iter_mut() {
            if op.incl_age.is_none() && op.cooldown > 0 {
                op.cooldown -= 1;
            }
        }

        // (6) Intent change: the current action must change.
        if rng.gen::<f64>() < p.p_intent_change {
            if let Some(idx) = ops.iter().position(|o| !o.stale) {
                if d.write_ahead {
                    if leaves_consumed >= p.leaf_budget {
                        return Play {
                            outcome: ForcingOutcome::LeafExhausted,
                            leaves_consumed,
                            delay: block,
                            adversary_profit,
                            honest_stale_landed,
                        };
                    }
                    let leaf = alloc_and_sign(&mut sig_count, &mut next_leaf, &mut leaves_consumed);
                    let mev = rng.gen::<f64>() < p.mev_sensitive_frac;
                    let old_lane = ops[idx].lane;
                    ops[idx].stale = true;
                    ops[idx].mev_sensitive = mev;
                    let lane = if d.same_key_nonce {
                        old_lane
                    } else {
                        let l = next_lane;
                        next_lane += 1;
                        l
                    };
                    let cooldown = if d.retry_after_finality {
                        p.finality_depth
                    } else {
                        0
                    };
                    ops.push(Op::fresh(leaf, lane, cooldown));
                } else {
                    // No write-ahead: re-sign the SAME leaf over the new intent.
                    let leaf = ops[idx].leaf as usize;
                    sig_count[leaf] += 1;
                    if sig_count[leaf] > r_eff {
                        return Play {
                            outcome: ForcingOutcome::ForgeryWindow,
                            leaves_consumed,
                            delay: block,
                            adversary_profit,
                            honest_stale_landed,
                        };
                    }
                    ops[idx].incl_age = None;
                    ops[idx].was_included = false;
                }
            }
        }

        // (7) If a lapse or a stale execution left no current op, re-attempt.
        if current_lapsed && !ops.iter().any(|o| !o.stale) {
            reattempt!();
        }
    }

    Play {
        outcome: ForcingOutcome::Stuck,
        leaves_consumed,
        delay: 0,
        adversary_profit,
        honest_stale_landed,
    }
}

/// Run `trials` independent forcing games and aggregate.
pub fn run_forcing(
    p: &ForcingParams,
    d: &Defenses,
    model: &BuilderModel,
    trials: u64,
    seed: u64,
) -> ForcingResult {
    assert!(p.r_max >= 1, "r_max must be >= 1 (WOTS baseline is 1)");
    assert!(p.leaf_budget >= 1, "leaf_budget must be >= 1");
    assert!(p.horizon >= 1, "horizon must be >= 1");
    if let BuilderModel::Markov { beta, persistence } = *model {
        assert!(
            persistence >= beta,
            "invalid Markov builder: persistence {persistence} < beta {beta}"
        );
    }
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut n = [0u64; 6]; // landed, forgery, double, mev, exhausted, stuck
    let mut honest_stale = 0u64;
    let mut sum_leaves: u64 = 0;
    let mut sum_delay: u64 = 0;
    let mut sum_profit: f64 = 0.0;
    let mut delay_hist = vec![0u64; (p.horizon + 1) as usize];
    for _ in 0..trials {
        let play = play_forcing(p, d, model, &mut rng);
        sum_leaves += u64::from(play.leaves_consumed);
        sum_profit += play.adversary_profit;
        if play.honest_stale_landed {
            honest_stale += 1;
        }
        let idx = match play.outcome {
            ForcingOutcome::ActionLanded => {
                sum_delay += u64::from(play.delay);
                delay_hist[play.delay as usize] += 1;
                0
            }
            ForcingOutcome::ForgeryWindow => 1,
            ForcingOutcome::DoubleExecution => 2,
            ForcingOutcome::MevCouplingLoss => 3,
            ForcingOutcome::LeafExhausted => 4,
            ForcingOutcome::Stuck => 5,
        };
        n[idx] += 1;
    }
    let t = trials as f64;
    let landed = n[0];
    let p_forgery = n[1] as f64 / t;
    let p_forgery_upper = if n[1] == 0 {
        3.0 / t // rule of three: one-sided 95% upper bound for a zero count
    } else {
        p_forgery + 1.96 * (p_forgery * (1.0 - p_forgery) / t).sqrt()
    };
    let pct = |frac: f64| -> Option<u32> {
        if landed == 0 {
            return None;
        }
        let target = (landed as f64 * frac).ceil() as u64;
        let mut cum = 0u64;
        for (delay, &c) in delay_hist.iter().enumerate() {
            cum += c;
            if cum >= target {
                return Some(delay as u32);
            }
        }
        Some(p.horizon)
    };
    ForcingResult {
        params: *p,
        defenses: *d,
        trials,
        action_landed: landed,
        forgery_window: n[1],
        double_execution: n[2],
        mev_coupling_loss: n[3],
        honest_stale_landed: honest_stale,
        leaf_exhausted: n[4],
        stuck: n[5],
        land_rate: landed as f64 / t,
        p_forgery,
        p_forgery_upper,
        p_double_execution: n[2] as f64 / t,
        mean_leaves_consumed: sum_leaves as f64 / t,
        mean_land_delay: if landed > 0 {
            Some(sum_delay as f64 / landed as f64)
        } else {
            None
        },
        p50_land_delay: pct(0.50),
        p95_land_delay: pct(0.95),
        mean_adversary_profit: sum_profit / t,
        forgery_restore_bound: restore_forgery_bound(p, d),
    }
}

/// Exact upper bound on the per-game forgery probability from the restore accident:
/// `P(Binomial(horizon, restore_rate) >= r_eff)`, the worst case where every
/// restore lands on one leaf over the full horizon. Since a leaf carries its
/// original signature, the leaf's total signatures are `1 + restores`, and a
/// forgery is `> r_eff`, i.e. `restores >= r_eff`. Games that end early only reduce
/// exposure, and spreading restores over multiple leaves only reduces the max per
/// leaf, so this is a genuine ceiling. Binomial (not Poisson) so it is exact.
fn restore_forgery_bound(p: &ForcingParams, d: &Defenses) -> f64 {
    let r_eff = d.effective_r_max(p.r_max);
    if p.restore_rate <= 0.0 {
        return 0.0;
    }
    let n = p.horizon as u64;
    let pr = p.restore_rate;
    // cdf = P(N <= r_eff - 1) via iterative pmf; bound = 1 - cdf = P(N >= r_eff).
    let mut pmf = (1.0 - pr).powi(n as i32); // pmf(0)
    let mut cdf = pmf;
    for k in 1..r_eff {
        // pmf(k) = pmf(k-1) * (n-k+1)/k * pr/(1-pr)
        pmf *= ((n - u64::from(k) + 1) as f64 / f64::from(k)) * (pr / (1.0 - pr));
        cdf += pmf;
        if pmf == 0.0 {
            break;
        }
    }
    (1.0 - cdf).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iid(beta: f64) -> BuilderModel {
        BuilderModel::Iid { beta }
    }

    fn base() -> ForcingParams {
        ForcingParams {
            p_reorg: 0.6,
            finality_depth: 4,
            q: 0.9,
            p_intent_change: 0.2,
            mev_sensitive_frac: 0.0,
            adversary_griefs: false,
            coupling_tie: TieRule::AdversaryWins,
            valid_until: u32::MAX,
            action_value: 1.0,
            restore_rate: 0.0,
            r_max: 1,
            leaf_budget: 1_000_000,
            horizon: 120,
        }
    }

    /// R2a: under full defenses with no restore accident, NO forgery and NO
    /// double-execution, for any builder share, strand rate, intent-change rate,
    /// MEV mix, griefing, or finite validUntil. Exact zero over a wide sweep.
    #[test]
    fn full_defense_no_forgery_no_double_exec() {
        let d = Defenses::full();
        for &beta in &[0.25_f64, 0.75] {
            for &p_reorg in &[0.0_f64, 0.5, 1.0] {
                for &p_ic in &[0.0_f64, 0.4] {
                    for &mev in &[0.0_f64, 1.0] {
                        for &vu in &[u32::MAX, 8] {
                            let p = ForcingParams {
                                p_reorg,
                                p_intent_change: p_ic,
                                mev_sensitive_frac: mev,
                                adversary_griefs: true,
                                valid_until: vu,
                                ..base()
                            };
                            let r = run_forcing(&p, &d, &iid(beta), 2_000, 1);
                            assert_eq!(r.forgery_window, 0, "forgery under full defense: beta={beta} p_reorg={p_reorg} p_ic={p_ic} mev={mev} vu={vu}");
                            assert_eq!(r.double_execution, 0, "double-exec under full defense: beta={beta} p_reorg={p_reorg} p_ic={p_ic} mev={mev} vu={vu}");
                        }
                    }
                }
            }
        }
    }

    /// PoC: no write-ahead => an intent change re-signs the same leaf => forgery.
    #[test]
    fn no_write_ahead_opens_forgery() {
        let d = Defenses {
            write_ahead: false,
            ..Defenses::full()
        };
        let p = ForcingParams {
            p_intent_change: 0.3,
            r_max: 1,
            ..base()
        };
        let r = run_forcing(&p, &d, &iid(0.3), 15_000, 2);
        assert!(
            r.forgery_window > 0,
            "expected forgeries without write-ahead: {}",
            r.p_forgery
        );
    }

    /// PoC: no same-key-nonce => the FIRST fresh-key retry is an independent lane,
    /// so double-execution is reachable after a SINGLE intent change. The lane
    /// allocator fix (advance past lane 0) makes the rate linear, not quadratic,
    /// in p_intent_change.
    #[test]
    fn no_same_key_nonce_opens_double_exec() {
        let d = Defenses {
            same_key_nonce: false,
            ..Defenses::full()
        };
        let p = ForcingParams {
            p_intent_change: 0.4,
            p_reorg: 0.3,
            q: 1.0,
            ..base()
        };
        let r = run_forcing(&p, &d, &iid(0.2), 20_000, 3);
        assert!(
            r.double_execution > 0,
            "expected double-exec without same-key nonce: {}",
            r.p_double_execution
        );
    }

    /// PoC: no randomizer R => index-steering collapses the few-time tail, so a
    /// SECOND exposure forges even at r_max = 2 (which with R would be safe).
    #[test]
    fn no_randomizer_r_defeats_few_time_tail() {
        let p = ForcingParams {
            restore_rate: 0.02,
            r_max: 2,
            q: 0.0,
            ..base()
        };
        let with_r = run_forcing(&p, &Defenses::full(), &iid(0.3), 20_000, 8);
        let without_r = run_forcing(
            &p,
            &Defenses {
                randomizer_r: false,
                ..Defenses::full()
            },
            &iid(0.3),
            20_000,
            8,
        );
        assert!(
            without_r.p_forgery > with_r.p_forgery + 0.05,
            "steering (no R) must forge more at r_max=2: withR={} noR={}",
            with_r.p_forgery,
            without_r.p_forgery
        );
    }

    /// Removing rebroadcast-don't-burn burns fresh leaves on REAL strands only, so
    /// leaf consumption rises with the strand rate; a never-stranded op burns none.
    #[test]
    fn rebroadcast_saves_leaves_on_real_strands() {
        // q=1 so ops are included and thus strandable; adversary strands them.
        let p = ForcingParams {
            p_reorg: 1.0,
            q: 1.0,
            p_intent_change: 0.0,
            finality_depth: 6,
            ..base()
        };
        let full = run_forcing(&p, &Defenses::full(), &iid(0.5), 15_000, 4);
        let burny = run_forcing(
            &p,
            &Defenses {
                rebroadcast_dont_burn: false,
                ..Defenses::full()
            },
            &iid(0.5),
            15_000,
            4,
        );
        assert_eq!(full.forgery_window, 0);
        assert_eq!(
            burny.forgery_window, 0,
            "write-ahead still prevents forgery when burning leaves"
        );
        assert!(
            burny.mean_leaves_consumed > full.mean_leaves_consumed + 0.5,
            "burn policy should consume more leaves on real strands: full={} burny={}",
            full.mean_leaves_consumed,
            burny.mean_leaves_consumed
        );

        // No inclusion (q=0) => no strand possible => burn policy adds no leaves.
        let pq0 = ForcingParams { q: 0.0, ..p };
        let burny0 = run_forcing(
            &pq0,
            &Defenses {
                rebroadcast_dont_burn: false,
                ..Defenses::full()
            },
            &iid(0.5),
            5_000,
            4,
        );
        assert!(
            (burny0.mean_leaves_consumed - 1.0).abs() < 1e-9,
            "no strand possible at q=0 => exactly 1 leaf, got {}",
            burny0.mean_leaves_consumed
        );
    }

    /// R2b: the measured restore-forgery rate respects the exact binomial bound in
    /// the hard low-q / long-horizon regime that broke the old off-by-one Poisson
    /// bound, and FORS r_max=2 cuts the rate versus WOTS r_max=1.
    #[test]
    fn restore_forgery_respects_binomial_bound_and_r_max_helps() {
        let d = Defenses::full();
        // q=0: games never land, so restores run the full horizon (the regime that
        // exposed the old bound as invalid).
        for &r_max in &[1_u32, 2, 3] {
            let p = ForcingParams {
                restore_rate: 0.02,
                r_max,
                q: 0.0,
                ..base()
            };
            let r = run_forcing(&p, &d, &iid(0.3), 30_000, 5);
            assert!(
                r.p_forgery <= r.forgery_restore_bound + r.p_forgery_ci_upper_slack(),
                "r_max={r_max}: measured {} exceeds binomial bound {}",
                r.p_forgery,
                r.forgery_restore_bound
            );
        }
        let r1 = run_forcing(
            &ForcingParams {
                restore_rate: 0.02,
                r_max: 1,
                q: 0.0,
                ..base()
            },
            &d,
            &iid(0.3),
            30_000,
            5,
        );
        let r2 = run_forcing(
            &ForcingParams {
                restore_rate: 0.02,
                r_max: 2,
                q: 0.0,
                ..base()
            },
            &d,
            &iid(0.3),
            30_000,
            5,
        );
        assert!(
            r2.p_forgery < r1.p_forgery,
            "r_max=2 must cut forgery vs r_max=1: {} vs {}",
            r2.p_forgery,
            r1.p_forgery
        );
    }

    /// MEV-coupling is adversary-attributed: at beta=0 (no adversary blocks) there
    /// are no adversary MEV losses, only the benign honest self-race floor.
    #[test]
    fn mev_coupling_is_adversary_attributed() {
        let p = ForcingParams {
            p_intent_change: 0.3,
            mev_sensitive_frac: 1.0,
            q: 0.9,
            ..base()
        };
        let z = run_forcing(&p, &Defenses::full(), &iid(0.0), 12_000, 9);
        assert_eq!(
            z.mev_coupling_loss, 0,
            "no adversary blocks => no adversary MEV loss, got {}",
            z.mev_coupling_loss
        );
        let a = run_forcing(&p, &Defenses::full(), &iid(0.5), 12_000, 9);
        assert!(
            a.mev_coupling_loss > 0,
            "with adversary blocks the coupling loss should appear"
        );
        assert!(
            a.mean_adversary_profit > 0.0,
            "adversary MEV wins should register profit"
        );
    }

    /// Determinism: same seed and params reproduce byte-for-byte.
    #[test]
    fn deterministic() {
        let p = base();
        let a = run_forcing(&p, &Defenses::full(), &iid(0.4), 10_000, 7);
        let b = run_forcing(&p, &Defenses::full(), &iid(0.4), 10_000, 7);
        assert_eq!(a.action_landed, b.action_landed);
        assert_eq!(a.mean_leaves_consumed, b.mean_leaves_consumed);
        assert_eq!(a.mev_coupling_loss, b.mev_coupling_loss);
    }
}

#[cfg(test)]
impl ForcingResult {
    /// CI slack for the bound assertion: the measured rate may exceed a tight bound
    /// by sampling noise, so allow a few CI widths.
    fn p_forgery_ci_upper_slack(&self) -> f64 {
        4.0 * (self.p_forgery * (1.0 - self.p_forgery) / self.trials as f64)
            .sqrt()
            .max(1e-4)
    }
}
