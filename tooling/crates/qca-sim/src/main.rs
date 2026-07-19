//! CLI for the authorization-game simulator. Two commands:
//!
//! `race`  - one parameter point, JSON result on stdout.
//! `sweep` - grid over (age, beta), JSON matrix on stdout; this is what
//!           produces the committed result vectors and the paper's curves.

use clap::{Parser, Subcommand};
use qca_sim::{
    run_cancel, run_forcing, run_race, BuilderModel, CancelParams, Defenses, ForcingParams,
    RaceParams, TieRule,
};

#[derive(Parser)]
#[command(about = "Adversarial mempool simulator for the QCA authorization game (docs/GAME.md)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Simulate one AUTH-RACE parameter point.
    Race {
        #[arg(long)]
        age: u32,
        #[arg(long)]
        beta: f64,
        /// P(adversary block | previous block adversary). Omit for i.i.d.
        #[arg(long)]
        persistence: Option<f64>,
        #[arg(long, default_value_t = 1.0)]
        q: f64,
        #[arg(long, value_parser = parse_tie, default_value = "adversary")]
        tie: TieRule,
        #[arg(long, default_value_t = 10_000)]
        remaining_ttl: u32,
        #[arg(long)]
        burn_response: bool,
        #[arg(long, default_value_t = 1_000_000)]
        trials: u64,
        #[arg(long, default_value_t = 42)]
        seed: u64,
    },
    /// Sweep a grid over age and beta at fixed q/tie; JSON array on stdout.
    Sweep {
        /// Comma-separated ages, e.g. 1,2,4,8,16
        #[arg(long, value_delimiter = ',')]
        ages: Vec<u32>,
        /// Comma-separated betas, e.g. 0.05,0.1,0.25,0.5,0.9
        #[arg(long, value_delimiter = ',')]
        betas: Vec<f64>,
        #[arg(long)]
        persistence: Option<f64>,
        #[arg(long, default_value_t = 1.0)]
        q: f64,
        #[arg(long, value_parser = parse_tie, default_value = "adversary")]
        tie: TieRule,
        #[arg(long, default_value_t = 10_000)]
        remaining_ttl: u32,
        #[arg(long)]
        burn_response: bool,
        #[arg(long, default_value_t = 1_000_000)]
        trials: u64,
        #[arg(long, default_value_t = 42)]
        seed: u64,
    },
    /// Forcing-adversary game (docs/STATE_MODEL.md M4): sweep p_reorg x beta at a
    /// fixed policy and defense set; JSON array on stdout. Defenses default to the
    /// full set; each `--no-*` flag removes one to demonstrate the attack it closes.
    Forcing {
        /// Comma-separated per-block strand probabilities, e.g. 0.0,0.1,0.3,0.6.
        #[arg(long, value_delimiter = ',')]
        p_reorgs: Vec<f64>,
        /// Comma-separated adversary builder shares.
        #[arg(long, value_delimiter = ',')]
        betas: Vec<f64>,
        #[arg(long)]
        persistence: Option<f64>,
        #[arg(long, default_value_t = 4)]
        finality_depth: u32,
        #[arg(long, default_value_t = 0.9)]
        q: f64,
        #[arg(long, default_value_t = 0.2)]
        p_intent_change: f64,
        #[arg(long, default_value_t = 0.0)]
        mev_sensitive_frac: f64,
        #[arg(long)]
        adversary_griefs: bool,
        #[arg(long, value_parser = parse_tie, default_value = "adversary")]
        coupling_tie: TieRule,
        #[arg(long, default_value_t = u32::MAX)]
        valid_until: u32,
        #[arg(long, default_value_t = 1.0)]
        action_value: f64,
        #[arg(long, default_value_t = 0.0)]
        restore_rate: f64,
        #[arg(long, default_value_t = 1)]
        r_max: u32,
        #[arg(long, default_value_t = 1_000_000)]
        leaf_budget: u32,
        #[arg(long, default_value_t = 200)]
        horizon: u32,
        #[arg(long)]
        no_write_ahead: bool,
        #[arg(long)]
        no_same_key_nonce: bool,
        #[arg(long)]
        no_rebroadcast: bool,
        #[arg(long)]
        no_retry_after_finality: bool,
        #[arg(long)]
        no_randomizer_r: bool,
        #[arg(long, default_value_t = 1_000_000)]
        trials: u64,
        #[arg(long, default_value_t = 42)]
        seed: u64,
    },
    /// Cancellation game (paper 3): the time-lock-revoke residual, P(owner cancels)
    /// = 1 - beta^delta, swept over veto window delta x builder share beta. JSON
    /// array on stdout.
    Cancel {
        /// Comma-separated veto windows (blocks), e.g. 1,2,4,8,16.
        #[arg(long, value_delimiter = ',')]
        deltas: Vec<u32>,
        /// Comma-separated adversary builder shares.
        #[arg(long, value_delimiter = ',')]
        betas: Vec<f64>,
        #[arg(long)]
        persistence: Option<f64>,
        #[arg(long, default_value_t = 1.0)]
        q: f64,
        #[arg(long, default_value_t = 0)]
        finality_depth: u32,
        #[arg(long, default_value_t = 0.0)]
        p_reorg: f64,
        #[arg(long, default_value_t = 1_000_000)]
        trials: u64,
        #[arg(long, default_value_t = 42)]
        seed: u64,
    },
}

fn parse_tie(s: &str) -> Result<TieRule, String> {
    match s {
        "adversary" => Ok(TieRule::AdversaryWins),
        "victim" => Ok(TieRule::VictimWins),
        _ => Err("tie must be 'adversary' or 'victim'".into()),
    }
}

fn model(beta: f64, persistence: Option<f64>) -> BuilderModel {
    match persistence {
        Some(p) => BuilderModel::Markov {
            beta,
            persistence: p,
        },
        None => BuilderModel::Iid { beta },
    }
}

fn main() {
    match Cli::parse().command {
        Command::Race {
            age,
            beta,
            persistence,
            q,
            tie,
            remaining_ttl,
            burn_response,
            trials,
            seed,
        } => {
            let params = RaceParams {
                age,
                q,
                tie,
                remaining_ttl,
                burn_response,
            };
            let r = run_race(&params, &model(beta, persistence), trials, seed);
            println!("{}", serde_json::to_string_pretty(&r).unwrap());
        }
        Command::Sweep {
            ages,
            betas,
            persistence,
            q,
            tie,
            remaining_ttl,
            burn_response,
            trials,
            seed,
        } => {
            let mut out = Vec::new();
            for &age in &ages {
                for &beta in &betas {
                    let params = RaceParams {
                        age,
                        q,
                        tie,
                        remaining_ttl,
                        burn_response,
                    };
                    // Seed derived per cell so the grid is embarrassingly
                    // reproducible cell by cell, not order-dependent.
                    let cell_seed = seed
                        ^ (u64::from(age) << 32)
                        ^ (beta.to_bits().rotate_left(17));
                    out.push(run_race(&params, &model(beta, persistence), trials, cell_seed));
                }
            }
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        Command::Forcing {
            p_reorgs,
            betas,
            persistence,
            finality_depth,
            q,
            p_intent_change,
            mev_sensitive_frac,
            adversary_griefs,
            coupling_tie,
            valid_until,
            action_value,
            restore_rate,
            r_max,
            leaf_budget,
            horizon,
            no_write_ahead,
            no_same_key_nonce,
            no_rebroadcast,
            no_retry_after_finality,
            no_randomizer_r,
            trials,
            seed,
        } => {
            let defenses = Defenses {
                write_ahead: !no_write_ahead,
                same_key_nonce: !no_same_key_nonce,
                rebroadcast_dont_burn: !no_rebroadcast,
                retry_after_finality: !no_retry_after_finality,
                randomizer_r: !no_randomizer_r,
            };
            let mut out = Vec::new();
            for &p_reorg in &p_reorgs {
                for &beta in &betas {
                    let params = ForcingParams {
                        p_reorg,
                        finality_depth,
                        q,
                        p_intent_change,
                        mev_sensitive_frac,
                        adversary_griefs,
                        coupling_tie,
                        valid_until,
                        action_value,
                        restore_rate,
                        r_max,
                        leaf_budget,
                        horizon,
                    };
                    let cell_seed = seed
                        ^ p_reorg.to_bits().rotate_left(31)
                        ^ beta.to_bits().rotate_left(17);
                    out.push(run_forcing(&params, &defenses, &model(beta, persistence), trials, cell_seed));
                }
            }
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        Command::Cancel {
            deltas,
            betas,
            persistence,
            q,
            finality_depth,
            p_reorg,
            trials,
            seed,
        } => {
            let mut out = Vec::new();
            for &delta in &deltas {
                for &beta in &betas {
                    let params = CancelParams {
                        delta,
                        q,
                        finality_depth,
                        p_reorg,
                    };
                    let cell_seed =
                        seed ^ (u64::from(delta) << 32) ^ beta.to_bits().rotate_left(17);
                    out.push(run_cancel(&params, &model(beta, persistence), trials, cell_seed));
                }
            }
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
    }
}
