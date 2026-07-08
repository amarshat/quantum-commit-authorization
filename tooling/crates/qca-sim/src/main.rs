//! CLI for the authorization-game simulator. Two commands:
//!
//! `race`  - one parameter point, JSON result on stdout.
//! `sweep` - grid over (age, beta), JSON matrix on stdout; this is what
//!           produces the committed result vectors and the paper's curves.

use clap::{Parser, Subcommand};
use qca_sim::{run_race, BuilderModel, RaceParams, TieRule};

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
    }
}
