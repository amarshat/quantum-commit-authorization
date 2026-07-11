//! Wallet CLI. Everything here is deterministic given a seed except
//! `keygen`, which pulls from the OS CSPRNG.

use clap::{Parser, Subcommand};
use qca_core::{action_hash, burn_commitment, commitment, secret_at, tags, u256_be, Hash, MerkleTree};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Serialize;

#[derive(Parser)]
#[command(name = "qca", about = "Commit-reveal PQ authorization wallet tooling")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a fresh 32-byte seed from the OS CSPRNG.
    Keygen,
    /// Compute the Merkle root for a seed.
    Root {
        #[arg(long)]
        seed: String,
        #[arg(long, default_value_t = 10)]
        depth: u32,
        /// Global index offset (used after rotations).
        #[arg(long, default_value_t = 0)]
        offset: u64,
    },
    /// Emit the reveal material for one leaf: secret and Merkle path.
    Proof {
        #[arg(long)]
        seed: String,
        #[arg(long, default_value_t = 10)]
        depth: u32,
        #[arg(long, default_value_t = 0)]
        offset: u64,
        #[arg(long)]
        index: u64,
    },
    /// Compute the commitment hash for an action.
    Commit {
        #[arg(long)]
        seed: String,
        #[arg(long)]
        chain_id: u64,
        /// The CommitRevealAccount address, 0x-hex.
        #[arg(long)]
        account: String,
        /// Call target, 0x-hex address.
        #[arg(long)]
        target: String,
        /// Wei value.
        #[arg(long, default_value_t = 0)]
        value: u128,
        /// Calldata, 0x-hex (empty allowed).
        #[arg(long, default_value = "0x")]
        data: String,
        #[arg(long)]
        index: u64,
        /// Global index offset of the active tree. Must match the offset the
        /// tree was built with, or the derived secret will not match the one
        /// the proof reveals and the on-chain reveal will fail.
        #[arg(long, default_value_t = 0)]
        offset: u64,
        /// Execution-gas budget forwarded to the action, bound into the
        /// commitment. The reveal must pass the same value.
        #[arg(long, default_value_t = 1_000_000)]
        call_gas_limit: u64,
    },
    /// Compute the burn commitment hash for a leaf. Opens the age-gated
    /// defensive nullify; no action is bound.
    BurnCommit {
        #[arg(long)]
        seed: String,
        #[arg(long)]
        chain_id: u64,
        /// The CommitRevealAccount address, 0x-hex.
        #[arg(long)]
        account: String,
        #[arg(long)]
        index: u64,
        /// Global index offset of the active tree; must match the tree build.
        #[arg(long, default_value_t = 0)]
        offset: u64,
    },
    /// Emit golden test vectors as JSON. The Foundry suite parses this file
    /// and asserts the contract computes identical bytes.
    Vectors {
        #[arg(long, default_value_t = 3)]
        depth: u32,
    },
}

fn parse_h32(s: &str) -> Hash {
    let raw = hex::decode(s.trim_start_matches("0x")).expect("invalid hex");
    raw.try_into().expect("expected 32 bytes")
}

fn parse_addr(s: &str) -> [u8; 20] {
    let raw = hex::decode(s.trim_start_matches("0x")).expect("invalid hex");
    raw.try_into().expect("expected 20 bytes")
}

fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

#[derive(Serialize)]
struct ProofOut {
    leaf_index: u64,
    secret: String,
    proof: Vec<String>,
    root: String,
}

#[derive(Serialize)]
struct VectorLeaf {
    index: u64,
    secret: String,
    leaf: String,
    proof: Vec<String>,
}

#[derive(Serialize)]
struct Vectors {
    // Field order matters: forge's vm.parseJson decodes struct fields
    // alphabetically, so consumers index by key, not order.
    seed: String,
    depth: u32,
    tag_secret: String,
    tag_leaf: String,
    tag_node: String,
    tag_action: String,
    tag_commit: String,
    tag_burn: String,
    root: String,
    leaves: Vec<VectorLeaf>,
    example_chain_id: u64,
    example_account: String,
    example_target: String,
    example_value: u128,
    example_data: String,
    example_leaf_index: u64,
    example_call_gas_limit: u64,
    example_action_hash: String,
    example_commitment: String,
    example_burn_commitment: String,
}

fn main() {
    match Cli::parse().cmd {
        Cmd::Keygen => {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            println!("{}", hx(&seed));
        }
        Cmd::Root { seed, depth, offset } => {
            let tree = MerkleTree::from_seed(&parse_h32(&seed), depth, offset);
            println!("{}", hx(&tree.root()));
        }
        Cmd::Proof { seed, depth, offset, index } => {
            let seed = parse_h32(&seed);
            let tree = MerkleTree::from_seed(&seed, depth, offset);
            let out = ProofOut {
                leaf_index: index,
                secret: hx(&secret_at(&seed, offset + index)),
                proof: tree.proof(index).iter().map(|h| hx(h)).collect(),
                root: hx(&tree.root()),
            };
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        Cmd::Commit { seed, chain_id, account, target, value, data, index, offset, call_gas_limit } => {
            // Derive with offset + index, exactly as `proof` and `root` do,
            // so a rotated tree's commitment binds the same secret the proof
            // will reveal.
            let secret = secret_at(&parse_h32(&seed), offset + index);
            let data = hex::decode(data.trim_start_matches("0x")).expect("invalid hex data");
            let a = action_hash(&parse_addr(&target), &u256_be(value), &data);
            let c = commitment(chain_id, &parse_addr(&account), &a, index, &secret, call_gas_limit);
            println!("{}", hx(&c));
        }
        Cmd::BurnCommit { seed, chain_id, account, index, offset } => {
            let secret = secret_at(&parse_h32(&seed), offset + index);
            let c = burn_commitment(chain_id, &parse_addr(&account), index, &secret);
            println!("{}", hx(&c));
        }
        Cmd::Vectors { depth } => {
            // Fixed, public seed: these are cross-implementation test
            // vectors, not key material.
            let seed = qca_core::keccak(b"QCA golden vectors v1");
            let tree = MerkleTree::from_seed(&seed, depth, 0);

            let leaves = (0..1u64 << depth)
                .map(|i| {
                    let secret = secret_at(&seed, i);
                    VectorLeaf {
                        index: i,
                        secret: hx(&secret),
                        leaf: hx(&qca_core::leaf_of(&secret)),
                        proof: tree.proof(i).iter().map(|h| hx(h)).collect(),
                    }
                })
                .collect();

            let example_account = [0xAAu8; 20];
            let example_target = [0xBBu8; 20];
            let example_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
            let (chain_id, value, leaf_index) = (1u64, 1_000_000_000_000_000_000u128, 5u64);
            let call_gas_limit = 1_000_000u64;
            let a = action_hash(&example_target, &u256_be(value), &example_data);
            let c = commitment(chain_id, &example_account, &a, leaf_index, &secret_at(&seed, leaf_index), call_gas_limit);
            let bc = burn_commitment(chain_id, &example_account, leaf_index, &secret_at(&seed, leaf_index));

            let v = Vectors {
                seed: hx(&seed),
                depth,
                tag_secret: hx(&tags::secret()),
                tag_leaf: hx(&tags::leaf()),
                tag_node: hx(&tags::node()),
                tag_action: hx(&tags::action()),
                tag_commit: hx(&tags::commit()),
                tag_burn: hx(&tags::burn()),
                root: hx(&tree.root()),
                leaves,
                example_chain_id: chain_id,
                example_account: hx(&example_account),
                example_target: hx(&example_target),
                example_value: value,
                example_data: hx(&example_data),
                example_leaf_index: leaf_index,
                example_call_gas_limit: call_gas_limit,
                example_action_hash: hx(&a),
                example_commitment: hx(&c),
                example_burn_commitment: hx(&bc),
            };
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        }
    }
}
