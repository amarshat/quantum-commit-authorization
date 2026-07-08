//! Wallet-side implementation of the commit-reveal authorization protocol.
//!
//! Normative reference: docs/SPEC.md. Every hash here must be byte-identical
//! to what `CommitRevealAccount.sol` computes; the golden vectors produced by
//! `qca-cli vectors` are asserted against the contract in the Foundry suite.
//!
//! Encoding rule: Solidity `abi.encode` pads every value to a 32-byte word,
//! so all tuples hashed below are plain concatenations of 32-byte words
//! (addresses left-padded, integers big-endian). That keeps the encoding
//! injective for the fixed-arity tuples the protocol uses.

use sha3::{Digest, Keccak256};

pub type Hash = [u8; 32];

pub fn keccak(data: &[u8]) -> Hash {
    Keccak256::digest(data).into()
}

/// Domain tags, `keccak256("QCA/v1/<name>")`, one per hash role.
pub mod tags {
    use super::{keccak, Hash};

    pub fn secret() -> Hash {
        keccak(b"QCA/v1/secret")
    }
    pub fn leaf() -> Hash {
        keccak(b"QCA/v1/leaf")
    }
    pub fn node() -> Hash {
        keccak(b"QCA/v1/node")
    }
    pub fn action() -> Hash {
        keccak(b"QCA/v1/action")
    }
    pub fn commit() -> Hash {
        keccak(b"QCA/v1/commit")
    }
    /// Sits in the action-hash slot of a burn commitment, domain-separating
    /// it from an action commitment. See the contract's TAG_BURN.
    pub fn burn() -> Hash {
        keccak(b"QCA/v1/burn")
    }
}

fn word_u64(v: u64) -> Hash {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// A 256-bit big-endian value, matching Solidity `uint256`. Kept as raw
/// bytes so the tooling can author commitments for any on-chain value,
/// including value >= 2^128, making the Rust/Solidity mirror total.
pub fn u256_be(v: u128) -> Hash {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

fn word_address(a: &[u8; 20]) -> Hash {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

fn hash_words(words: &[Hash]) -> Hash {
    let mut h = Keccak256::new();
    for w in words {
        h.update(w);
    }
    h.finalize().into()
}

/// `secret_i = H(enc(TAG_SECRET, seed, i))`. The seed never leaves the
/// wallet; individual secrets are exposed one at a time at reveal.
pub fn secret_at(seed: &Hash, index: u64) -> Hash {
    hash_words(&[tags::secret(), *seed, word_u64(index)])
}

/// `leaf_i = H(enc(TAG_LEAF, secret_i))`.
pub fn leaf_of(secret: &Hash) -> Hash {
    hash_words(&[tags::leaf(), *secret])
}

fn parent(left: &Hash, right: &Hash) -> Hash {
    hash_words(&[tags::node(), *left, *right])
}

/// Complete binary Merkle tree over `2^depth` leaves. Stores every level so
/// proof extraction is O(depth).
pub struct MerkleTree {
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Build the authorization tree for a seed. Global leaf indices run from
    /// `index_offset`; rotations use a fresh offset so nullifier bits from
    /// earlier trees are never re-hit.
    pub fn from_seed(seed: &Hash, depth: u32, index_offset: u64) -> Self {
        assert!((1..=32).contains(&depth), "depth must be in 1..=32");
        let leaves = (0..1u64 << depth)
            .map(|i| leaf_of(&secret_at(seed, index_offset + i)))
            .collect();
        Self::from_leaves(leaves)
    }

    pub fn from_leaves(leaves: Vec<Hash>) -> Self {
        assert!(leaves.len().is_power_of_two() && leaves.len() >= 2);
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let next = prev.chunks(2).map(|p| parent(&p[0], &p[1])).collect();
            levels.push(next);
        }
        Self { levels }
    }

    pub fn depth(&self) -> u32 {
        (self.levels.len() - 1) as u32
    }

    pub fn root(&self) -> Hash {
        self.levels.last().unwrap()[0]
    }

    /// Sibling path from leaf to root, bottom up. Matches the fold order in
    /// the contract's `reveal`.
    pub fn proof(&self, leaf_index: u64) -> Vec<Hash> {
        let mut idx = leaf_index as usize;
        assert!(idx < self.levels[0].len(), "leaf index out of range");
        let mut path = Vec::with_capacity(self.depth() as usize);
        for level in &self.levels[..self.levels.len() - 1] {
            path.push(level[idx ^ 1]);
            idx >>= 1;
        }
        path
    }
}

/// Verify a membership proof exactly the way the contract does. Used by
/// tests and the adversarial simulator; the contract stays the authority.
pub fn verify_proof(root: &Hash, secret: &Hash, leaf_index: u64, proof: &[Hash]) -> bool {
    let mut node = leaf_of(secret);
    let mut idx = leaf_index;
    for sibling in proof {
        node = if idx & 1 == 0 {
            parent(&node, sibling)
        } else {
            parent(sibling, &node)
        };
        idx >>= 1;
    }
    node == *root
}

/// `H(enc(TAG_ACTION, target, value, H(data)))`. The calldata is hashed
/// before encoding so the outer tuple has fixed arity. `value` is the full
/// 256-bit word, so the encoding matches Solidity `uint256` at every value.
pub fn action_hash(target: &[u8; 20], value_be: &Hash, data: &[u8]) -> Hash {
    hash_words(&[tags::action(), word_address(target), *value_be, keccak(data)])
}

/// `H(enc(TAG_COMMIT, chainid, account, actionHash, leafIndex, secret))`.
/// Binding chain id and account kills cross-chain and cross-account replay;
/// the high-entropy secret inside the preimage is what makes the commitment
/// hiding.
pub fn commitment(
    chain_id: u64,
    account: &[u8; 20],
    action_hash: &Hash,
    leaf_index: u64,
    secret: &Hash,
) -> Hash {
    hash_words(&[
        tags::commit(),
        word_u64(chain_id),
        word_address(account),
        *action_hash,
        word_u64(leaf_index),
        *secret,
    ])
}

/// Burn commitment: identical shape to [`commitment`] but with `TAG_BURN` in
/// the action slot, so it opens the age-gated `burn` path and can never be
/// confused with an action commitment.
pub fn burn_commitment(chain_id: u64, account: &[u8; 20], leaf_index: u64, secret: &Hash) -> Hash {
    hash_words(&[
        tags::commit(),
        word_u64(chain_id),
        word_address(account),
        tags::burn(),
        word_u64(leaf_index),
        *secret,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> Hash {
        keccak(b"test seed")
    }

    #[test]
    fn derivation_is_deterministic_and_distinct() {
        assert_eq!(secret_at(&seed(), 0), secret_at(&seed(), 0));
        assert_ne!(secret_at(&seed(), 0), secret_at(&seed(), 1));
        assert_ne!(secret_at(&seed(), 0), leaf_of(&secret_at(&seed(), 0)));
    }

    #[test]
    fn proofs_verify_for_every_leaf() {
        let tree = MerkleTree::from_seed(&seed(), 4, 0);
        for i in 0..16u64 {
            let s = secret_at(&seed(), i);
            assert!(verify_proof(&tree.root(), &s, i, &tree.proof(i)));
        }
    }

    #[test]
    fn wrong_secret_or_index_fails() {
        let tree = MerkleTree::from_seed(&seed(), 3, 0);
        let s = secret_at(&seed(), 2);
        assert!(!verify_proof(&tree.root(), &s, 3, &tree.proof(3)));
        assert!(!verify_proof(&tree.root(), &keccak(b"nope"), 2, &tree.proof(2)));
    }

    #[test]
    fn offset_shifts_leaves() {
        let a = MerkleTree::from_seed(&seed(), 3, 0);
        let b = MerkleTree::from_seed(&seed(), 3, 8);
        assert_ne!(a.root(), b.root());
        // Tree b covers global indices 8..16; its local leaf 0 is index 8.
        let s = secret_at(&seed(), 8);
        assert!(verify_proof(&b.root(), &s, 0, &b.proof(0)));
    }

    #[test]
    fn commitment_binds_every_field() {
        let acct = [0x11u8; 20];
        let target = [0x22u8; 20];
        let s = secret_at(&seed(), 0);
        let a = action_hash(&target, &u256_be(1), b"data");
        let base = commitment(1, &acct, &a, 0, &s);
        assert_ne!(base, commitment(2, &acct, &a, 0, &s));
        assert_ne!(base, commitment(1, &[0x12u8; 20], &a, 0, &s));
        assert_ne!(base, commitment(1, &acct, &action_hash(&target, &u256_be(2), b"data"), 0, &s));
        assert_ne!(base, commitment(1, &acct, &a, 1, &s));
        assert_ne!(base, commitment(1, &acct, &a, 0, &secret_at(&seed(), 1)));
    }
}
