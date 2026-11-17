use crate::utils::rescue::{Hash, Rescue128};
use rand_utils::rand_value;
use winterfell::{
    crypto::{Hasher, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement},
};

/// Merkle root of the ring's public keys, plus the authentication path of the signer's leaf.
///
/// Only the signer's path is kept, so the same type can be backed either by a real Merkle tree
/// over all keys or by a simulated path for very large rings.
pub struct AggPublicKey {
    root: Hash,
    num_keys: usize,
    signer_idx: usize,
    signer_path: Vec<Hash>,
}

impl AggPublicKey {
    /// Builds a full Merkle tree over `keys` and stores the path to `signer_idx`.
    pub fn new(keys: &[[BaseElement; 2]], signer_idx: usize) -> Self {
        let mut leaves: Vec<Hash> = Vec::new();
        for key in keys.iter() {
            leaves.push(Rescue128::digest(key));
        }

        // pad the list of keys with zero keys to make sure the number of leaves is a power of two
        let num_leaves = if leaves.len().is_power_of_two() {
            leaves.len()
        } else {
            leaves.len().next_power_of_two()
        };
        let zero_hash = Rescue128::digest(&[BaseElement::ZERO, BaseElement::ZERO]);
        for _ in leaves.len()..num_leaves {
            leaves.push(zero_hash);
        }

        // build a Merkle tree of all leaves
        let tree = MerkleTree::<Rescue128>::new(leaves).unwrap();

        AggPublicKey {
            root: *tree.root(),
            num_keys: keys.len(),
            signer_idx,
            signer_path: tree.prove(signer_idx).unwrap(),
        }
    }

    /// Simulates a ring of `2^depth` keys without building the tree: the signer's leaf is hashed
    /// up with `depth` random siblings to produce the root.
    pub fn simulated(signer_pk: &[BaseElement; 2], signer_idx: usize, depth: usize) -> Self {
        assert!(depth >= 1, "ring depth must be at least 1");
        assert!(
            depth >= usize::BITS as usize || signer_idx >> depth == 0,
            "signer index out of range"
        );

        let leaf = Rescue128::digest(signer_pk);
        let mut signer_path = vec![leaf];
        let mut node = leaf;
        for level in 0..depth {
            let sibling = Hash::new(rand_value(), rand_value());
            signer_path.push(sibling);
            node = if (signer_idx >> level) & 1 == 0 {
                Rescue128::merge(&[node, sibling])
            } else {
                Rescue128::merge(&[sibling, node])
            };
        }

        AggPublicKey {
            root: node,
            num_keys: 1 << depth,
            signer_idx,
            signer_path,
        }
    }

    /// Returns a 32-byte representation of the aggregated public key.
    pub fn root(&self) -> Hash {
        self.root
    }

    /// Returns the number of individual keys aggregated into this key.
    pub fn num_keys(&self) -> usize {
        self.num_keys
    }

    /// Returns the Merkle path to the signer's leaf, in the format of `MerkleTree::prove`
    /// (leaf first, then siblings from the bottom up). Only the signer's path is stored.
    pub fn get_leaf_path(&self, index: usize) -> Vec<Hash> {
        assert_eq!(index, self.signer_idx, "only the signer's path is stored");
        self.signer_path.clone()
    }
}
