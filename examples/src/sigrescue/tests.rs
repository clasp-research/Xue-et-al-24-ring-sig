use super::*;
use winterfell::FieldExtension;

fn test_options() -> ProofOptions {
    ProofOptions::new(28, 8, 0, FieldExtension::None, 4, 31)
}

#[test]
fn real_tree_prove_verify() {
    for num_signers in [7, 63] {
        let example = RingSigExample::<Blake3_256>::new(num_signers, test_options());
        let proof = example.prove();
        assert!(example.verify(proof.clone()).is_ok());
        assert!(example.verify_with_wrong_inputs(proof).is_err());
    }
}

#[test]
fn simulated_path_prove_verify() {
    for depth in [3, 10, 30, 32] {
        let example = RingSigExample::<Blake3_256>::new_simulated(depth, test_options());
        assert_eq!(example.ring_size(), 1 << depth);
        let proof = example.prove();
        assert!(example.verify(proof.clone()).is_ok(), "depth {depth}");
        assert!(example.verify_with_wrong_inputs(proof).is_err());
    }
}

#[test]
fn simulated_path_rejects_wrong_root() {
    let example = RingSigExample::<Blake3_256>::new_simulated(10, test_options());
    let proof = example.prove();
    let mut root = example.root.root().to_elements();
    root[0] += BaseElement::ONE;
    let pub_inputs = PublicInputs {
        pub_key_root: root,
        num_pub_keys: example.ring_size(),
        tag: example.tag,
        eventid: example.eventid,
    };
    assert!(
        winterfell::verify::<RingSigAir, Blake3_256, DefaultRandomCoin<Blake3_256>>(
            proof, pub_inputs
        )
        .is_err()
    );
}

#[test]
fn simulated_path_matches_real_tree_format() {
    use winterfell::crypto::Hasher;

    let keys: Vec<[BaseElement; 2]> = (0..16u64)
        .map(|i| Rescue128::digest(&[BaseElement::from(i), BaseElement::ONE]).to_elements())
        .collect();
    let signer_idx = 5;
    let real = AggPublicKey::new(&keys, signer_idx);
    let path = real.get_leaf_path(signer_idx);
    assert_eq!(path.len(), 5);
    assert_eq!(path[0], Rescue128::digest(&keys[signer_idx]));

    // hashing the real path up the same way the simulated constructor does gives the real root
    let mut node = path[0];
    for (level, sibling) in path[1..].iter().enumerate() {
        node = if (signer_idx >> level) & 1 == 0 {
            Rescue128::merge(&[node, *sibling])
        } else {
            Rescue128::merge(&[*sibling, node])
        };
    }
    assert_eq!(node, real.root());

    let simulated = AggPublicKey::simulated(&keys[signer_idx], signer_idx, 4);
    let sim_path = simulated.get_leaf_path(signer_idx);
    assert_eq!(sim_path.len(), path.len());
    assert_eq!(sim_path[0], path[0]);
    assert_eq!(simulated.num_keys(), 16);
}
