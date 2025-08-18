use std::collections::HashSet;

use ark_ff::FftField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::{collections::HashMap, rand::{rngs::StdRng, Rng}};

pub mod elgamal;

/// Maps the evaluation domain elements (roots of unity - keys) to their respective index (value) in the FFT domain.
pub fn index_map<S: FftField>(domain: GeneralEvaluationDomain<S>) -> HashMap<S, usize> {
    domain.elements().enumerate().map(|(i, e)| (e, i)).collect()
}

pub fn random_subset_indices<S: FftField>(
    domain: &GeneralEvaluationDomain<S>,
    subset_size: usize,
    rng: &mut StdRng,
) -> Vec<usize> {
    let mut index_set = HashSet::<usize>::new();
    for _ in 0..subset_size {
        let mut index = rng.gen_range(0..domain.size());
        while index_set.contains(&index) {
            index = rng.gen_range(0..domain.size());
        }
        index_set.insert(index);
    }
    
    index_set.into_iter().collect()
}

#[cfg(test)]
mod test {
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
    use ark_ec::{bls12::Bls12, pairing::Pairing};
    use ark_std::{test_rng, rand::SeedableRng};
    use ark_bls12_381::Bls12_381;
    use ark_ff::{UniformRand, PrimeField, BigInteger};

    use crate::veck::random_subset_indices;

    #[test]
    fn test_random_subset_indices() {
        let mut rng = test_rng();
        let challenge = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
        let seed_vec = challenge.into_bigint().to_bytes_be();
        let mut seed_bytes = [0u8; 32];
        let bytes = &seed_vec;
        let len = bytes.len().min(32);
        seed_bytes[..len].copy_from_slice(&seed_vec[..len]);

        let mut rng = ark_std::rand::rngs::StdRng::from_seed(seed_bytes);
        let domain = GeneralEvaluationDomain::<<Bls12<ark_bls12_381::Config> as Pairing>::ScalarField>::new(16).unwrap();
        let indices = random_subset_indices(&domain, 8, &mut rng);
        println!("Random subset indices: {:?}", indices);
    }
}
