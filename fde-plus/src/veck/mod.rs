use std::collections::HashSet;

use ark_ff::FftField;
use ark_poly::{EvaluationDomain, univariate::SparsePolynomial, GeneralEvaluationDomain};
use ark_std::{collections::HashMap, rand::{rngs::StdRng, Rng}, One};

pub mod elgamal;

/// Maps the evaluation domain elements (roots of unity - keys) to their respective index (value) in the FFT domain.
pub fn index_map<S: FftField>(domain: GeneralEvaluationDomain<S>) -> HashMap<S, usize> {
    domain.elements().enumerate().map(|(i, e)| (e, i)).collect()
}

pub fn random_subset_indices(
    evals_len: usize,
    subset_size: usize,
    rng: &mut StdRng,
) -> Vec<usize> {
    let mut index_set = HashSet::<usize>::new();
    for _ in 0..subset_size {
        let mut index = rng.gen_range(0..evals_len);
        while index_set.contains(&index) {
            index = rng.gen_range(0..evals_len);
        }
        index_set.insert(index);
    }
    
    index_set.into_iter().collect::<Vec<usize>>()
}

pub fn to_vanishing_poly<S: FftField>(
    indics: Vec<usize>,
    domain: GeneralEvaluationDomain<S>,
) -> SparsePolynomial<S> {
    let mut poly = SparsePolynomial::from_coefficients_vec(vec![(0, S::one())]);
    for i in indics {
        let root = domain.element(i);
        let x_minus_root = SparsePolynomial::from_coefficients_vec(vec![
                (0, S::zero() - root), 
                (1, S::one()),
            ]);
        poly = poly.mul(&x_minus_root);
    }
    poly
}

pub fn compute_beta(size_sr: usize, lambda: usize) -> f64 {
    let lower_power = (lambda as f64) / (size_sr as f64);
    let upper_power = (lambda as f64) / ((size_sr - 1) as f64);
    let two_lower_power = 2f64.powf(lower_power);
    let two_upper_power = 2f64.powf(upper_power);
    let beta1 = two_lower_power / (2f64 - two_lower_power);
    let beta2 = two_upper_power / (2f64 - two_upper_power);
    (beta1 + beta2) / 2f64
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
        let indices = random_subset_indices(domain.size(), 8, &mut rng);
        println!("Random subset indices: {:?}", indices);
    }

    #[test]
    fn test_compute_beta() {
        for i in 8..=20 {
            let size_sr = 1 << i;
            let beta = super::compute_beta(size_sr, 128);
            println!("size_sr: {}, beta: {}", size_sr, beta);

            let denominator = (beta * 2f64 / (beta + 1f64)).log2();
            let sr = (128f64 / denominator).ceil() as usize;
            println!("size_sr: {}, computed_sr: {}", size_sr, sr);
            assert_eq!(size_sr, sr);
        }
    }
}
