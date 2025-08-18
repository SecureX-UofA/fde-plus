#[cfg(test)]
mod test {
    use std::cmp::min;

    use ark_ff::{PrimeField, BigInteger};
    use ark_ec::{pairing::Pairing, Group, CurveGroup};
    use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial};
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::{Rng, SeedableRng};
    use ark_std::{test_rng, UniformRand};
    use fde::commit::kzg::Powers;
    use fde::encrypt::elgamal::MAX_BITS;
    use fde::hash::Hasher;
    use fde::veck::kzg::elgamal::{EncryptionProof, Proof};
    use fde::veck::subset_evals;

    use crate::tests::*;
    use crate::veck::random_subset_indices;

    type ElgamalEncryptionProof = EncryptionProof<{ N }, TestCurve, TestHash>;
    type KzgElgamalProof = Proof<{ N }, TestCurve, TestHash>;

    const DATA_SIZE: usize = 16;
    const SUBSET_SIZE: usize = 8;

    #[test]
    fn flow() {
        // KZG setup simulation
        let rng = &mut test_rng();
        let tau = Scalar::rand(rng);
        let powers = Powers::<TestCurve>::unsafe_setup(tau, (DATA_SIZE + 1).max(MAX_BITS * 4));

        // Server's encryption key for this session
        let encryption_sk = Scalar::rand(rng);
        let encryption_pk = (<TestCurve as Pairing>::G1::generator() * encryption_sk).into_affine();

        // beta
        let beta = 1.5f64;
        // number of evaluations to sample
        let m: usize = DATA_SIZE * beta as usize;

        // Generate random data and public inputs (encrypted data, etc)
        let data: Vec<Scalar> = (0..DATA_SIZE).map(|_| Scalar::rand(rng)).collect();

        let domain = GeneralEvaluationDomain::new(m).expect("valid domain");
        let index_map = crate::veck::index_map(domain);

        // Interpolate original polynomial and compute its KZG commitment.
        // This is performed only once by the server
        let evaluations = Evaluations::from_vec_and_domain(data, domain);
        let f_poly: UniPoly = evaluations.interpolate_by_ref();
        let com_f_poly = powers.commit_g1(&f_poly);

        // Sample m evaluations from the polynomial
        let sampled_evals = (0..m)
            .map(| i | {
                let x = domain.element(i);
                f_poly.evaluate(&x)
            })
            .collect::<Vec<Scalar>>();

        let encryption_proof = ElgamalEncryptionProof::new(&sampled_evals, &encryption_pk, &powers, rng);

        let lambda = 128f64;
        let order_subset = min(SUBSET_SIZE + 1, (lambda / (beta - 1f64)).ceil() as usize);

        let subdomain_size = order_subset.next_power_of_two();

        // Generate the random challenge subset
        let mut hasher = Hasher::<TestHash>::new();
        hasher.update(&com_f_poly);
        let hash_output = hasher.finalize();
        let challenge = <TestCurve as Pairing>::ScalarField::from_le_bytes_mod_order(&hash_output);
        let seed_vec = challenge.into_bigint().to_bytes_be();
        let mut seed_bytes = [0u8; 32];
        let bytes = &seed_vec;
        let len = bytes.len().min(32);
        seed_bytes[..len].copy_from_slice(&seed_vec[..len]);
        let mut r_set_rng = StdRng::from_seed(seed_bytes);
        let r_set_indices = random_subset_indices(&domain, subdomain_size, &mut r_set_rng);

        // get subdomain with size suitable for interpolating a polynomial with SUBSET_SIZE
        // coefficients
        let subdomain = GeneralEvaluationDomain::new(subdomain_size).unwrap();
        let subset_evaluations = subset_evals(&evaluations, &r_set_indices, subdomain);
        let f_s_poly: UniPoly = subset_evaluations.interpolate_by_ref();
        let com_f_s_poly = powers.commit_g1(&f_s_poly);

        let sub_encryption_proof = encryption_proof.subset(&r_set_indices);

        let proof = KzgElgamalProof::new(
            &f_poly,
            &f_s_poly,
            &encryption_sk,
            sub_encryption_proof,
            &powers,
            rng,
        )
        .unwrap();
        assert!(proof
            .verify(com_f_poly, com_f_s_poly, encryption_pk, &powers)
            .is_ok());
    }

    #[test]
    fn test_rand() {
        let mut rng = test_rng();
        let challenge = <TestCurve as Pairing>::ScalarField::rand(&mut rng);
        let seed_vec = challenge.into_bigint().to_bytes_be();
        let mut seed_bytes = [0u8; 32];
        let bytes = &seed_vec;
        let len = bytes.len().min(32);
        seed_bytes[..len].copy_from_slice(&seed_vec[..len]);
        
        for _ in 0..10 {
            let mut rng = ark_std::rand::rngs::StdRng::from_seed(seed_bytes);
            for i in 0..4 {
                let random_value: u64 = rng.r#gen();
                println!("Random value - {}: {}", i, random_value);
            }
            println!("---");
        }
    }
}
