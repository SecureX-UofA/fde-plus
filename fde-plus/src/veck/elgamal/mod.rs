mod encryption;

#[cfg(test)]
mod test {
    use std::cmp::min;
    use std::intrinsics::ceilf64;

    use ark_ff::PrimeField;
    use ark_ec::{pairing::Pairing, Group, CurveGroup};
    use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial};
    use ark_std::{test_rng, UniformRand};
    use fde::commit::kzg::Powers;
    use fde::encrypt::elgamal::MAX_BITS;
    use fde::hash::Hasher;
    use fde::veck::{subset_evals, subset_indices};

    use crate::veck::elgamal::encryption::EncryptionProof;
    use crate::tests::*;

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
        let m: usize = SUBSET_SIZE * beta as usize;

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

        let encryption_proof = ElgamalEncryptionProof::enc1(&sampled_evals, &encryption_pk, &powers, rng);

        let lambda = 128f64;
        let order_subset = min(SUBSET_SIZE + 1, (lambda / (beta - 1f64)).ceil() as usize);

        // Generate the random challenge subset
        let mut hasher = Hasher::<TestHash>::new();
        hasher.update(&com_f_poly);
        let hash_output = hasher.finalize();
        let challenge = <TestCurve as Pairing>::ScalarField::from_le_bytes_mod_order(&hash_output);


        // get subdomain with size suitable for interpolating a polynomial with SUBSET_SIZE
        // coefficients
        let subdomain = GeneralEvaluationDomain::new(order_subset).unwrap();
        let subset_indices = subset_indices(&index_map, &subdomain);
        let subset_evaluations = subset_evals(&evaluations, &subset_indices, subdomain);
        let f_s_poly: UniPoly = subset_evaluations.interpolate_by_ref();
        let com_f_s_poly = powers.commit_g1(&f_s_poly);

        // let sub_encryption_proof = encryption_proof.subset(&subset_indices);
    }
}
