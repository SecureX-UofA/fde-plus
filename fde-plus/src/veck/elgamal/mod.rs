use std::{fs::File, io::Write};

use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fde::veck::kzg::elgamal::{EncryptionProof, Proof};

use crate::{Scalar, TestCurve, N, TestHash};

type KzgElgamalProof = Proof<{ N }, TestCurve, TestHash>;

type ElgamalEncryptionProof = EncryptionProof<{ N }, TestCurve, TestHash>;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct Storage {
    pub tau: Scalar,
    pub data: Vec<Scalar>,
    pub encryption: ElgamalEncryptionProof,
    pub sk: Scalar,
    pub pk: <TestCurve as Pairing>::G1Affine,
}

pub fn read_cipher_from(filename: &str)
    -> (Scalar, Vec<Scalar>, ElgamalEncryptionProof, Scalar, <TestCurve as Pairing>::G1Affine) {
        let bytes = std::fs::read(filename).unwrap();
        let storage = Storage::deserialize_compressed(&*bytes).unwrap();
        (storage.tau, storage.data, storage.encryption, storage.sk, storage.pk)
}

pub fn write_to_file(
    tau: Scalar,
    data: Vec<Scalar>,
    encryption: ElgamalEncryptionProof,
    sk: Scalar,
    pk: <TestCurve as Pairing>::G1Affine,
    filename: &str) -> std::io::Result<()> {
        let storage = Storage { tau, data, encryption, sk, pk };
        let mut bytes = Vec::new();
        storage.serialize_compressed(&mut bytes).unwrap();
        let mut file = File::create(filename)?;
        file.write_all(&bytes)?;
        Ok(())
}

#[cfg(test)]
pub mod test {
    use std::cmp::min;

    use ark_std::rand::{Rng, SeedableRng};
    use ark_ff::{PrimeField, BigInteger, Zero};
    use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};
    use ark_ec::{pairing::Pairing, Group, CurveGroup};
    use ark_std::{test_rng, UniformRand};
    use fde::{commit::kzg::Powers, veck::kzg::elgamal::Proof};
    use fde::encrypt::elgamal::MAX_BITS;

    use crate::{veck::{compute_beta, elgamal::{read_cipher_from, write_to_file, ElgamalEncryptionProof, KzgElgamalProof}}, Scalar, TestCurve, UniPoly};

    const DATA_SIZE: usize = 32;
    const SUBSET_SIZE: usize = 8;

    #[test]
    fn test_encryption() {
        let rng = &mut test_rng();
        let tau = Scalar::rand(rng);

        let encryption_sk = Scalar::rand(rng);
        let encryption_pk = (<TestCurve as Pairing>::G1::generator() * encryption_sk).into_affine();

        // beta
        // let beta = 1.5f64;
        // number of evaluations to sample
        // let m: usize = ((DATA_SIZE as f64 * beta).ceil() as usize).next_power_of_two();
        let m: usize = 64;

        let data: Vec<Scalar> = (0..m).map(|_| Scalar::rand(rng)).collect();

        let powers = Powers::<TestCurve>::unsafe_setup(tau, m + 1);

        let encryption = ElgamalEncryptionProof::new(&data, &encryption_pk, &powers, rng);

        write_to_file(tau, data.clone(), encryption.clone(), encryption_sk, encryption_pk, &"data.bin").unwrap();

        let (de_tau, de_data, de_encrypt, de_sk, de_pk) = read_cipher_from(&"data.bin");

        assert_eq!(tau, de_tau);
        assert_eq!(data, de_data);
        assert_eq!(encryption.ciphers, de_encrypt.ciphers);
        assert_eq!(encryption.short_ciphers, de_encrypt.short_ciphers);
        assert_eq!(encryption.random_encryption_points, de_encrypt.random_encryption_points);
        assert_eq!(encryption_sk, de_sk);
        assert_eq!(encryption_pk, de_pk);
    }

    #[test]
    fn test_read_storage() {
        let (tau, data, encryption_proof, sk, pk) = read_cipher_from(&"data.bin");

        println!("Completed setup");

        // beta
        let beta = 1.5f64;
        // number of evaluations to sample
        // let m: usize = ((DATA_SIZE as f64 * beta).ceil() as usize).next_power_of_two();
        let m: usize = 32;
        let m_domain = GeneralEvaluationDomain::new(m).expect("valid domain");

        let powers = Powers::<TestCurve>::unsafe_setup(tau, (m + 1).max(MAX_BITS * 4));

        // Interpolate original polynomial and compute its KZG commitment.
        // This is performed only once by the server
        let data = data[..m].to_vec();
        let m_evaluations = Evaluations::from_vec_and_domain(data, m_domain);
        let f_poly: UniPoly = m_evaluations.interpolate_by_ref();
        let com_f_poly = powers.commit_g1(&f_poly);

        let lambda = 128f64;
        let order_subset = min(SUBSET_SIZE + 1, (lambda / (beta - 1f64)).ceil() as usize);

        // let subdomain_size = order_subset.next_power_of_two();
        let subdomain_size = 16;

        // get subdomain with size suitable for interpolating a polynomial with SUBSET_SIZE
        // coefficients

        let index_map = fde::veck::index_map(m_domain);
        let subdomain = GeneralEvaluationDomain::new(subdomain_size).unwrap();
        let subset_indices = fde::veck::subset_indices(&index_map, &subdomain);
        let subset_evaluations = fde::veck::subset_evals(&m_evaluations, &subset_indices, subdomain);

        let rng = &mut test_rng();

        let f_s_poly: UniPoly = subset_evaluations.interpolate_by_ref();
        let com_f_s_poly = powers.commit_g1(&f_s_poly);

        let mut sub_encryption_proof = encryption_proof.subset(&subset_indices);
        sub_encryption_proof.generate_range_proof(&subset_evaluations.evals, &powers, rng);

        let proof = KzgElgamalProof::new(
            &f_poly,
            &f_s_poly,
            &sk,
            sub_encryption_proof,
            &powers,
            rng,
        )
        .unwrap();
        assert!(proof
            .verify(com_f_poly, com_f_s_poly, pk, &powers)
            .is_ok());
    }

    #[test]
    fn flow() {
        let rng = &mut test_rng();

        let tau = Scalar::rand(rng);
        let encryption_sk = Scalar::rand(rng);
        let encryption_pk = (<TestCurve as Pairing>::G1::generator() * encryption_sk).into_affine();

        const UPPER_BOUND: usize = 12;
        let powers = Powers::<TestCurve>::unsafe_setup(tau, (1 << UPPER_BOUND) * 8 + 1);

        const LAMBDA: usize = 128;
        const SIZE_SUBSET: usize = 1024;

        let data_size = 1024;

        let (size_sr, m) = if SIZE_SUBSET > data_size + 1 {
            (data_size + 1, data_size + 1)
        } else {
            let beta = compute_beta(SIZE_SUBSET, LAMBDA);
            let m = (data_size as f64 * beta).ceil() as usize;
            (SIZE_SUBSET, m)
        };

        let mut data: Vec<Scalar> = (0..m).map(|_| Scalar::rand(rng)).collect();
        let next_pow2 = m.next_power_of_two();

        let pad = next_pow2 - m;
        if pad > 0 {
            let pad_evals = vec![Scalar::zero(); pad];
            data.extend_from_slice(&pad_evals);
        }
        let t_start = std::time::Instant::now();
        println!("Generating encryption proofs ...");
        let encryption_proof = ElgamalEncryptionProof::new(&data, &encryption_pk, &powers, rng);
        let elapsed = std::time::Instant::now().duration_since(t_start).as_millis();
        println!("Generated encryption proofs, elapsed time: {} [ms]", elapsed);

        let domain = GeneralEvaluationDomain::new(next_pow2).expect("valid domain");
        let index_map = fde::veck::index_map(domain);

        let evaluations = Evaluations::from_vec_and_domain(data, domain);
        let f_poly: UniPoly = evaluations.interpolate_by_ref();
        let t_start = std::time::Instant::now();
        let com_f_poly = powers.commit_g1(&f_poly);
        let elapsed = std::time::Instant::now().duration_since(t_start).as_millis();
        println!("Commit to f, elapsed time: {} [ms]", elapsed);

        let subdomain = GeneralEvaluationDomain::new(size_sr).unwrap();
        let subset_indices = fde::veck::subset_indices(&index_map, &subdomain);
        let subset_evaluations = fde::veck::subset_evals(&evaluations, &subset_indices, subdomain);

        let f_s_poly: UniPoly = subset_evaluations.interpolate_by_ref();
        let com_f_s_poly = powers.commit_g1(&f_s_poly);

        let t_start = std::time::Instant::now();
        println!("Start generating range proof");
        let mut sub_encryption_proof = encryption_proof.subset(&subset_indices);
        sub_encryption_proof
                .generate_range_proof(&subset_evaluations.evals, &powers, rng);
        let elapsed = std::time::Instant::now().duration_since(t_start).as_secs();
        println!("Generate range proof, elapsed time: {} [s]", elapsed);

        let proof = Proof::new(
            &f_poly,
            &f_s_poly,
            &encryption_sk,
            sub_encryption_proof.clone(),
            &powers,
            rng,
        ).unwrap();
            
        let t_start = std::time::Instant::now();
        assert!(proof.verify(com_f_poly, com_f_s_poly, encryption_pk, &powers).is_ok());
        let elapsed = std::time::Instant::now().duration_since(t_start).as_secs();
        println!("Verifying proof, elapsed time: {} [s]", elapsed);
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
