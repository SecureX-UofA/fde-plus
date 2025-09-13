use std::fs::File;
use std::io::Write;

use ark_ec::{pairing::Pairing, Group, CurveGroup};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{test_rng, Zero, UniformRand};
use criterion::{criterion_group, criterion_main, Criterion};
use fde::commit::kzg::Powers;
use fde::encrypt::elgamal::MAX_BITS;
use fde::veck::kzg::elgamal::EncryptionProof;
use fde_plus::veck::compute_beta;

const N: usize = Scalar::MODULUS_BIT_SIZE as usize / MAX_BITS + 1;

type TestCurve = ark_bls12_381::Bls12_381;
type TestHash = sha3::Keccak256;
type Scalar = <TestCurve as Pairing>::ScalarField;
type UniPoly = DensePolynomial<Scalar>;
type Proof = fde::veck::kzg::elgamal::Proof<{ N }, TestCurve, TestHash>;
type ElgamalEncryptionProof = EncryptionProof<{ N }, TestCurve, TestHash>;

const SIZE_SUBSET: usize = 256;

fn bench_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("kzg-elgamal");
    group.sample_size(10);

    let rng = &mut test_rng();

    let encryption_sk = Scalar::rand(rng);
    let encryption_pk = (<TestCurve as Pairing>::G1::generator() * encryption_sk).into_affine();

    const UPPER_BOUND: usize = 22;

    // write powers to disk
    // let mut bytes = Vec::new();
    // powers.serialize_compressed(&mut bytes).unwrap();
    // let mut file = File::create("powers.bin").unwrap();
    // let _ = file.write_all(&bytes);

    println!("KZG setup...");
    let t_start = std::time::Instant::now();
    let bytes = std::fs::read("powers.bin").unwrap();
    let powers = Powers::deserialize_compressed(&*bytes)
        .unwrap();
    let elapsed = std::time::Instant::now().duration_since(t_start).as_secs();
    println!("KZG setup, elapsed time: {} [s]", elapsed);

    // let tau = Scalar::rand(rng);
    // let powers = Powers::<TestCurve>::unsafe_setup(tau, (1 << UPPER_BOUND).max(SIZE_SUBSET * 8) + 1);

    const LAMBDA: usize = 128;
    
    for i in 0..=UPPER_BOUND {
        let data_size = 1 << i;

        let (size_sr, m) = if SIZE_SUBSET > data_size {
            (data_size, data_size)
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
        let suffix = format!("l{}-m{}-rsr{}-sr{}", data_size, m, size_sr, SIZE_SUBSET);
        // let proof_enc_name = format!("proof-encryption-{}", suffix);
        // group.bench_function(&proof_enc_name, |b| {
        //     b.iter(|| {
        //         ElgamalEncryptionProof::new(&data, &encryption_pk, &powers, rng);
        //     })
        // });
        let encryption_proof = ElgamalEncryptionProof::new(&data, &encryption_pk, &powers, rng);

        let domain = GeneralEvaluationDomain::new(data_size).expect("valid domain");
        let index_map = fde::veck::index_map(domain);

        let evaluations = Evaluations::from_vec_and_domain(data[..data_size].to_vec(), domain);
        let f_poly: UniPoly = evaluations.interpolate_by_ref();
        let com_f_poly = powers.commit_g1(&f_poly);

        let subdomain = GeneralEvaluationDomain::new(size_sr).unwrap();
        let subset_indices = fde::veck::subset_indices(&index_map, &subdomain);
        let subset_evaluations = fde::veck::subset_evals(&evaluations, &subset_indices, subdomain);

        let f_s_poly: UniPoly = subset_evaluations.interpolate_by_ref();
        let com_f_s_poly = powers.commit_g1(&f_s_poly);

        let range_proof_name = format!("range-proof-{}", suffix);
        group.bench_function(&range_proof_name, |b| {
            let mut sub_encryption_proof = encryption_proof.subset(&subset_indices);
            b.iter(|| {
                sub_encryption_proof
                    .generate_range_proof(&subset_evaluations.evals, &powers);
            })
        });
        let mut sub_encryption_proof = encryption_proof.subset(&subset_indices);
        sub_encryption_proof
            .generate_range_proof(&subset_evaluations.evals, &powers);

        let ciphers = encryption_proof.ciphers.iter().map(|c| {
            c.c1()
        })
        .collect();

        let proof_prv_name = format!("proof-prove-{}", suffix);
        group.bench_function(&proof_prv_name, |b| {
            b.iter(|| {
                Proof::new_v2(
                    &f_poly,
                    &f_s_poly,
                    &encryption_sk,
                    sub_encryption_proof.clone(),
                    &ciphers,
                    &powers,
                    rng,
                )
                .unwrap();
            })
        });
        
        let proof_vfy_name = format!("proof-verify-{}", suffix);
        let (proof, challenge)  = Proof::new_v2(
            &f_poly,
            &f_s_poly,
            &encryption_sk,
            sub_encryption_proof.clone(),
            &ciphers,
            &powers,
            rng,
        )
        .unwrap();
        group.bench_function(&proof_vfy_name, |b| {
            b.iter(|| {
                assert!(proof
                    .verify_v2(com_f_poly, com_f_s_poly, encryption_pk, challenge, &powers)
                    .is_ok())
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_proof);
criterion_main!(benches);
