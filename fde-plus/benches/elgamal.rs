use ark_ec::{pairing::Pairing, Group, CurveGroup};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};
use ark_std::{test_rng, Zero, UniformRand};
use criterion::{criterion_group, criterion_main, Criterion};
use fde::commit::kzg::Powers;
use fde::encrypt::elgamal::MAX_BITS;
use fde::veck::kzg::elgamal::EncryptionProof;

const N: usize = Scalar::MODULUS_BIT_SIZE as usize / fde::encrypt::elgamal::MAX_BITS + 1;

type TestCurve = ark_bls12_381::Bls12_381;
type TestHash = sha3::Keccak256;
type Scalar = <TestCurve as Pairing>::ScalarField;
type UniPoly = DensePolynomial<Scalar>;
type Proof = fde::veck::kzg::elgamal::Proof<{ N }, TestCurve, TestHash>;
type ElgamalEncryptionProof = EncryptionProof<{ N }, TestCurve, TestHash>;

fn bench_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("kzg-elgamal");
    group.sample_size(10);

    let rng = &mut test_rng();

    let tau = Scalar::rand(rng);
    let encryption_sk = Scalar::rand(rng);
    let encryption_pk = (<TestCurve as Pairing>::G1::generator() * encryption_sk).into_affine();

    let m = 48usize;
    let mut data: Vec<Scalar> = (0..m).map(|_| Scalar::rand(rng)).collect();
    let next_pow2 = m.next_power_of_two();

    let powers = Powers::<TestCurve>::unsafe_setup(tau, (next_pow2 + 1).max(MAX_BITS * 4));

    let pad = next_pow2 - m;
    if pad > 0 {
        let pad_evals = vec![Scalar::zero(); pad];
        data.extend_from_slice(&pad_evals);
    }
    let encryption_proof = ElgamalEncryptionProof::new(&data, &encryption_pk, &powers, rng);

    let domain = GeneralEvaluationDomain::new(next_pow2).expect("valid domain");
    let index_map = fde::veck::index_map(domain);

    let evaluations = Evaluations::from_vec_and_domain(data, domain);
    let f_poly: UniPoly = evaluations.interpolate_by_ref();
    let com_f_poly = powers.commit_g1(&f_poly);

    for i in 4..=5 {
        let size_sr = 1 << i;
        let proof_prv_name = format!("proof-prove-{}", size_sr);
        let range_proof_name = format!("range-proof-{}", size_sr);
        let proof_vfy_name = format!("proof-verify-{}", size_sr);

        let subdomain = GeneralEvaluationDomain::new(size_sr).unwrap();
        let subset_indices = fde::veck::subset_indices(&index_map, &subdomain);
        let subset_evaluations = fde::veck::subset_evals(&evaluations, &subset_indices, subdomain);

        let f_s_poly: UniPoly = subset_evaluations.interpolate_by_ref();
        let com_f_s_poly = powers.commit_g1(&f_s_poly);

        let mut sub_encryption_proof = encryption_proof.subset(&subset_indices);

        group.bench_function(&proof_prv_name, |b| {
            b.iter(|| {
                Proof::new(
                    &f_poly,
                    &f_s_poly,
                    &encryption_sk,
                    sub_encryption_proof.clone(),
                    &powers,
                    rng,
                )
                .unwrap();
            })
        });

        group.bench_function(&range_proof_name, |b| {
            b.iter(|| {
                sub_encryption_proof
                    .generate_range_proof(&subset_evaluations.evals, &powers, rng);
            })
        });

        group.bench_function(&proof_vfy_name, |b| {
            let proof = Proof::new(
                &f_poly,
                &f_s_poly,
                &encryption_sk,
                sub_encryption_proof.clone(),
                &powers,
                rng,
            )
            .unwrap();
            sub_encryption_proof
                .generate_range_proof(&subset_evaluations.evals, &powers, rng);
            b.iter(|| {
                assert!(proof
                    .verify(com_f_poly, com_f_s_poly, encryption_pk, &powers)
                    .is_ok())
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_proof);
criterion_main!(benches);
