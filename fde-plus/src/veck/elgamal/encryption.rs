use ark_ec::{pairing::Pairing, CurveGroup, AffineRepr};
use ark_std::rand::Rng;
use digest::Digest;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use fde::{commit::kzg::Powers, encrypt::{elgamal::{Cipher, ExponentialElgamal as Elgamal, SplitScalar, MAX_BITS}, EncryptionEngine}, range_proof::RangeProof};

#[derive(Clone)]
pub struct EncryptionProof<const N: usize, C: Pairing, D: Clone + Digest> {
    pub ciphers: Vec<Cipher<C::G1>>,
    pub short_ciphers: Vec<[Cipher<C::G1>; N]>,
    pub range_proofs: Vec<[RangeProof<C, D>; N]>,
    pub random_encryption_points: Vec<C::G1Affine>,
}

impl<const N: usize, C: Pairing, D: Clone + Digest + Send + Sync> EncryptionProof<N, C, D> {
    fn default() -> Self {
        Self {
            ciphers: Vec::new(),
            short_ciphers: Vec::new(),
            range_proofs: Vec::new(),
            random_encryption_points: Vec::new(),
        }
    }

    /// Exactly the same as `new` in the original code
    pub fn enc1<R: Rng + Send + Sync>(
        evaluations: &[C::ScalarField],
        encryption_pk: &<Elgamal<C::G1> as EncryptionEngine>::EncryptionKey,
        powers: &Powers<C>,
        _rng: &mut R,
    ) -> Self {
        #[cfg(not(feature = "parallel"))]
        let proof = evaluations.iter().fold(Self::default(), |acc, eval| {
            acc.append(eval, encryption_pk, powers, _rng)
        });

        #[cfg(feature = "parallel")]
        let proof = evaluations
            .par_iter()
            .fold(Self::default, |acc, eval| {
                let rng = &mut ark_std::rand::thread_rng();
                acc.append(eval, encryption_pk, powers, rng)
            })
            .reduce(Self::default, |acc, proof| acc.extend(proof));
        proof
    }

    pub fn enc2() {
    }

    fn append<R: Rng>(
        mut self,
        eval: &C::ScalarField,
        encryption_pk: &<Elgamal<C::G1> as EncryptionEngine>::EncryptionKey,
        powers: &Powers<C>,
        rng: &mut R,
    ) -> Self {
        let split_eval = SplitScalar::from(*eval);
        let rp = split_eval
            .splits()
            .map(|s| RangeProof::new(s, MAX_BITS, powers, rng).expect("invalid range proof input"));
        let (sc, rand) = split_eval.encrypt::<Elgamal<C::G1>, _>(encryption_pk, rng);
        let cipher = <Elgamal<C::G1> as EncryptionEngine>::encrypt_with_randomness(
            eval,
            encryption_pk,
            &rand,
        );
        self.random_encryption_points
            .push((C::G1Affine::generator() * rand).into_affine());
        self.ciphers.push(cipher);
        self.short_ciphers.push(sc);
        self.range_proofs.push(rp);
        self
    }

    fn extend(mut self, other: Self) -> Self {
        self.random_encryption_points
            .extend(other.random_encryption_points);
        self.ciphers.extend(other.ciphers);
        self.short_ciphers.extend(other.short_ciphers);
        self.range_proofs.extend(other.range_proofs);
        self
    }
}
