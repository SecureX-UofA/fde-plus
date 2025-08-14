pub use ark_bls12_381::{Bls12_381 as TestCurve, G1Affine};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use criterion as _;
pub use sha3::Keccak256 as TestHash;

pub const N: usize = Scalar::MODULUS_BIT_SIZE as usize / fde::encrypt::elgamal::MAX_BITS + 1;

pub type Scalar = <TestCurve as Pairing>::ScalarField;
pub type UniPoly = DensePolynomial<Scalar>;
