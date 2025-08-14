use ark_ff::FftField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::collections::HashMap;

pub mod elgamal;

/// Maps the evaluation domain elements (roots of unity - keys) to their respective index (value) in the FFT domain.
pub fn index_map<S: FftField>(domain: GeneralEvaluationDomain<S>) -> HashMap<S, usize> {
    domain.elements().enumerate().map(|(i, e)| (e, i)).collect()
}
