//! A pure-Rust implementation of group operations on secp224k1.

pub(crate) mod affine;
mod field;

pub use field::FieldElement;
pub(crate) mod scalar;
