//! Field element modulo the curve internal modulus using 32-bit limbs.
//! Inspired by the implementation in <https://github.com/bitcoin-core/secp256k1>

use elliptic_curve::subtle::Choice;

/// Scalars modulo SECP256k1 modulus (2^224 - 2^32 - 2^12 - 2^11 - 2^9 - 2^7 - 2^4 - 2 - 1).
/// Uses 5 64-bit limbs (little-endian), where in the normalized form
/// first 4 contain 52 bits of the value each, and the last one contains 16 bits.
/// CurveArithmetic operations can be done without modulo reduction for some time,
/// using the remaining overflow bits.
#[derive(Clone, Copy, Debug)]
pub struct FieldElement5x52(pub(crate) [u64; 5]);

impl FieldElement5x52 {
    /// Additive identity.
    pub const ZERO: Self = Self([0, 0, 0, 0, 0]);

    /// Multiplicative identity.
    pub const ONE: Self = Self([1, 0, 0, 0, 0]);

    /// Determine if this `FieldElement5x52` is zero.
    ///
    /// # Returns
    ///
    /// If zero, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_zero(&self) -> Choice {
        Choice::from(((self.0[0] | self.0[1] | self.0[2] | self.0[3] | self.0[4]) == 0) as u8)
    }

    /// Determine if this `FieldElement5x52` is odd in the SEC1 sense: `self mod 2 == 1`.
    ///
    /// # Returns
    ///
    /// If odd, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_odd(&self) -> Choice {
        (self.0[0] as u8 & 1).into()
    }
}
