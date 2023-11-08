//! Field element modulo the curve internal modulus using 32-bit limbs.
//! Inspired by the implementation in <https://github.com/bitcoin-core/secp256k1>

use crate::FieldBytes;
use elliptic_curve::{
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq},
    zeroize::Zeroize,
};

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

    /// Attempts to parse the given byte array as an SEC1-encoded field element.
    /// Does not check the result for being in the correct range.
    pub(crate) const fn from_bytes_unchecked(bytes: &[u8; 28]) -> Self {
        let w0 = (bytes[27] as u64)
            | ((bytes[26] as u64) << 8)
            | ((bytes[25] as u64) << 16)
            | ((bytes[24] as u64) << 24)
            | ((bytes[23] as u64) << 32)
            | ((bytes[22] as u64) << 40)
            | (((bytes[21] & 0xFu8) as u64) << 48);

        let w1 = ((bytes[21] >> 4) as u64)
            | ((bytes[20] as u64) << 4)
            | ((bytes[19] as u64) << 12)
            | ((bytes[18] as u64) << 20)
            | ((bytes[17] as u64) << 28)
            | ((bytes[16] as u64) << 36)
            | ((bytes[15] as u64) << 44);

        let w2 = (bytes[14] as u64)
            | ((bytes[13] as u64) << 8)
            | ((bytes[12] as u64) << 16)
            | ((bytes[11] as u64) << 24)
            | ((bytes[10] as u64) << 32)
            | ((bytes[9] as u64) << 40)
            | (((bytes[8] & 0xFu8) as u64) << 48);

        let w3 = ((bytes[8] >> 4) as u64)
            | ((bytes[7] as u64) << 4)
            | ((bytes[6] as u64) << 12)
            | ((bytes[5] as u64) << 20)
            | ((bytes[4] as u64) << 28)
            | ((bytes[3] as u64) << 36)
            | ((bytes[2] as u64) << 44);

        let w4 = (bytes[1] as u64) | ((bytes[0] as u64) << 8);

        Self([w0, w1, w2, w3, w4])
    }

    pub const fn from_u64(val: u64) -> Self {
        let w0 = val & 0xFFFFFFFFFFFFF;
        let w1 = val >> 52;
        Self([w0, w1, 0, 0, 0])
    }

    /// Returns the SEC1 encoding of this field element.
    pub fn to_bytes(self) -> FieldBytes {
        let mut ret = FieldBytes::default();
        ret[0] = (self.0[4] >> 8) as u8;
        ret[1] = self.0[4] as u8;
        ret[2] = (self.0[3] >> 44) as u8;
        ret[3] = (self.0[3] >> 36) as u8;
        ret[4] = (self.0[3] >> 28) as u8;
        ret[5] = (self.0[3] >> 20) as u8;
        ret[6] = (self.0[3] >> 12) as u8;
        ret[7] = (self.0[3] >> 4) as u8;
        ret[8] = ((self.0[2] >> 48) as u8 & 0xFu8) | ((self.0[3] as u8 & 0xFu8) << 4);
        ret[9] = (self.0[2] >> 40) as u8;
        ret[10] = (self.0[2] >> 32) as u8;
        ret[11] = (self.0[2] >> 24) as u8;
        ret[12] = (self.0[2] >> 16) as u8;
        ret[13] = (self.0[2] >> 8) as u8;
        ret[14] = self.0[2] as u8;
        ret[15] = (self.0[1] >> 44) as u8;
        ret[16] = (self.0[1] >> 36) as u8;
        ret[17] = (self.0[1] >> 28) as u8;
        ret[18] = (self.0[1] >> 20) as u8;
        ret[19] = (self.0[1] >> 12) as u8;
        ret[20] = (self.0[1] >> 4) as u8;
        ret[21] = ((self.0[0] >> 48) as u8 & 0xFu8) | ((self.0[1] as u8 & 0xFu8) << 4);
        ret[22] = (self.0[0] >> 40) as u8;
        ret[23] = (self.0[0] >> 32) as u8;
        ret[24] = (self.0[0] >> 24) as u8;
        ret[25] = (self.0[0] >> 16) as u8;
        ret[26] = (self.0[0] >> 8) as u8;
        ret[27] = self.0[0] as u8;
        ret
    }

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

    /// Returns self + rhs mod p.
    /// Sums the magnitudes.
    pub const fn add(&self, rhs: &Self) -> Self {
        Self([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
        ])
    }

    /// Multiplies by a single-limb integer.
    /// Multiplies the magnitude by the same value.
    pub const fn mul_single(&self, rhs: u32) -> Self {
        let rhs_u64 = rhs as u64;
        Self([
            self.0[0] * rhs_u64,
            self.0[1] * rhs_u64,
            self.0[2] * rhs_u64,
            self.0[3] * rhs_u64,
            self.0[4] * rhs_u64,
        ])
    }
}

impl Default for FieldElement5x52 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl ConditionallySelectable for FieldElement5x52 {
    #[inline(always)]
    fn conditional_select(
        a: &FieldElement5x52,
        b: &FieldElement5x52,
        choice: Choice,
    ) -> FieldElement5x52 {
        FieldElement5x52([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
            u64::conditional_select(&a.0[4], &b.0[4], choice),
        ])
    }
}

impl ConstantTimeEq for FieldElement5x52 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
            & self.0[4].ct_eq(&other.0[4])
    }
}

impl Zeroize for FieldElement5x52 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
