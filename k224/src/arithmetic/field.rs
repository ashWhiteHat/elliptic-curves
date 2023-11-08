//! Field arithmetic modulo p = 2^224 - 2^32 - 2^12 - 2^11 - 2^9 - 2^7 - 2^4 - 2 - 1
#![allow(clippy::assign_op_pattern, clippy::op_ref)]

mod field_5x52;
mod field_impl;

#[cfg(not(debug_assertions))]
use field_5x52::FieldElement5x52 as FieldElementImpl;
#[cfg(debug_assertions)]
use field_impl::FieldElementImpl;

use crate::FieldBytes;
use core::ops::{Add, AddAssign, Neg, Sub, SubAssign};
use elliptic_curve::{
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
};

/// An element in the finite field used for curve coordinates.
#[derive(Clone, Copy, Debug)]
pub struct FieldElement(FieldElementImpl);

impl FieldElement {
    /// Zero element.
    pub const ZERO: Self = Self(FieldElementImpl::ZERO);

    /// Multiplicative identity.
    pub const ONE: Self = Self(FieldElementImpl::ONE);

    /// Determine if this `FieldElement` is zero.
    ///
    /// # Returns
    ///
    /// If zero, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    /// Determine if this `FieldElement` is even in the SEC1 sense: `self mod 2 == 0`.
    ///
    /// # Returns
    ///
    /// If even, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_even(&self) -> Choice {
        !self.0.is_odd()
    }

    /// Determine if this `FieldElement` is odd in the SEC1 sense: `self mod 2 == 1`.
    ///
    /// # Returns
    ///
    /// If odd, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_odd(&self) -> Choice {
        self.0.is_odd()
    }

    /// Attempts to parse the given byte array as an SEC1-encoded field element.
    /// Does not check the result for being in the correct range.
    pub(crate) const fn from_bytes_unchecked(bytes: &[u8; 28]) -> Self {
        Self(FieldElementImpl::from_bytes_unchecked(bytes))
    }

    /// Attempts to parse the given byte array as an SEC1-encoded field element.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    pub fn from_bytes(bytes: &FieldBytes) -> CtOption<Self> {
        FieldElementImpl::from_bytes(bytes).map(Self)
    }

    /// Convert a `u64` to a field element.
    pub const fn from_u64(w: u64) -> Self {
        Self(FieldElementImpl::from_u64(w))
    }

    /// Returns -self, treating it as a value of given magnitude.
    /// The provided magnitude must be equal or greater than the actual magnitude of `self`.
    pub fn negate(&self, magnitude: u32) -> Self {
        Self(self.0.negate(magnitude))
    }

    /// Multiplies by a single-limb integer.
    /// Multiplies the magnitude by the same value.
    pub fn mul_single(&self, rhs: u32) -> Self {
        Self(self.0.mul_single(rhs))
    }
}

impl ConditionallySelectable for FieldElement {
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(FieldElementImpl::conditional_select(&(a.0), &(b.0), choice))
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&(other.0))
    }
}

impl Default for FieldElement {
    fn default() -> Self {
        Self::ZERO
    }
}

impl DefaultIsZeroes for FieldElement {}

impl Eq for FieldElement {}

impl From<u64> for FieldElement {
    fn from(k: u64) -> Self {
        Self(FieldElementImpl::from_u64(k))
    }
}

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&(other.0)).into()
    }
}

impl Add<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn add(self, other: FieldElement) -> FieldElement {
        FieldElement(self.0.add(&(other.0)))
    }
}

impl Add<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn add(self, other: &FieldElement) -> FieldElement {
        FieldElement(self.0.add(&(other.0)))
    }
}

impl Add<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn add(self, other: &FieldElement) -> FieldElement {
        FieldElement(self.0.add(&(other.0)))
    }
}

impl AddAssign<FieldElement> for FieldElement {
    fn add_assign(&mut self, other: FieldElement) {
        *self = *self + &other;
    }
}

impl AddAssign<&FieldElement> for FieldElement {
    fn add_assign(&mut self, other: &FieldElement) {
        *self = *self + other;
    }
}

impl Sub<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn sub(self, other: FieldElement) -> FieldElement {
        self + -other
    }
}

impl Sub<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn sub(self, other: &FieldElement) -> FieldElement {
        self + -other
    }
}

impl SubAssign<FieldElement> for FieldElement {
    fn sub_assign(&mut self, other: FieldElement) {
        *self = *self + -other;
    }
}

impl SubAssign<&FieldElement> for FieldElement {
    fn sub_assign(&mut self, other: &FieldElement) {
        *self = *self + -other;
    }
}

impl Neg for FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        self.negate(1)
    }
}

impl Neg for &FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        self.negate(1)
    }
}
