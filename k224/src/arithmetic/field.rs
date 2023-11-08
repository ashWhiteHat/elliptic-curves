//! Field arithmetic modulo p = 2^224 - 2^32 - 2^12 - 2^11 - 2^9 - 2^7 - 2^4 - 2 - 1
#![allow(clippy::assign_op_pattern, clippy::op_ref)]

mod field_5x52;
mod field_impl;

#[cfg(not(debug_assertions))]
use field_5x52::FieldElement5x52 as FieldElementImpl;
#[cfg(debug_assertions)]
use field_impl::FieldElementImpl;

use crate::FieldBytes;
use elliptic_curve::subtle::{Choice, CtOption};

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
}
