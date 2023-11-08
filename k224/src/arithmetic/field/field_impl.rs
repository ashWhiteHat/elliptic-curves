use crate::FieldBytes;
use elliptic_curve::{
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq},
    zeroize::Zeroize,
};

use super::field_5x52::FieldElement5x52 as FieldElementUnsafeImpl;

#[derive(Clone, Copy, Debug)]
pub struct FieldElementImpl {
    value: FieldElementUnsafeImpl,
    magnitude: u32,
    normalized: bool,
}

impl FieldElementImpl {
    /// Additive identity.
    pub const ZERO: Self = Self {
        value: FieldElementUnsafeImpl::ZERO,
        magnitude: 1,
        normalized: true,
    };

    /// Multiplicative identity.
    pub const ONE: Self = Self {
        value: FieldElementUnsafeImpl::ONE,
        magnitude: 1,
        normalized: true,
    };

    const fn new_normalized(value: &FieldElementUnsafeImpl) -> Self {
        Self {
            value: *value,
            magnitude: 1,
            normalized: true,
        }
    }

    const fn new_weak_normalized(value: &FieldElementUnsafeImpl) -> Self {
        Self {
            value: *value,
            magnitude: 1,
            normalized: false,
        }
    }

    pub(crate) const fn from_bytes_unchecked(bytes: &[u8; 28]) -> Self {
        let value = FieldElementUnsafeImpl::from_bytes_unchecked(bytes);
        Self::new_normalized(&value)
    }

    pub fn to_bytes(self) -> FieldBytes {
        debug_assert!(self.normalized);
        self.value.to_bytes()
    }

    pub fn is_zero(&self) -> Choice {
        debug_assert!(self.normalized);
        self.value.is_zero()
    }

    pub fn is_odd(&self) -> Choice {
        debug_assert!(self.normalized);
        self.value.is_odd()
    }
}

impl Default for FieldElementImpl {
    fn default() -> Self {
        Self::ZERO
    }
}

impl ConditionallySelectable for FieldElementImpl {
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        // 1. It's debug only, so it shouldn't present a security risk
        // 2. Being normalized does is independent from the field element value;
        //    elements must be normalized explicitly.
        let new_normalized = if bool::from(choice) {
            b.normalized
        } else {
            a.normalized
        };
        Self {
            value: FieldElementUnsafeImpl::conditional_select(&(a.value), &(b.value), choice),
            magnitude: u32::conditional_select(&(a.magnitude), &(b.magnitude), choice),
            normalized: new_normalized,
        }
    }
}

impl ConstantTimeEq for FieldElementImpl {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.value.ct_eq(&(other.value))
            & self.magnitude.ct_eq(&(other.magnitude))
            // See the comment in `conditional_select()`
            & Choice::from((self.normalized == other.normalized) as u8)
    }
}

impl Zeroize for FieldElementImpl {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.magnitude.zeroize();
        self.normalized.zeroize();
    }
}
