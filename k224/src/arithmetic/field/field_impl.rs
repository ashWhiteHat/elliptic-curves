use crate::FieldBytes;
use elliptic_curve::subtle::Choice;

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

    pub fn is_zero(&self) -> Choice {
        debug_assert!(self.normalized);
        self.value.is_zero()
    }

    pub fn is_odd(&self) -> Choice {
        debug_assert!(self.normalized);
        self.value.is_odd()
    }
}
