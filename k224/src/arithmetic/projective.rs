//! Projective points

#![allow(clippy::op_ref)]
use super::{AffinePoint, FieldElement};

use elliptic_curve::{
    group::prime::PrimeCurveAffine,
    subtle::{Choice, ConditionallySelectable},
};

/// A point on the secp224k1 curve in projective coordinates.
#[derive(Clone, Copy, Debug)]
pub struct ProjectivePoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
}

impl ProjectivePoint {
    /// Additive identity of the group: the point at infinity.
    pub const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ZERO,
    };

    /// Base point of secp256k1.
    pub const GENERATOR: Self = Self {
        x: AffinePoint::GENERATOR.x,
        y: AffinePoint::GENERATOR.y,
        z: FieldElement::ONE,
    };
}

impl From<AffinePoint> for ProjectivePoint {
    fn from(p: AffinePoint) -> Self {
        let projective = ProjectivePoint {
            x: p.x,
            y: p.y,
            z: FieldElement::ONE,
        };
        Self::conditional_select(&projective, &Self::IDENTITY, p.is_identity())
    }
}

impl ConditionallySelectable for ProjectivePoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ProjectivePoint {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
        }
    }
}
