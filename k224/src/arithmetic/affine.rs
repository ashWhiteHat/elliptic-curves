//! Affine points

#![allow(clippy::op_ref)]

use super::{FieldElement, ProjectivePoint, Scalar};
use crate::FieldBytes;
use core::ops::{Mul, Neg};
use elliptic_curve::{
    group::{prime::PrimeCurveAffine, GroupEncoding},
    point::{AffineCoordinates, DecompactPoint, DecompressPoint},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq},
    zeroize::DefaultIsZeroes,
};

/// secp224k1 curve point expressed in affine coordinates.
///
/// # `serde` support
///
/// When the `serde` feature of this crate is enabled, the `Serialize` and
/// `Deserialize` traits are impl'd for this type.
///
/// The serialization uses the [SEC1] `Elliptic-Curve-Point-to-Octet-String`
/// encoding, serialized as binary.
///
/// When serialized with a text-based format, the SEC1 representation is
/// subsequently hex encoded.
///
/// [SEC1]: https://www.secg.org/sec1-v2.pdf
#[derive(Clone, Copy, Debug)]
pub struct AffinePoint {
    /// x-coordinate
    pub(crate) x: FieldElement,

    /// y-coordinate
    pub(crate) y: FieldElement,

    /// Is this point the point at infinity? 0 = no, 1 = yes
    ///
    /// This is a proxy for [`Choice`], but uses `u8` instead to permit `const`
    /// constructors for `IDENTITY` and `GENERATOR`.
    pub(super) infinity: u8,
}

impl AffinePoint {
    /// Additive identity of the group: the point at infinity.
    pub const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ZERO,
        infinity: 1,
    };

    /// Base point of secp224k1.
    ///
    /// ```text
    /// Gₓ = a1455b33 4df099df 30fc28a1 69a467e9 e47075a9 0f7e650e b6b7a45c
    /// Gᵧ = 7e089fed 7fba3442 82cafbd6 f7e319f7 c0b0bd59 e2ca4bdb 556d61a5
    /// ```
    pub const GENERATOR: Self = Self {
        x: FieldElement::from_bytes_unchecked(&[
            0xa1, 0x45, 0x5b, 0x33, 0x4d, 0xf0, 0x99, 0xdf, 0x30, 0xfc, 0x28, 0xa1, 0x69, 0xa4,
            0x67, 0xe9, 0xe4, 0x70, 0x75, 0xa9, 0x0f, 0x7e, 0x65, 0x0e, 0xb6, 0xb7, 0xa4, 0x5c,
        ]),
        y: FieldElement::from_bytes_unchecked(&[
            0x7e, 0x08, 0x9f, 0xed, 0x7f, 0xba, 0x34, 0x42, 0x82, 0xca, 0xfb, 0xd6, 0xf7, 0xe3,
            0x19, 0xf7, 0xc0, 0xb0, 0xbd, 0x59, 0xe2, 0xca, 0x4b, 0xdb, 0x55, 0x6d, 0x61, 0xa5,
        ]),
        infinity: 0,
    };
}

impl AffinePoint {
    /// Create a new [`AffinePoint`] with the given coordinates.
    pub(crate) const fn new(x: FieldElement, y: FieldElement) -> Self {
        Self { x, y, infinity: 0 }
    }
}

impl PrimeCurveAffine for AffinePoint {
    type Scalar = Scalar;
    type Curve = ProjectivePoint;

    /// Returns the identity of the group: the point at infinity.
    fn identity() -> Self {
        Self::IDENTITY
    }

    /// Returns the base point of secp256k1.
    fn generator() -> Self {
        Self::GENERATOR
    }

    /// Is this point the identity point?
    fn is_identity(&self) -> Choice {
        Choice::from(self.infinity)
    }

    /// Convert to curve representation.
    fn to_curve(&self) -> ProjectivePoint {
        ProjectivePoint::from(*self)
    }
}

impl ConditionallySelectable for AffinePoint {
    fn conditional_select(a: &AffinePoint, b: &AffinePoint, choice: Choice) -> AffinePoint {
        AffinePoint {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            infinity: u8::conditional_select(&a.infinity, &b.infinity, choice),
        }
    }
}

impl Default for AffinePoint {
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl DefaultIsZeroes for AffinePoint {}

impl PartialEq for AffinePoint {
    fn eq(&self, other: &AffinePoint) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for AffinePoint {}

impl Mul<Scalar> for AffinePoint {
    type Output = ProjectivePoint;

    fn mul(self, scalar: Scalar) -> ProjectivePoint {
        ProjectivePoint::from(self) * scalar
    }
}

impl Mul<&Scalar> for AffinePoint {
    type Output = ProjectivePoint;

    fn mul(self, scalar: &Scalar) -> ProjectivePoint {
        ProjectivePoint::from(self) * scalar
    }
}
