//! Wide scalar (64-bit limbs)

use super::{Scalar, MODULUS};
use crate::ORDER;
use elliptic_curve::bigint::U512;

/// Limbs of 2^256 minus the secp224k1 order.
const NEG_MODULUS: [u64; 4] = [!MODULUS[0] + 1, !MODULUS[1], !MODULUS[2], !MODULUS[3]];

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct WideScalar(pub(super) U512);

impl WideScalar {
    pub const fn from_bytes(bytes: &[u8; 64]) -> Self {
        Self(U512::from_be_slice(bytes))
    }
}
