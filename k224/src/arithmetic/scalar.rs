mod wide;

use crate::ORDER;

use elliptic_curve::{
    bigint::{Word, U256},
    subtle::{Choice, ConstantTimeEq},
};

/// Constant representing the modulus
/// n = 00000001 00000000 00000000 00000000 0001DCE8 D2EC6184 CAF0A971 769FB1F7
const MODULUS: [Word; U256::LIMBS] = ORDER.to_words();

/// Scalars are elements in the finite field modulo n.
#[derive(Clone, Copy, Debug, Default, PartialOrd, Ord)]
pub struct Scalar(pub(crate) U256);

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&(other.0))
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Scalar {}
