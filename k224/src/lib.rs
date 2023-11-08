#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

//! ## `serde` support
//!
//! When the `serde` feature of this crate is enabled, `Serialize` and
//! `Deserialize` are impl'd for the following types:
//!
//! - [`AffinePoint`]
//! - [`Scalar`]
//! - [`ecdsa::VerifyingKey`]
//!
//! Please see type-specific documentation for more information.

mod arithmetic;

pub use arithmetic::FieldElement;

pub use elliptic_curve;

use elliptic_curve::{
    consts::{U28, U29},
    generic_array::GenericArray,
    FieldBytesEncoding,
};

#[cfg(target_pointer_width = "32")]
pub use elliptic_curve::bigint::U224 as Uint;

#[cfg(target_pointer_width = "64")]
use elliptic_curve::bigint::U256 as Uint;

/// Order of the secp224k1 elliptic curve in hexadecimal.
#[cfg(any(target_pointer_width = "32", feature = "arithmetic"))]
const ORDER_HEX: &str = "10000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7";

/// secp224k1 (K-224) elliptic curve.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct Secp224k1;

impl elliptic_curve::Curve for Secp224k1 {
    /// 28-byte serialized field elements.
    type FieldBytesSize = U28;

    /// Big integer type used for representing field elements.
    type Uint = Uint;

    /// Order of NIST P-224's elliptic curve group (i.e. scalar modulus).
    #[cfg(target_pointer_width = "32")]
    const ORDER: Uint = Uint::from_be_hex(ORDER_HEX);

    /// Order of NIST P-224's elliptic curve group (i.e. scalar modulus).
    #[cfg(target_pointer_width = "64")]
    const ORDER: Uint =
        Uint::from_be_hex("000000010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7");
}

impl elliptic_curve::PrimeCurve for Secp224k1 {}

/// Compressed SEC1-encoded secp224k1 (k-224) curve point.
pub type CompressedPoint = GenericArray<u8, U29>;

/// secp224k1 (K-224) field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<Secp224k1>;

impl FieldBytesEncoding<Secp224k1> for Uint {}

/// secp224k1 (K-224) secret key.
pub type SecretKey = elliptic_curve::SecretKey<Secp224k1>;
