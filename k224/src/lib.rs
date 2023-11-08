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

pub use elliptic_curve::{self, bigint::U256};

use elliptic_curve::{
    consts::{U28, U29},
    generic_array::GenericArray,
    FieldBytesEncoding,
};

/// Order of the secp224k1 elliptic curve in hexadecimal.
const ORDER_HEX: &str = "000000010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7";

/// Order of the secp224k1 elliptic curve.
const ORDER: U256 = U256::from_be_hex(ORDER_HEX);

/// secp224k1 (K-224) elliptic curve.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct Secp224k1;

impl elliptic_curve::Curve for Secp224k1 {
    /// 28-byte serialized field elements.
    type FieldBytesSize = U28;

    /// 256-bit field modulus.
    type Uint = U256;

    /// Curve order.
    const ORDER: U256 = ORDER;
}

impl elliptic_curve::PrimeCurve for Secp224k1 {}

/// Compressed SEC1-encoded secp224k1 (k-224) curve point.
pub type CompressedPoint = GenericArray<u8, U29>;

/// secp224k1 (K-224) field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<Secp224k1>;

impl FieldBytesEncoding<Secp224k1> for U256 {}

/// secp224k1 (K-224) secret key.
pub type SecretKey = elliptic_curve::SecretKey<Secp224k1>;
