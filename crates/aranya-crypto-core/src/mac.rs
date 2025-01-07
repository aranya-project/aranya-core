//! Message Authentication Codes.
//!
//! # Warning
//!
//! This is a low-level module. You should not be using it
//! directly unless you are implementing an engine.

use core::{
    array::TryFromSliceError,
    fmt::{self, Debug},
    num::NonZeroU16,
    result::Result,
};

use generic_array::{ArrayLength, GenericArray};
use subtle::{Choice, ConstantTimeEq};
use typenum::{
    type_operators::{IsGreaterOrEqual, IsLess},
    U16, U32, U48, U64, U65536,
};

use crate::{
    keys::{raw_key, SecretKey},
    AlgId,
};

/// An error from a [`Mac`].
#[derive(Debug, Eq, PartialEq)]
pub enum MacError {
    /// The key provided to [`Mac::new`] is insecure.
    InsecureKey,
    /// The MAC (authentication tag) could not be verified.
    Verification,
}

impl fmt::Display for MacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecureKey => write!(f, "insecure key"),
            Self::Verification => write!(f, "unable to verify MAC"),
        }
    }
}

impl core::error::Error for MacError {}

/// MAC algorithm identifiers.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, AlgId)]
pub enum MacId {
    /// HMAC-SHA256.
    #[alg_id(0x0001)]
    HmacSha256,
    /// HMAC-SHA384.
    #[alg_id(0x0002)]
    HmacSha384,
    /// HMAC-SHA512.
    #[alg_id(0x0003)]
    HmacSha512,
    /// Some other digital signature algorithm.
    #[alg_id(Other)]
    Other(NonZeroU16),
}

/// A keyed Message Authentication Code Function (MAC).
///
/// # Requirements
///
/// The MAC must:
///
/// * Produce tags at least 256 bits long
/// * Have at minimum a 256-bit security level
/// * Reject insecure keys
/// * Be at least strongly EUF-CMA secure
/// * Be a PRF
///
/// Examples of keyed MAC algorithms that fulfill these
/// requirements include HMAC-SHA-512 (for |K| in [L, B]) and
/// KMAC256 (for |K| >= 256).
pub trait Mac: Clone + Sized {
    /// Uniquely identifies the MAC algorithm.
    const ID: MacId;

    /// An authentication tag.
    type Tag: ConstantTimeEq;
    /// The size in octets of a tag used by this [`Mac`].
    ///
    /// Must be at least 32 octets and less than 2³² octets.
    type TagSize: ArrayLength + IsGreaterOrEqual<U32> + IsLess<U65536> + 'static;

    /// The key used by the [`Mac`].
    type Key: SecretKey<Size = Self::KeySize>;
    /// The size in octets of a key used by this [`Mac`].
    ///
    /// Must be at least 16 octets and less than 2¹⁶ octets.
    type KeySize: ArrayLength + IsGreaterOrEqual<U16> + IsLess<U65536> + 'static;

    /// Creates a new [`Mac`].
    fn new(key: &Self::Key) -> Self;

    /// Adds `data` to the running tag.
    fn update(&mut self, data: &[u8]);

    /// Returns the current authentication tag.
    fn tag(self) -> Self::Tag;

    /// Determines in constant time whether the current tag is
    /// equal to `expect`.
    fn verify(self, expect: &Self::Tag) -> Result<(), MacError> {
        if bool::from(self.tag().ct_eq(expect)) {
            Ok(())
        } else {
            Err(MacError::Verification)
        }
    }

    /// Returns the tag for `data` using `key`.
    ///
    /// While this function is provided by default,
    /// implementations of [`Mac`] are encouraged to provide
    /// optimized "single-shot" implementations.
    fn mac(key: &Self::Key, data: &[u8]) -> Self::Tag {
        let mut h = Self::new(key);
        h.update(data);
        h.tag()
    }
}

raw_key! {
    /// A [`Mac`] key.
    pub MacKey,
}

/// An authentication tag.
#[derive(Copy, Clone, Debug)]
pub struct Tag<const N: usize>([u8; N]);

impl<const N: usize> Tag<N> {
    /// Returns its length in octets.
    #[allow(clippy::len_without_is_empty)]
    #[inline]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns itself as a byte array.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> ConstantTimeEq for Tag<N> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[..].ct_eq(&other.0[..])
    }
}

impl<const N: usize> AsRef<[u8]> for Tag<N> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for Tag<N> {
    #[inline]
    fn from(tag: [u8; N]) -> Self {
        Self(tag)
    }
}

impl From<GenericArray<u8, U32>> for Tag<32> {
    #[inline]
    fn from(tag: GenericArray<u8, U32>) -> Self {
        Self(tag.into())
    }
}

impl From<GenericArray<u8, U48>> for Tag<48> {
    #[inline]
    fn from(tag: GenericArray<u8, U48>) -> Self {
        Self(tag.into())
    }
}

impl From<GenericArray<u8, U64>> for Tag<64> {
    #[inline]
    fn from(tag: GenericArray<u8, U64>) -> Self {
        Self(tag.into())
    }
}

impl<const N: usize> From<Tag<N>> for [u8; N] {
    #[inline]
    fn from(tag: Tag<N>) -> Self {
        tag.0
    }
}

impl<const N: usize> TryFrom<&[u8]> for Tag<N> {
    type Error = TryFromSliceError;

    #[inline]
    fn try_from(tag: &[u8]) -> Result<Self, Self::Error> {
        Ok(Tag(tag.try_into()?))
    }
}
