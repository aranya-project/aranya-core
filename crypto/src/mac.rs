//! Message Authentication Codes.
//!
//! # Warning
//!
//! This is a low-level module. You should not be using it
//! directly unless you are implementing an engine.

use {
    crate::keys::{raw_key, SecretKey},
    cfg_if::cfg_if,
    core::{
        array::TryFromSliceError,
        fmt::{self, Debug},
        mem,
        result::Result,
    },
    postcard::experimental::max_size::MaxSize,
    serde::{Deserialize, Serialize},
    subtle::{Choice, ConstantTimeEq},
};

cfg_if! {
    if #[cfg(feature = "error_in_core")] {
        use core::error;
    } else if #[cfg(feature = "std")] {
        use std::error;
    }
}

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

#[cfg_attr(docs, doc(cfg(any(feature = "error_in_core", feature = "std"))))]
#[cfg(any(feature = "error_in_core", feature = "std"))]
impl error::Error for MacError {}

/// MAC algorithm identifiers.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize, MaxSize)]
pub enum MacId {
    /// HMAC-SHA256.
    HmacSha256,
    /// HMAC-SHA384.
    HmacSha384,
    /// HMAC-SHA512.
    HmacSha512,
    /// Some other digital signature algorithm.
    Other(u16),
}

impl MacId {
    pub(crate) const fn to_u16(self) -> u16 {
        match self {
            Self::HmacSha256 => 0x0001,
            Self::HmacSha384 => 0x0002,
            Self::HmacSha512 => 0x0003,
            Self::Other(id) => id,
        }
    }
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

    /// The key used by the [`Mac`].
    type Key: SecretKey;

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

impl<'a, const N: usize> From<&'a [u8; N]> for &'a MacKey<N> {
    #[inline]
    fn from(v: &[u8; N]) -> Self {
        // SAFETY: `[u8; N]` and `MacKey` have the same
        // memory layout.
        unsafe { mem::transmute(v) }
    }
}

/// A [`Mac`] authentication tag.
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
