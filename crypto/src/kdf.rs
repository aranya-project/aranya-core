//! Key Derivation Functions.
//!
//! # Warning
//!
//! This is a low-level module. You should not be be directly
//! using it directly unless you are implementing an engine.

#![forbid(unsafe_code)]

use {
    crate::{keys::raw_key, mac::Tag},
    cfg_if::cfg_if,
    core::{
        borrow::{Borrow, BorrowMut},
        fmt,
        result::Result,
    },
};

cfg_if! {
    if #[cfg(feature = "error_in_core")] {
        use core::error;
    } else if #[cfg(feature = "std")] {
        use std::error;
    }
}

pub use crate::hpke::KdfId;

/// An error from a [`Kdf`].
#[derive(Debug, Eq, PartialEq)]
pub enum KdfError {
    /// The requested output from a KDF exceeded
    /// [`Kdf::MAX_OUTPUT`].
    OutputTooLong,
}

impl fmt::Display for KdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputTooLong => write!(f, "requested KDF output too long"),
        }
    }
}

#[cfg_attr(docs, doc(cfg(any(feature = "error_in_core", feature = "std"))))]
#[cfg(any(feature = "error_in_core", feature = "std"))]
impl error::Error for KdfError {}

/// An extract-then-expand Key Derivation Function (KDF) as
/// formally defined in section 3 of [HKDF].
///
/// # Requirements
///
/// The KDF must:
///
///  * Have a security level of at least 128 bits.
///  * Extract a PRK at least 128 bits long.
///  * Expand a PRK into a key at least 512 bits long.
///
/// # Notes
///
/// It is not suitable for deriving keys from passwords.
///
/// [HKDF]: https://eprint.iacr.org/2010/264
pub trait Kdf {
    /// Uniquely identifies the KDF.
    const ID: KdfId;

    /// The size in bytes of the largest key that can be created
    /// with [`Self::expand`] (and [`Self::extract_and_expand`]).
    ///
    /// Must be at least 64 bytes (512 bits).
    const MAX_OUTPUT: usize = 255 * Self::PRK_SIZE;

    /// The size in bytes of a [`Self::Prk`].
    ///
    /// Must be at least 16 bytes (128 bits).
    const PRK_SIZE: usize;

    /// The PRK returned by [`Self::extract`] and
    /// [`Self::extract_multi`].
    ///
    /// Must be exactly [`Self::PRK_SIZE`] bytes long.
    type Prk: Borrow<[u8]> + BorrowMut<[u8]> + Default;

    /// A randomness extractor that extracts a fixed-length
    /// pseudorandom key (PRK) from the Input Keying Material
    /// (IKM) and an optional salt.
    ///
    /// It handles IKM and salts of an arbitrary length.
    fn extract(ikm: &[u8], salt: &[u8]) -> Self::Prk {
        Self::extract_multi(&[ikm], salt)
    }

    /// Identical to [`Kdf::extract`], but accepts the `ikm`
    /// parameter as multiple parts.
    fn extract_multi(ikm: &[&[u8]], salt: &[u8]) -> Self::Prk;

    /// A Pseudo Random Function (PRF) that expands the PRK with
    /// an optional info parameter into a key.
    ///
    /// It handles `info` parameters of an arbitrary length and
    /// outputs up to [`Self::MAX_OUTPUT`] bytes.
    ///
    /// It returns an error if the output is too large.
    fn expand(out: &mut [u8], prk: &Self::Prk, info: &[u8]) -> Result<(), KdfError> {
        Self::expand_multi(out, prk, &[info])
    }

    /// Identical to [`Kdf::expand`], but accepts the `info`
    /// parameter as multiple parts.
    fn expand_multi(out: &mut [u8], prk: &Self::Prk, info: &[&[u8]]) -> Result<(), KdfError>;

    /// Performs both the extract and expand steps.
    ///
    /// It handles `ikm`, `salt`, and `info` parameters of an
    /// arbitrary length and outputs up to [`Self::MAX_OUTPUT`]
    /// bytes.
    ///
    /// It returns an error if the output is too large.
    ///
    /// While this function is provided by default,
    /// implementations of [`Kdf`] are encouraged to provide
    /// optimized "single-shot" implementations.
    fn extract_and_expand(
        out: &mut [u8],
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
    ) -> Result<(), KdfError> {
        if out.len() > Self::MAX_OUTPUT {
            Err(KdfError::OutputTooLong)
        } else {
            let prk = Self::extract_multi(&[ikm], salt);
            Self::expand_multi(out, &prk, &[info])
        }
    }

    /// Performs both the extract and expand steps.
    ///
    /// It handles `ikm`, `salt`, and `info` parameters of an
    /// arbitrary length and outputs up to [`Self::MAX_OUTPUT`]
    /// bytes.
    ///
    /// It returns an error if the output is too large.
    ///
    /// While this function is provided by default,
    /// implementations of [`Kdf`] are encouraged to provide
    /// optimized "single-shot" implementations.
    fn extract_and_expand_multi(
        out: &mut [u8],
        ikm: &[&[u8]],
        salt: &[u8],
        info: &[&[u8]],
    ) -> Result<(), KdfError> {
        if out.len() > Self::MAX_OUTPUT {
            Err(KdfError::OutputTooLong)
        } else {
            let prk = Self::extract_multi(ikm, salt);
            Self::expand_multi(out, &prk, info)
        }
    }
}

raw_key! {
    /// A [`Kdf`] pseudorandom key.
    pub Prk,
}

impl<const N: usize> From<Tag<N>> for Prk<N> {
    #[inline]
    fn from(tag: Tag<N>) -> Self {
        Prk(tag.into())
    }
}
