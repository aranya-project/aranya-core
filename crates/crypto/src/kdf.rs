//! Key Derivation Functions.
//!
//! # Warning
//!
//! This is a low-level module. You should not be be directly
//! using it directly unless you are implementing an engine.

#![forbid(unsafe_code)]

use core::{fmt, iter::IntoIterator, mem, result::Result};

use buggy::Bug;
use generic_array::{ArrayLength, ConstArrayLength, GenericArray, IntoArrayLength};
use subtle::{Choice, ConstantTimeEq};
use typenum::{
    type_operators::{IsGreaterOrEqual, IsLess},
    Const, Unsigned, U32, U64, U65536,
};

pub use crate::hpke::KdfId;
use crate::{keys::SecretKeyBytes, zeroize::ZeroizeOnDrop};

/// An error from a [`Kdf`].
#[derive(Debug, Eq, PartialEq)]
pub enum KdfError {
    /// The requested output from a KDF exceeded
    /// [`Kdf::MAX_OUTPUT`].
    OutputTooLong,
    /// An internal bug was discovered.
    Bug(Bug),
}

impl fmt::Display for KdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputTooLong => write!(f, "requested KDF output too long"),
            Self::Bug(err) => write!(f, "{err}"),
        }
    }
}

impl core::error::Error for KdfError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Bug(err) => Some(err),
            _ => None,
        }
    }
}

impl From<Bug> for KdfError {
    fn from(err: Bug) -> Self {
        Self::Bug(err)
    }
}

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

    /// The size in octets of the largest key that can be created
    /// with [`expand`][Self::expand],
    /// [`expand_multi`][Self::expand_multi], or
    /// [`extract_and_expand`][Self::extract_and_expand].
    ///
    /// Must be at least 64 octets (512 bits).
    type MaxOutput: ArrayLength + IsGreaterOrEqual<U64> + 'static;
    /// The size in octets of the largest key that can be created
    /// with [`expand`][Self::expand],
    /// [`expand_multi`][Self::expand_multi], or
    /// [`extract_and_expand`][Self::extract_and_expand].
    ///
    /// Must be at least 64 bytes (512 bits).
    const MAX_OUTPUT: usize = Self::MaxOutput::USIZE;

    /// The size in octets of a pseudorandom key used by this
    /// [`Kdf`].
    ///
    /// Must be at least 32 octets and less than 2¹⁶ octets.
    type PrkSize: ArrayLength + IsGreaterOrEqual<U32> + IsLess<U65536> + 'static;
    /// Shorthand for [`PrkSize`][Self::PrkSize].
    const PRK_SIZE: usize = Self::PrkSize::USIZE;

    /// A randomness extractor that extracts a fixed-length
    /// pseudorandom key (PRK) from the Input Keying Material
    /// (IKM) and an optional salt.
    ///
    /// It handles IKM and salts of an arbitrary length.
    fn extract(ikm: &[u8], salt: &[u8]) -> Prk<Self::PrkSize> {
        Self::extract_multi(&[ikm], salt)
    }

    /// Identical to [`Kdf::extract`], but accepts the `ikm`
    /// parameter as multiple parts.
    fn extract_multi<I>(ikm: I, salt: &[u8]) -> Prk<Self::PrkSize>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>;

    /// A Pseudo Random Function (PRF) that expands the PRK with
    /// an optional info parameter into a key.
    ///
    /// It handles `info` parameters of an arbitrary length and
    /// outputs up to [`Self::MAX_OUTPUT`] bytes.
    ///
    /// It returns an error if the output is too large.
    fn expand(out: &mut [u8], prk: &Prk<Self::PrkSize>, info: &[u8]) -> Result<(), KdfError> {
        Self::expand_multi(out, prk, &[info])
    }

    /// Identical to [`Kdf::expand`], but accepts the `info`
    /// parameter as multiple parts.
    fn expand_multi<I>(out: &mut [u8], prk: &Prk<Self::PrkSize>, info: I) -> Result<(), KdfError>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
        I::IntoIter: Clone;

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

/// A pseudorandom key.
#[derive(Clone, Default, ZeroizeOnDrop)]
#[repr(transparent)]
pub struct Prk<N: ArrayLength>(SecretKeyBytes<N>);

impl<N: ArrayLength> Prk<N> {
    /// Creates a new PRK.
    #[inline]
    pub const fn new(prk: SecretKeyBytes<N>) -> Self {
        Self(prk)
    }

    /// Returns the size in bytes of the PRK.
    #[inline]
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns the pseudorandom key bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns the pseudorandom key bytes.
    pub(crate) fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.0.as_bytes_mut()
    }

    /// Converts itself to an array.
    #[inline]
    pub fn into_bytes(mut self) -> SecretKeyBytes<N> {
        // This is fine since we're consuming the receiver. If
        // the receiver were an exclusive reference this would be
        // very wrong since it'd be replacing the secret key with
        // all zeros.
        mem::take(&mut self.0)
    }
}

impl<N: ArrayLength> ConstantTimeEq for Prk<N> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

// TODO(eric): get rid of this. The only use is `Kem::Secret`.
impl<N: ArrayLength> AsRef<[u8]> for Prk<N> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<N: ArrayLength> Expand for Prk<N>
where
    N: IsLess<U65536>,
{
    type Size = N;

    fn expand_multi<'a, K, I>(prk: &Prk<K::PrkSize>, info: I) -> Result<Self, KdfError>
    where
        K: Kdf,
        I: IntoIterator<Item = &'a [u8]>,
        I::IntoIter: Clone,
    {
        Ok(Self(Expand::expand_multi::<K, I>(prk, info)?))
    }
}

/// Implemented by types that can expand themselves from a PRK.
pub trait Expand: Sized {
    /// The size in octets of the derived key.
    type Size: ArrayLength + IsLess<U65536> + 'static;

    /// Derives itself from a PRK.
    fn expand<K: Kdf>(prk: &Prk<K::PrkSize>, info: &[u8]) -> Result<Self, KdfError> {
        Self::expand_multi::<K, _>(prk, [info])
    }

    /// Derives itself from a PRk.
    fn expand_multi<'a, K, I>(prk: &Prk<K::PrkSize>, info: I) -> Result<Self, KdfError>
    where
        K: Kdf,
        I: IntoIterator<Item = &'a [u8]>,
        I::IntoIter: Clone;
}

impl<N: ArrayLength> Expand for GenericArray<u8, N>
where
    N: IsLess<U65536>,
{
    type Size = N;

    fn expand_multi<'a, K, I>(prk: &Prk<K::PrkSize>, info: I) -> Result<Self, KdfError>
    where
        K: Kdf,
        I: IntoIterator<Item = &'a [u8]>,
        I::IntoIter: Clone,
    {
        let mut out = GenericArray::default();
        K::expand_multi(&mut out, prk, info)?;
        Ok(out)
    }
}

impl<const N: usize> Expand for [u8; N]
where
    Const<N>: IntoArrayLength,
    ConstArrayLength<N>: IsLess<U65536>,
{
    type Size = ConstArrayLength<N>;

    fn expand_multi<'a, K, I>(prk: &Prk<K::PrkSize>, info: I) -> Result<Self, KdfError>
    where
        K: Kdf,
        I: IntoIterator<Item = &'a [u8]>,
        I::IntoIter: Clone,
    {
        let mut out = [0u8; N];
        K::expand_multi(&mut out, prk, info)?;
        Ok(out)
    }
}

/// Context for labeled key derivation per RFC 9180.
pub struct Context {
    /// A domain separation string.
    pub domain: &'static str,
    /// Suite identifiers.
    pub suite_ids: &'static [u8],
}

impl Context {
    /// Performs `LabeledExtract` per RFC 9180.
    pub fn labeled_extract<K: Kdf>(
        &self,
        salt: &[u8],
        label: &'static str,
        ikm: &[u8],
    ) -> Prk<K::PrkSize> {
        // def LabeledExtract(salt, label, ikm):
        //     labeled_ikm = concat(domain, suite_ids, label, ikm)
        //     return Extract(salt, labeled_ikm)
        let labeled_ikm = [
            self.domain.as_bytes(),
            self.suite_ids,
            label.as_bytes(),
            ikm,
        ];
        K::extract_multi(labeled_ikm, salt)
    }

    /// Performs `LabeledExpand` per RFC 9180.
    pub fn labeled_expand<K, T>(
        &self,
        prk: &Prk<K::PrkSize>,
        label: &'static str,
        info: &[&[u8]],
    ) -> Result<T, KdfError>
    where
        K: Kdf,
        T: Expand,
    {
        // def LabeledExpand(prk, label, info):
        //     labeled_info = concat(I2OSP(L, 2), domain, suite_ids,
        //                   label, info)
        //     return Expand(prk, labeled_info)
        let size = T::Size::U16.to_be_bytes();
        let labeled_info = [
            &size,
            self.domain.as_bytes(),
            self.suite_ids,
            label.as_bytes(),
        ]
        .into_iter()
        .chain(info.iter().copied());
        T::expand_multi::<K, _>(prk, labeled_info)
    }

    /// Performs `LabeledExpand` per RFC 9180.
    pub fn labeled_expand_into<K: Kdf>(
        &self,
        out: &mut [u8],
        prk: &Prk<K::PrkSize>,
        label: &'static str,
        info: &[&[u8]],
    ) -> Result<(), KdfError> {
        // def LabeledExpand(prk, label, info):
        //     labeled_info = concat(I2OSP(L, 2), domain, suite_ids,
        //                   label, info)
        //     return Expand(prk, labeled_info)
        let size = u16::try_from(out.len())
            .map_err(|_| KdfError::OutputTooLong)?
            .to_be_bytes();
        let labeled_info = [
            &size,
            self.domain.as_bytes(),
            self.suite_ids,
            label.as_bytes(),
        ]
        .into_iter()
        .chain(info.iter().copied());
        K::expand_multi(out, prk, labeled_info)
    }
}
