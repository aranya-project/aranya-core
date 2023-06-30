//! Authenticated Encryption with Additional Associated Data per
//! [RFC 5116].
//!
//! # Warning
//!
//! This is a low-level module. You should not be using it
//! directly unless you are implementing an engine.
//!
//! [RFC 5116]: https://www.rfc-editor.org/rfc/rfc5116

#![forbid(unsafe_code)]

use {
    crate::{
        hybrid_array::{
            typenum::{
                type_operators::{IsGreaterOrEqual, IsLess},
                Unsigned, U16, U65536,
            },
            ArraySize,
        },
        keys::{raw_key, SecretKey},
        zeroize::Zeroize,
    },
    cfg_if::cfg_if,
    core::{
        borrow::{Borrow, BorrowMut},
        fmt::{self, Debug},
        mem,
        result::Result,
    },
};

#[allow(clippy::wildcard_imports)]
use crate::features::*;

cfg_if! {
    if #[cfg(feature = "error_in_core")] {
        use core::error;
    } else if #[cfg(feature = "std")] {
        use std::error;
    }
}

pub use crate::hpke::AeadId;

// Some of the bounds for `Aead` are at least 32 bits, prevent
// the crate from being built for, e.g., a 16-bit CPU. If we ever
// need to support such a CPU we will need to revisit the API.
const_assert!(mem::size_of::<usize>() >= 4);

/// The output buffer is too small.
///
/// It contains the size that the buffer needs to be for the
/// call to succeed, if known.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BufferTooSmallError(pub Option<usize>);

impl BufferTooSmallError {
    /// Returns a human-readable string describing the error.
    pub fn as_str(&self) -> &'static str {
        "dest buffer too small"
    }
}

impl fmt::Display for BufferTooSmallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(n) = self.0 {
            write!(f, "{} (need {})", self.as_str(), n)
        } else {
            write!(f, "{}", self.as_str())
        }
    }
}

#[cfg_attr(docs, doc(cfg(any(feature = "error_in_core", feature = "std"))))]
#[cfg(any(feature = "error_in_core", feature = "std"))]
impl error::Error for BufferTooSmallError {}

/// An error from an [`Aead`].
#[derive(Debug, Eq, PartialEq)]
pub enum AeadError {
    /// An unknown or internal error has occurred.
    Other(&'static str),
    /// The size of the key is incorrect.
    InvalidKeySize,
    /// The size of the nonce is incorrect.
    InvalidNonceSize,
    /// The size of the tag is incorrect.
    InvalidTagSize,
    /// The plaintext is too long.
    PlaintextTooLong,
    /// The ciphertext is too long.
    CiphertextTooLong,
    /// The additional data is too long.
    AdditionalDataTooLong,
    /// The output buffer is too small.
    BufferTooSmall(BufferTooSmallError),
    /// The ciphertext could not be authenticated.
    Authentication,
    /// The plaintext could not be encrypted.
    Encryption,
}

impl AeadError {
    /// Returns a human-readable string describing the error.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Other(msg) => msg,
            Self::InvalidKeySize => "invalid key size",
            Self::InvalidNonceSize => "invalid nonce size",
            Self::InvalidTagSize => "invalid tag size",
            Self::PlaintextTooLong => "plaintext too long",
            Self::CiphertextTooLong => "ciphertext too long",
            Self::AdditionalDataTooLong => "additional data too long",
            Self::Authentication => "authentication error",
            Self::Encryption => "encryption error",
            Self::BufferTooSmall(err) => err.as_str(),
        }
    }
}

impl fmt::Display for AeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall(err) => write!(f, "{}", err),
            _ => write!(f, "{}", self.as_str()),
        }
    }
}

#[cfg_attr(docs, doc(cfg(any(feature = "error_in_core", feature = "std"))))]
#[cfg(any(feature = "error_in_core", feature = "std"))]
impl error::Error for AeadError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::BufferTooSmall(err) => Some(err),
            _ => None,
        }
    }
}

impl From<BufferTooSmallError> for AeadError {
    fn from(value: BufferTooSmallError) -> Self {
        AeadError::BufferTooSmall(value)
    }
}

/// A symmetric cipher implementing a particular Authenticated
/// Encryption with Associated Data (AEAD) algorithm per
/// [RFC 5116].
///
/// Briefly, AEAD encryption is a construction with four inputs:
///
///  1. uniformly random key `K`
///  2. nonce `N` that is unique for each unique `(K, P)` tuple
///  3. plaintext `P` which will be encrypted
///  4. associated data `A` that will be authenticated, but *not*
///     encrypted
///
/// It outputs a ciphertext `C` which is at least as long as `P`.
/// AEAD decryption works in the inverse manner. For formal and
/// more comprehensive documentation, see [RFC 5116].
///
/// # Requirements
///
/// This API is more restrictive than [RFC 5116]. Specifically,
/// the cipher must:
///
/// * Have at least a 128-bit security level for confidentiality.
/// * Have at least a 128-bit security level for authenticity.
/// * Have a minimum key size of 16 octets (128 bits).
/// * Accept plaintexts up to 2³² - 1 octets (2³⁵ - 8 bits) long.
/// * Accept associated data up to 2³² - 1 (2³⁵ - 8 bits) octets
///   long.
///
/// Examples of AEAD algorithms that fulfill these requirements
/// include [AES-256-GCM], [ChaCha20-Poly1305], and [Ascon].
///
/// It is highly recommended to use a nonce misuse-resistant
/// AEAD, like [AES-GCM-SIV].
///
/// [AES-256-GCM]: https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf
/// [AES-GCM-SIV]: https://www.rfc-editor.org/rfc/rfc8452.html
/// [Ascon]: https://csrc.nist.gov/News/2023/lightweight-cryptography-nist-selects-ascon
/// [ChaCha20-Poly1305]: https://datatracker.ietf.org/doc/html/rfc8439
/// [RFC 5116]: https://www.rfc-editor.org/rfc/rfc5116.html
pub trait Aead {
    /// Uniquely identifies the AEAD algorithm.
    const ID: AeadId;

    /// The size in octets of a key used by this [`Aead`].
    ///
    /// Must be at least 16 octets and less than 2¹⁶ octets.
    type KeySize: ArraySize + IsGreaterOrEqual<U16> + IsLess<U65536> + 'static;
    /// Shorthand for [`KeySize`][Self::KeySize].
    const KEY_SIZE: usize = Self::KeySize::USIZE;

    /// The size in octets of a nonce used by this [`Aead`].
    ///
    /// Must be less than 2¹⁶ octets.
    type NonceSize: ArraySize + IsLess<U65536> + 'static;
    /// Shorthand for [`NonceSize`][Self::NonceSize].
    const NONCE_SIZE: usize = Self::NonceSize::USIZE;

    /// The size in octets of an authentication tag used by this
    /// [`Aead`].
    ///
    /// Must be at least 16 bytes (128 bits).
    type TagSize: ArraySize + IsGreaterOrEqual<U16> + 'static;
    /// Shorthand for [`TagSize`][Self::TagSize].
    const TAG_SIZE: usize = Self::TagSize::USIZE;

    /// The maximum size in octets of a plaintext allowed by this
    /// [`Aead`] (i.e., `P_MAX`).
    ///
    /// Must be at least 2³² - 1 octets.
    const MAX_PLAINTEXT_SIZE: u64;
    /// The maximum size in octets of additional data allowed by
    /// this [`Aead`] (i.e., `A_MAX`).
    ///
    /// Must be at least 2³² - 1 octets.
    const MAX_ADDITIONAL_DATA_SIZE: u64;
    /// The maximum size in octets of a ciphertext allowed by
    /// this [`Aead`] (i.e., `C_MAX`).
    ///
    /// Must be at least 2³² - 1 octets and
    /// [`TAG_SIZE`][Self::TAG_SIZE] octets larger than
    /// [`MAX_PLAINTEXT_SIZE`][Self::MAX_PLAINTEXT_SIZE].
    const MAX_CIPHERTEXT_SIZE: u64 =
        match Self::MAX_PLAINTEXT_SIZE.checked_add(Self::TAG_SIZE as u64) {
            Some(n) => n,
            None => panic!("overflow"),
        };

    /// The key used by the [`Aead`].
    type Key: SecretKey;

    /// The nonce used by the [`Aead`].
    type Nonce: Borrow<[u8]>
        + BorrowMut<[u8]>
        + Clone
        + Default
        + Debug
        + for<'a> TryFrom<&'a [u8], Error = AeadError>;

    /// Creates a new [`Aead`].
    fn new(key: &Self::Key) -> Self;

    /// Encrypts and authenticates `plaintext`, writing the
    /// resulting ciphertext to `dst`.
    ///
    /// Only `plaintext.len()` + [`Self::TAG_SIZE`] bytes of
    /// `dst` will be written to.
    ///
    /// # Requirements
    ///
    /// * `dst` must be at least [`Self::TAG_SIZE`] bytes longer
    ///   than `plaintext`.
    /// * `nonce` must be exactly [`Self::NONCE_SIZE`] bytes
    ///   long.
    /// * `plaintext` must be at most [`Self::MAX_PLAINTEXT_SIZE`]
    ///   bytes long.
    /// * `additional_data` must be at most
    ///   [`Self::MAX_ADDITIONAL_DATA_SIZE`] bytes long.
    fn seal(
        &self,
        dst: &mut [u8],
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), AeadError> {
        check_seal_params::<Self>(dst, nonce, plaintext, additional_data)?;

        let out = &mut dst[..plaintext.len() + Self::TAG_SIZE];
        out[..plaintext.len()].copy_from_slice(plaintext);
        let (out, tag) = out.split_at_mut(out.len() - Self::TAG_SIZE);
        self.seal_in_place(nonce, out, tag, additional_data)
            // Encryption failed, make sure that we do not
            // release any invalid plaintext to the caller.
            .inspect_err(|_| out.zeroize())
    }

    /// Encrypts and authenticates `data` in-place.
    ///
    /// The authentication tag is written to `tag`.
    ///
    /// # Requirements
    ///
    /// * `nonce` must be exactly [`Self::NONCE_SIZE`] bytes
    ///   long.
    /// * `data` must be at most [`Self::MAX_PLAINTEXT_SIZE`]
    ///   bytes long.
    /// * `tag` must be exactly [`Self::TAG_SIZE`] bytes long.
    /// * `additional_data` must be at most
    ///   [`Self::MAX_ADDITIONAL_DATA_SIZE`] bytes long.
    fn seal_in_place(
        &self,
        nonce: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
        additional_data: &[u8],
    ) -> Result<(), AeadError>;

    /// Decrypts and authenticates `ciphertext`, writing the
    /// resulting plaintext to `dst`.
    ///
    /// Only `ciphertext.len()` - [`Self::TAG_SIZE`] bytes of
    /// `dst` will be written to.
    ///
    /// # Requirements
    ///
    /// * `dst` must be at least `ciphertext.len()` -
    ///   [`Self::TAG_SIZE`] bytes long.
    /// * `nonce` must be exactly [`Self::NONCE_SIZE`] bytes
    ///   long.
    /// * `ciphertext` must be at most
    ///   [`Self::MAX_CIPHERTEXT_SIZE`] bytes long.
    /// * `additional_data` must be at most
    ///   [`Self::MAX_ADDITIONAL_DATA_SIZE`] bytes long.
    fn open(
        &self,
        dst: &mut [u8],
        nonce: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), AeadError> {
        check_open_params::<Self>(dst, nonce, ciphertext, additional_data)?;

        let max = ciphertext.len() - Self::TAG_SIZE;
        let (ciphertext, tag) = ciphertext.split_at(max);
        let out = &mut dst[..max];
        out.copy_from_slice(ciphertext);
        self.open_in_place(nonce, out, tag, additional_data)
            // Decryption failed, ensure that we do not release
            // any invalid plaintext to the caller.
            .inspect_err(|_| out.zeroize())
    }

    /// Decrypts and authenticates `data` in-place.
    ///
    /// # Requirements
    ///
    /// * `nonce` must be exactly [`Self::NONCE_SIZE`] bytes
    ///   long.
    /// * `data` must be at most [`Self::MAX_CIPHERTEXT_SIZE`] -
    ///   [`Self::TAG_SIZE`] bytes long.
    /// * `tag` must be exactly [`Self::TAG_SIZE`] bytes long.
    /// * `additional_data` must be at most
    ///   [`Self::MAX_ADDITIONAL_DATA_SIZE`] bytes long.
    fn open_in_place(
        &self,
        nonce: &[u8],
        data: &mut [u8],
        tag: &[u8],
        additional_data: &[u8],
    ) -> Result<(), AeadError>;
}

/// Shorthand for the `A::Key::Data`, which the compiler does not
/// understand without a good amount of hand holding.
pub(crate) type KeyData<A> = <<A as Aead>::Key as SecretKey>::Data;

const fn check_aead_params<A: Aead + ?Sized>() {
    debug_assert!(A::KEY_SIZE >= 16);
    debug_assert!(A::TAG_SIZE >= 16);
    debug_assert!(A::MAX_PLAINTEXT_SIZE >= u32::MAX as u64);
    debug_assert!(A::MAX_CIPHERTEXT_SIZE == A::MAX_PLAINTEXT_SIZE + A::TAG_SIZE as u64);
    debug_assert!(A::MAX_ADDITIONAL_DATA_SIZE >= u32::MAX as u64);
}

/// Checks that the parameters to [`Aead::seal`] have the correct
/// lengths, etc.
pub const fn check_seal_params<A: Aead + ?Sized>(
    dst: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    additional_data: &[u8],
) -> Result<(), AeadError> {
    check_aead_params::<A>();

    let need = match plaintext.len().checked_add(A::TAG_SIZE) {
        // Overflow.
        None => return Err(AeadError::PlaintextTooLong),
        Some(n) => n,
    };
    if need > dst.len() {
        return Err(AeadError::BufferTooSmall(BufferTooSmallError(Some(need))));
    }
    if nonce.len() != A::NONCE_SIZE {
        return Err(AeadError::InvalidNonceSize);
    }
    if plaintext.len() as u64 > A::MAX_PLAINTEXT_SIZE {
        return Err(AeadError::PlaintextTooLong);
    }
    if additional_data.len() as u64 > A::MAX_ADDITIONAL_DATA_SIZE {
        return Err(AeadError::AdditionalDataTooLong);
    }
    Ok(())
}

/// Checks that the parameters to [`Aead::seal_in_place`] have
/// the correct lengths, etc.
pub const fn check_seal_in_place_params<A: Aead + ?Sized>(
    nonce: &[u8],
    data: &[u8],
    tag: &[u8],
    additional_data: &[u8],
) -> Result<(), AeadError> {
    check_aead_params::<A>();

    if nonce.len() != A::NONCE_SIZE {
        return Err(AeadError::InvalidNonceSize);
    }
    if data.len() as u64 > A::MAX_PLAINTEXT_SIZE {
        return Err(AeadError::PlaintextTooLong);
    }
    if tag.len() > A::TAG_SIZE {
        return Err(AeadError::InvalidTagSize);
    }
    if additional_data.len() as u64 > A::MAX_ADDITIONAL_DATA_SIZE {
        return Err(AeadError::AdditionalDataTooLong);
    }
    Ok(())
}

/// Checks that the parameters to [`Aead::open`] have the correct
/// lengths, etc.
pub const fn check_open_params<A: Aead + ?Sized>(
    dst: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    additional_data: &[u8],
) -> Result<(), AeadError> {
    check_aead_params::<A>();

    let need = match ciphertext.len().checked_sub(A::TAG_SIZE) {
        // If the ciphertext does not have a full tag it cannot
        // be authenticated.
        None => return Err(AeadError::Authentication),
        Some(n) => n,
    };
    if need > dst.len() {
        return Err(AeadError::BufferTooSmall(BufferTooSmallError(Some(need))));
    }
    if nonce.len() != A::NONCE_SIZE {
        return Err(AeadError::InvalidNonceSize);
    }
    // The case where the `ciphertext.len()` < `A::TAG_SIZE` is
    // covered by the `match` expression above.
    if ciphertext.len() as u64 > A::MAX_CIPHERTEXT_SIZE {
        return Err(AeadError::CiphertextTooLong);
    }
    if additional_data.len() as u64 > A::MAX_ADDITIONAL_DATA_SIZE {
        return Err(AeadError::AdditionalDataTooLong);
    }
    Ok(())
}

/// Checks that the parameters to [`Aead::open_in_place`] have
/// the correct lengths, etc.
pub const fn check_open_in_place_params<A: Aead + ?Sized>(
    nonce: &[u8],
    data: &[u8],
    tag: &[u8],
    additional_data: &[u8],
) -> Result<(), AeadError> {
    check_aead_params::<A>();

    if nonce.len() != A::NONCE_SIZE {
        return Err(AeadError::InvalidNonceSize);
    }
    if data.len() as u64 > A::MAX_PLAINTEXT_SIZE - A::TAG_SIZE as u64 {
        return Err(AeadError::PlaintextTooLong);
    }
    if tag.len() > A::TAG_SIZE {
        return Err(AeadError::InvalidTagSize);
    }
    if additional_data.len() as u64 > A::MAX_ADDITIONAL_DATA_SIZE {
        return Err(AeadError::AdditionalDataTooLong);
    }
    Ok(())
}

raw_key! {
    /// An [`Aead`] key.
    pub AeadKey,
}

/// An [`Aead`] nonce.
#[derive(Copy, Clone, Debug)]
pub struct Nonce<const N: usize>([u8; N]);

impl<const N: usize> Borrow<[u8]> for Nonce<N> {
    fn borrow(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<const N: usize> BorrowMut<[u8]> for Nonce<N> {
    fn borrow_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<const N: usize> Default for Nonce<N> {
    fn default() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> TryFrom<&[u8]> for Nonce<N> {
    type Error = AeadError;

    fn try_from(data: &[u8]) -> Result<Self, AeadError> {
        let nonce = data.try_into().map_err(|_| AeadError::InvalidNonceSize)?;
        Ok(Self(nonce))
    }
}
