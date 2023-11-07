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

use core::{
    borrow::{Borrow, BorrowMut},
    cmp::{Eq, PartialEq},
    fmt::{self, Debug},
    mem,
    result::Result,
};

use cfg_if::cfg_if;
use generic_array::ArrayLength;
use typenum::{
    type_operators::{IsGreaterOrEqual, IsLess},
    Unsigned, U16, U65536,
};

#[allow(clippy::wildcard_imports)]
use crate::features::*;
use crate::{
    error::Unreachable,
    keys::{raw_key, SecretKey},
    zeroize::Zeroize,
};

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
    pub const fn as_str(&self) -> &'static str {
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

/// An error from a [`Nonce`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InvalidNonceSize;

impl InvalidNonceSize {
    /// Returns a human-readable string describing the error.
    pub const fn as_str(&self) -> &'static str {
        "nonce size is invalid"
    }
}

impl fmt::Display for InvalidNonceSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg_attr(docs, doc(cfg(any(feature = "error_in_core", feature = "std"))))]
#[cfg(any(feature = "error_in_core", feature = "std"))]
impl error::Error for InvalidNonceSize {}

/// An error from an [`Aead`] seal.
#[derive(Debug, Eq, PartialEq)]
pub enum SealError {
    /// An unreachable code path has been taken.
    Unreachable(Unreachable),
    /// An unknown or internal error has occurred.
    Other(&'static str),
    /// The size of the key is incorrect.
    InvalidKeySize,
    /// The size of the nonce is incorrect.
    InvalidNonceSize(InvalidNonceSize),
    /// The size of the overhead is incorrect.
    InvalidOverheadSize,
    /// The plaintext is too long.
    PlaintextTooLong,
    /// The additional data is too long.
    AdditionalDataTooLong,
    /// The output buffer is too small.
    BufferTooSmall(BufferTooSmallError),
    /// The plaintext could not be encrypted.
    Encryption,
}

impl SealError {
    /// Returns a human-readable string describing the error.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unreachable(err) => err.as_str(),
            Self::Other(msg) => msg,
            Self::InvalidKeySize => "invalid key size",
            Self::InvalidNonceSize(err) => err.as_str(),
            Self::InvalidOverheadSize => "invalid overhead size",
            Self::PlaintextTooLong => "plaintext too long",
            Self::AdditionalDataTooLong => "additional data too long",
            Self::Encryption => "encryption error",
            Self::BufferTooSmall(err) => err.as_str(),
        }
    }
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable(err) => write!(f, "{}", err),
            Self::BufferTooSmall(err) => write!(f, "{}", err),
            Self::InvalidNonceSize(err) => write!(f, "{}", err),
            _ => write!(f, "{}", self.as_str()),
        }
    }
}

#[cfg_attr(docs, doc(cfg(any(feature = "error_in_core", feature = "std"))))]
#[cfg(any(feature = "error_in_core", feature = "std"))]
impl error::Error for SealError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Unreachable(err) => Some(err),
            Self::BufferTooSmall(err) => Some(err),
            Self::InvalidNonceSize(err) => Some(err),
            _ => None,
        }
    }
}

impl From<BufferTooSmallError> for SealError {
    fn from(value: BufferTooSmallError) -> Self {
        SealError::BufferTooSmall(value)
    }
}

impl From<Unreachable> for SealError {
    fn from(value: Unreachable) -> Self {
        SealError::Unreachable(value)
    }
}

impl From<InvalidNonceSize> for SealError {
    fn from(value: InvalidNonceSize) -> Self {
        SealError::InvalidNonceSize(value)
    }
}

/// An error from an [`Aead`] open.
#[derive(Debug, Eq, PartialEq)]
pub enum OpenError {
    /// An unreachable code path has been taken.
    Unreachable(Unreachable),
    /// An unknown or internal error has occurred.
    Other(&'static str),
    /// The size of the key is incorrect.
    InvalidKeySize,
    /// The size of the nonce is incorrect.
    InvalidNonceSize(InvalidNonceSize),
    /// The size of the overhead is incorrect.
    InvalidOverheadSize,
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
}

impl OpenError {
    /// Returns a human-readable string describing the error.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unreachable(err) => err.as_str(),
            Self::Other(msg) => msg,
            Self::InvalidKeySize => "invalid key size",
            Self::InvalidNonceSize(err) => err.as_str(),
            Self::InvalidOverheadSize => "invalid overhead size",
            Self::PlaintextTooLong => "plaintext too long",
            Self::CiphertextTooLong => "ciphertext too long",
            Self::AdditionalDataTooLong => "additional data too long",
            Self::Authentication => "authentication error",
            Self::BufferTooSmall(err) => err.as_str(),
        }
    }
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable(err) => write!(f, "{}", err),
            Self::BufferTooSmall(err) => write!(f, "{}", err),
            Self::InvalidNonceSize(err) => write!(f, "{}", err),
            _ => write!(f, "{}", self.as_str()),
        }
    }
}

#[cfg_attr(docs, doc(cfg(any(feature = "error_in_core", feature = "std"))))]
#[cfg(any(feature = "error_in_core", feature = "std"))]
impl error::Error for OpenError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Unreachable(err) => Some(err),
            Self::BufferTooSmall(err) => Some(err),
            Self::InvalidNonceSize(err) => Some(err),
            _ => None,
        }
    }
}

impl From<BufferTooSmallError> for OpenError {
    fn from(value: BufferTooSmallError) -> Self {
        OpenError::BufferTooSmall(value)
    }
}

impl From<Unreachable> for OpenError {
    fn from(value: Unreachable) -> Self {
        OpenError::Unreachable(value)
    }
}

impl From<InvalidNonceSize> for OpenError {
    fn from(value: InvalidNonceSize) -> Self {
        OpenError::InvalidNonceSize(value)
    }
}

/// The lifetime of a cryptographic key.
///
/// It can be decremented to track usage. For example:
///
/// ```rust
/// # use crypto::aead::Lifetime;
/// let mut remain = Lifetime::Messages(3);
/// assert_eq!(remain, 3);
///
/// remain = remain.consume(1).expect("should be 2");
/// assert_eq!(remain, 2);
///
/// remain = remain.consume(1).expect("should be 1");
/// assert_eq!(remain, 1);
///
/// remain = remain.consume(1).expect("should be 0");
/// assert_eq!(remain, 0);
///
/// assert!(remain.consume(1).is_none());
/// ```
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Lifetime {
    /// The maximum number of messages that can be sealed.
    ///
    /// In other words, the maximum number of calls to
    /// [`Aead::seal`], etc.
    Messages(u64),
    /// The maximum number of bytes that can be encrypted.
    Bytes(u64),
}

impl Lifetime {
    const fn as_u64(self) -> u64 {
        match self {
            Self::Messages(x) => x,
            Self::Bytes(x) => x,
        }
    }

    /// Decrements the lifetime by the length of the plaintext,
    /// `bytes`.
    #[inline]
    #[must_use]
    pub fn consume(self, bytes: u64) -> Option<Self> {
        match self {
            Self::Messages(x) => x.checked_sub(1).map(Self::Messages),
            Self::Bytes(x) => x.checked_sub(bytes).map(Self::Bytes),
        }
    }
}

impl PartialEq<u64> for Lifetime {
    fn eq(&self, other: &u64) -> bool {
        self.as_u64() == *other
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
/// * Accept plaintexts at least 2³² - 1 octets (2³⁵ - 8 bits) long.
/// * Accept associated data at least 2³² - 1 (2³⁵ - 8 bits) octets
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

    /// The lifetime of a cryptographic key.
    const LIFETIME: Lifetime;

    /// The size in octets of a key used by this [`Aead`].
    ///
    /// Must be at least 16 octets and less than 2¹⁶ octets.
    type KeySize: ArrayLength + IsGreaterOrEqual<U16> + IsLess<U65536> + 'static;
    /// Shorthand for [`KeySize`][Self::KeySize].
    const KEY_SIZE: usize = Self::KeySize::USIZE;

    /// The size in octets of a nonce used by this [`Aead`].
    ///
    /// Must be less than 2¹⁶ octets.
    type NonceSize: ArrayLength + IsLess<U65536> + 'static;
    /// Shorthand for [`NonceSize`][Self::NonceSize].
    const NONCE_SIZE: usize = Self::NonceSize::USIZE;

    /// The size in octets of authentication overhead added to
    /// encrypted plaintexts.
    ///
    /// For regular AEADs, this is the size of the authentication
    /// tag. For other AEADs, like [`CommittingAead`], this is
    /// the size of the authentication tag and key committment.
    ///
    /// Must be at least 16 octets (128 bits).
    type Overhead: ArrayLength + 'static;
    /// Shorthand for [`Overhead`][Self::Overhead].
    const OVERHEAD: usize = Self::Overhead::USIZE;

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
    /// [`OVERHEAD`][Self::OVERHEAD] octets larger than
    /// [`MAX_PLAINTEXT_SIZE`][Self::MAX_PLAINTEXT_SIZE].
    const MAX_CIPHERTEXT_SIZE: u64 =
        match Self::MAX_PLAINTEXT_SIZE.checked_add(Self::OVERHEAD as u64) {
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
        + Sized
        + for<'a> TryFrom<&'a [u8], Error = InvalidNonceSize>;

    /// Creates a new [`Aead`].
    fn new(key: &Self::Key) -> Self;

    /// Encrypts and authenticates `plaintext`, writing the
    /// resulting ciphertext to `dst`.
    ///
    /// Only `plaintext.len()` + [`Self::OVERHEAD`] bytes of
    /// `dst` will be written to.
    ///
    /// # Requirements
    ///
    /// * `dst` must be at least [`Self::OVERHEAD`] bytes longer
    ///   than `plaintext`.
    /// * `nonce` must be exactly [`Self::NONCE_SIZE`] bytes
    ///   long.
    /// * `plaintext` must be at most [`Self::MAX_PLAINTEXT_SIZE`]
    ///   bytes long.
    /// * `additional_data` must be at most
    ///   [`Self::MAX_ADDITIONAL_DATA_SIZE`] bytes long.
    ///
    /// It must not be used more than permitted by its
    /// [`lifetime`][`Aead::LIFETIME`].
    fn seal(
        &self,
        dst: &mut [u8],
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), SealError> {
        check_seal_params::<Self>(dst, nonce, plaintext, additional_data)?;

        let out = &mut dst[..plaintext.len() + Self::OVERHEAD];
        out[..plaintext.len()].copy_from_slice(plaintext);
        let (out, overhead) = out.split_at_mut(out.len() - Self::OVERHEAD);
        self.seal_in_place(nonce, out, overhead, additional_data)
            // Encryption failed, make sure that we do not
            // release any invalid plaintext to the caller.
            .inspect_err(|_| out.zeroize())
    }

    /// Encrypts and authenticates `data` in-place.
    ///
    /// The authentication overhead is written to `overhead`.
    ///
    /// # Requirements
    ///
    /// * `nonce` must be exactly [`Self::NONCE_SIZE`] bytes
    ///   long.
    /// * `data` must be at most [`Self::MAX_PLAINTEXT_SIZE`]
    ///   bytes long.
    /// * `overhead` must be exactly [`Self::OVERHEAD`] bytes
    ///   long.
    /// * `additional_data` must be at most
    ///   [`Self::MAX_ADDITIONAL_DATA_SIZE`] bytes long.
    ///
    /// It must not be used more than permitted by its
    /// [`lifetime`][`Aead::LIFETIME`].
    fn seal_in_place(
        &self,
        nonce: &[u8],
        data: &mut [u8],
        overhead: &mut [u8],
        additional_data: &[u8],
    ) -> Result<(), SealError>;

    /// Decrypts and authenticates `ciphertext`, writing the
    /// resulting plaintext to `dst`.
    ///
    /// Only `ciphertext.len()` - [`Self::OVERHEAD`] bytes of
    /// `dst` will be written to.
    ///
    /// # Requirements
    ///
    /// * `dst` must be at least `ciphertext.len()` -
    ///   [`Self::OVERHEAD`] bytes long.
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
    ) -> Result<(), OpenError> {
        check_open_params::<Self>(dst, nonce, ciphertext, additional_data)?;

        let max = ciphertext.len() - Self::OVERHEAD;
        let (ciphertext, overhead) = ciphertext.split_at(max);
        let out = &mut dst[..max];
        out.copy_from_slice(ciphertext);
        self.open_in_place(nonce, out, overhead, additional_data)
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
    ///   [`Self::OVERHEAD`] bytes long.
    /// * `overhead` must be exactly [`Self::OVERHEAD`] bytes
    ///   long.
    /// * `additional_data` must be at most
    ///   [`Self::MAX_ADDITIONAL_DATA_SIZE`] bytes long.
    fn open_in_place(
        &self,
        nonce: &[u8],
        data: &mut [u8],
        overhead: &[u8],
        additional_data: &[u8],
    ) -> Result<(), OpenError>;
}

/// Shorthand for the `A::Key::Data`, which the compiler does not
/// understand without a good amount of hand holding.
pub(crate) type KeyData<A> = <<A as Aead>::Key as SecretKey>::Data;

const fn check_aead_params<A: Aead + ?Sized>() {
    debug_assert!(A::KEY_SIZE >= 16);
    debug_assert!(A::OVERHEAD >= 16);
    debug_assert!(A::MAX_PLAINTEXT_SIZE >= u32::MAX as u64);
    debug_assert!(A::MAX_CIPHERTEXT_SIZE == A::MAX_PLAINTEXT_SIZE + A::OVERHEAD as u64);
    debug_assert!(A::MAX_ADDITIONAL_DATA_SIZE >= u32::MAX as u64);
}

/// Checks that the parameters to [`Aead::seal`] have the correct
/// lengths, etc.
pub const fn check_seal_params<A: Aead + ?Sized>(
    dst: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    additional_data: &[u8],
) -> Result<(), SealError> {
    check_aead_params::<A>();

    let need = match plaintext.len().checked_add(A::OVERHEAD) {
        // Overflow.
        None => return Err(SealError::PlaintextTooLong),
        Some(n) => n,
    };
    if need > dst.len() {
        return Err(SealError::BufferTooSmall(BufferTooSmallError(Some(need))));
    }
    if nonce.len() != A::NONCE_SIZE {
        return Err(SealError::InvalidNonceSize(InvalidNonceSize));
    }
    if plaintext.len() as u64 > A::MAX_PLAINTEXT_SIZE {
        return Err(SealError::PlaintextTooLong);
    }
    if additional_data.len() as u64 > A::MAX_ADDITIONAL_DATA_SIZE {
        return Err(SealError::AdditionalDataTooLong);
    }
    Ok(())
}

/// Checks that the parameters to [`Aead::seal_in_place`] have
/// the correct lengths, etc.
pub const fn check_seal_in_place_params<A: Aead + ?Sized>(
    nonce: &[u8],
    data: &[u8],
    overhead: &[u8],
    additional_data: &[u8],
) -> Result<(), SealError> {
    check_aead_params::<A>();

    if nonce.len() != A::NONCE_SIZE {
        return Err(SealError::InvalidNonceSize(InvalidNonceSize));
    }
    if data.len() as u64 > A::MAX_PLAINTEXT_SIZE {
        return Err(SealError::PlaintextTooLong);
    }
    if overhead.len() > A::OVERHEAD {
        return Err(SealError::InvalidOverheadSize);
    }
    if additional_data.len() as u64 > A::MAX_ADDITIONAL_DATA_SIZE {
        return Err(SealError::AdditionalDataTooLong);
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
) -> Result<(), OpenError> {
    check_aead_params::<A>();

    let need = match ciphertext.len().checked_sub(A::OVERHEAD) {
        // If the ciphertext does not have a full tag, etc. it
        // cannot be authenticated.
        None => return Err(OpenError::Authentication),
        Some(n) => n,
    };
    if need > dst.len() {
        return Err(OpenError::BufferTooSmall(BufferTooSmallError(Some(need))));
    }
    if nonce.len() != A::NONCE_SIZE {
        return Err(OpenError::InvalidNonceSize(InvalidNonceSize));
    }
    // The case where the `ciphertext.len()` < `A::OVERHEAD` is
    // covered by the `match` expression above.
    if ciphertext.len() as u64 > A::MAX_CIPHERTEXT_SIZE {
        return Err(OpenError::CiphertextTooLong);
    }
    if additional_data.len() as u64 > A::MAX_ADDITIONAL_DATA_SIZE {
        return Err(OpenError::AdditionalDataTooLong);
    }
    Ok(())
}

/// Checks that the parameters to [`Aead::open_in_place`] have
/// the correct lengths, etc.
pub const fn check_open_in_place_params<A: Aead + ?Sized>(
    nonce: &[u8],
    data: &[u8],
    overhead: &[u8],
    additional_data: &[u8],
) -> Result<(), OpenError> {
    check_aead_params::<A>();

    if nonce.len() != A::NONCE_SIZE {
        return Err(OpenError::InvalidNonceSize(InvalidNonceSize));
    }
    if data.len() as u64 > A::MAX_PLAINTEXT_SIZE - A::OVERHEAD as u64 {
        return Err(OpenError::PlaintextTooLong);
    }
    if overhead.len() > A::OVERHEAD {
        return Err(OpenError::InvalidOverheadSize);
    }
    if additional_data.len() as u64 > A::MAX_ADDITIONAL_DATA_SIZE {
        return Err(OpenError::AdditionalDataTooLong);
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
    type Error = InvalidNonceSize;

    fn try_from(data: &[u8]) -> Result<Self, InvalidNonceSize> {
        let nonce = data.try_into().map_err(|_| InvalidNonceSize)?;
        Ok(Self(nonce))
    }
}

/// A marker trait signifying that the [`Aead`] is IND-CCA2
/// secure.
pub trait IndCca2: Aead {}

/// A marker trait signifying that the [`Aead`] is committing.
pub trait CommittingAead: Aead {}

/// A marker trait signifying that the [`Aead`] is CMT-1 secure.
///
/// It provides a commitment over the key and nothing else.
pub trait Cmt1Aead: CommittingAead {}

/// A marker trait signifying that the [`Aead`] is CMT-3 secure.
///
/// It provides a commitment over the key, nonce, and additional
/// data, but not plaintext.
pub trait Cmt3Aead: Cmt1Aead {}

/// A marker trait signifying that the [`Aead`] is CMT-4 secure.
///
/// It provides a commitment over everything: the key, nonce,
/// plaintext, and additional data.
pub trait Cmt4Aead: Cmt3Aead {}

#[cfg(feature = "committing-aead")]
mod committing {
    use core::{
        borrow::{Borrow, BorrowMut},
        cmp,
        marker::PhantomData,
        num::NonZeroU64,
        result::Result,
    };

    use generic_array::{ArrayLength, GenericArray};
    use typenum::{
        type_operators::{IsGreaterOrEqual, IsLess},
        Unsigned, U16, U65536,
    };

    use super::{Aead, KeyData};
    use crate::error::{safe_unreachable, Unreachable};

    /// A symmetric block cipher.
    #[doc(hidden)]
    pub trait BlockCipher {
        /// The size in octets of a the cipher's block.
        type BlockSize: ArrayLength + IsGreaterOrEqual<U16> + IsLess<U65536> + 'static;
        /// Shorthand for [`BlockSize::USIZE`][Self::BlockSize];
        const BLOCK_SIZE: usize = Self::BlockSize::USIZE;
        /// The cipher's key.
        type Key;

        /// Creates a new instance of the block cipher.
        fn new(key: &Self::Key) -> Self;
        /// Encrypts `block` in place.
        fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>);
    }

    /// An implementation of the Counter-then-Xor (CX) PRF per
    /// [bellare].
    ///
    /// [bellare]: https://eprint.iacr.org/2022/268
    pub(crate) struct CtrThenXorPrf<A, C> {
        _aead: PhantomData<A>,
        _cipher: PhantomData<C>,
    }

    impl<A, C> CtrThenXorPrf<A, C>
    where
        A: Aead,
        C: BlockCipher<Key = A::Key>,
        // The paper requires m < n where m is the nonce space
        // and n is the block size.
        A::NonceSize: IsLess<C::BlockSize>,
        GenericArray<u8, C::BlockSize>: Clone,
    {
        /// Returns the key commitment and new key (P,L) for
        /// (K,M).
        #[inline]
        #[allow(clippy::type_complexity)] // internal method
        pub fn commit(
            key: &A::Key,
            nonce: &A::Nonce,
        ) -> Result<(GenericArray<u8, C::BlockSize>, KeyData<A>), Unreachable> {
            let mut cx = Default::default();
            let key = Self::commit_into(&mut cx, key, nonce)?;
            Ok((cx, key))
        }

        /// Same as [`commit`][Self::commit], but writes directly
        /// to `cx`.
        pub fn commit_into(
            cx: &mut GenericArray<u8, C::BlockSize>,
            key: &A::Key,
            nonce: &A::Nonce,
        ) -> Result<KeyData<A>, Unreachable> {
            /// Pad is a one-to-one encoding that converts the
            /// pair (M,i) in {0,1}^m x {1,...,2^(n-m)} into an
            /// n-bit string.
            ///
            /// We let `i` be a `u64` since it's large enough to
            /// never overflow.
            #[inline(always)]
            fn pad<C: BlockCipher>(m: &[u8], i: NonZeroU64) -> GenericArray<u8, C::BlockSize> {
                // This is checked by `Self`'s generic bounds, but it
                // doesn't hurt to double check.
                debug_assert!(m.len() < C::BlockSize::USIZE);

                let mut b = GenericArray::<u8, C::BlockSize>::default();
                b[..m.len()].copy_from_slice(m);
                let x = i.get().to_le_bytes();
                let n = cmp::min(b.len() - m.len(), x.len());
                b[m.len()..].copy_from_slice(&x[..n]);
                b
            }

            let mut i = NonZeroU64::MIN;
            let cipher = C::new(key);
            let nonce = nonce.borrow();

            let v_1 = {
                // X_i <- pad(M, i)
                let x_1 = pad::<C>(nonce, i);

                // V_i <- E_k(X_i);
                let mut v_1 = {
                    // Make a copy since we need `x_1` for the
                    // XOR.
                    let mut tmp = x_1.clone();
                    cipher.encrypt_block(&mut tmp);
                    tmp
                };

                // V_1 = V_1 ^ X_1;
                for (v, x) in v_1.iter_mut().zip(x_1.iter()) {
                    *v ^= x;
                }
                v_1
            };
            cx.copy_from_slice(&v_1);

            let mut key = KeyData::<A>::default();
            for chunk in key.borrow_mut().chunks_mut(C::BLOCK_SIZE) {
                i = i
                    .checked_add(1)
                    // It should be impossible to overflow. At
                    // one nanosecond per op, this will take
                    // upward of 500 years.
                    .ok_or_else(|| safe_unreachable!("should be impossible to overflow"))?;

                // V_i <- E_k(X_i);
                let v_i = {
                    // X_i <- pad(M, i)
                    let mut x_i = pad::<C>(nonce, i);
                    cipher.encrypt_block(&mut x_i);
                    x_i
                };
                chunk.copy_from_slice(&v_i[..chunk.len()]);
            }
            Ok(key)
        }
    }

    /// Implements the UNAE-Then-Commit (UtC) transform to turn
    /// a standard AEAD (that implements [`CtrThenXorPrf`]) into
    /// a CMT-1 AEAD.
    macro_rules! utc_aead {
        ($name:ident, $inner:ty, $cipher:ty, $doc:expr) => {
            #[doc = $doc]
            #[cfg_attr(docs, doc(cfg(feature = "committing-aead")))]
            pub struct $name {
                key: <$inner as $crate::aead::Aead>::Key,
            }

            impl $name {
                const COMMITMENT_SIZE: usize = <<$cipher as $crate::aead::BlockCipher>::BlockSize as
                                                                        ::typenum::Unsigned>::USIZE;
            }

            #[cfg_attr(docs, doc(cfg(feature = "committing-aead")))]
            impl $crate::aead::CommittingAead for $name {}

            #[cfg_attr(docs, doc(cfg(feature = "committing-aead")))]
            impl $crate::aead::Cmt1Aead for $name {}

            #[cfg_attr(docs, doc(cfg(feature = "committing-aead")))]
            impl $crate::aead::Aead for $name {
                const ID: $crate::aead::AeadId = $crate::aead::AeadId::$name;
                const LIFETIME: $crate::aead::Lifetime = <$inner as $crate::aead::Aead>::LIFETIME;

                type KeySize = <$inner as $crate::aead::Aead>::KeySize;
                type NonceSize = <$inner as $crate::aead::Aead>::NonceSize;
                type Overhead = ::typenum::Sum<
                    <$inner as $crate::aead::Aead>::Overhead,
                    // UtC has one block of overhead.
                    <$cipher as $crate::aead::BlockCipher>::BlockSize,
                >;

                const MAX_PLAINTEXT_SIZE: u64 = <$inner as $crate::aead::Aead>::MAX_PLAINTEXT_SIZE;
                const MAX_ADDITIONAL_DATA_SIZE: u64 =
                    <$inner as $crate::aead::Aead>::MAX_ADDITIONAL_DATA_SIZE;

                type Key = <$inner as $crate::aead::Aead>::Key;
                type Nonce = <$inner as $crate::aead::Aead>::Nonce;

                #[inline]
                fn new(key: &Self::Key) -> Self {
                    Self { key: key.clone() }
                }

                fn seal(
                    &self,
                    dst: &mut [u8],
                    nonce: &[u8],
                    plaintext: &[u8],
                    additional_data: &[u8],
                ) -> ::core::result::Result<(), $crate::aead::SealError> {
                    $crate::aead::check_seal_params::<Self>(
                        dst,
                        nonce,
                        plaintext,
                        additional_data,
                    )?;

                    let out = &mut dst[..plaintext.len() + Self::OVERHEAD];
                    let (out, cx) = out.split_at_mut(out.len() - $name::COMMITMENT_SIZE);
                    let key = $crate::aead::CtrThenXorPrf::<$inner, $cipher>::commit_into(
                        cx.try_into().map_err(|_| {
                            $crate::error::safe_unreachable!("should be exactly `COMMITTMENT_SIZE`")
                        })?,
                        &self.key,
                        &nonce.try_into()?,
                    )?;
                    <$inner as $crate::aead::Aead>::new(&key).seal(
                        out,
                        nonce,
                        plaintext,
                        additional_data,
                    )
                }

                fn seal_in_place(
                    &self,
                    nonce: &[u8],
                    data: &mut [u8],
                    overhead: &mut [u8],
                    additional_data: &[u8],
                ) -> ::core::result::Result<(), $crate::aead::SealError> {
                    $crate::aead::check_seal_in_place_params::<Self>(
                        nonce,
                        data,
                        overhead,
                        additional_data,
                    )?;

                    let (tag, cx) = overhead.split_at_mut(overhead.len() - $name::COMMITMENT_SIZE);
                    let key = $crate::aead::CtrThenXorPrf::<$inner, $cipher>::commit_into(
                        cx.try_into().map_err(|_| {
                            $crate::error::safe_unreachable!("should be exactly `COMMITTMENT_SIZE`")
                        })?,
                        &self.key,
                        &nonce.try_into()?,
                    )?;
                    <$inner as $crate::aead::Aead>::new(&key).seal_in_place(
                        nonce,
                        data,
                        tag,
                        additional_data,
                    )
                }

                fn open(
                    &self,
                    dst: &mut [u8],
                    nonce: &[u8],
                    ciphertext: &[u8],
                    additional_data: &[u8],
                ) -> ::core::result::Result<(), $crate::aead::OpenError> {
                    $crate::aead::check_open_params::<Self>(
                        dst,
                        nonce,
                        ciphertext,
                        additional_data,
                    )?;

                    let (ciphertext, got_cx) =
                        ciphertext.split_at(ciphertext.len() - $name::COMMITMENT_SIZE);
                    let (want_cx, key) = $crate::aead::CtrThenXorPrf::<$inner, $cipher>::commit(
                        &self.key,
                        &nonce.try_into()?,
                    )?;
                    if !bool::from(::subtle::ConstantTimeEq::ct_eq(
                        ::core::borrow::Borrow::borrow(&want_cx),
                        got_cx,
                    )) {
                        Err($crate::aead::OpenError::Authentication)
                    } else {
                        <$inner as $crate::aead::Aead>::new(&key).open(
                            dst,
                            nonce,
                            ciphertext,
                            additional_data,
                        )
                    }
                }

                fn open_in_place(
                    &self,
                    nonce: &[u8],
                    data: &mut [u8],
                    overhead: &[u8],
                    additional_data: &[u8],
                ) -> ::core::result::Result<(), $crate::aead::OpenError> {
                    $crate::aead::check_open_in_place_params::<Self>(
                        nonce,
                        data,
                        overhead,
                        additional_data,
                    )?;

                    let (overhead, got_cx) =
                        overhead.split_at(overhead.len() - $name::COMMITMENT_SIZE);
                    let (want_cx, key) = $crate::aead::CtrThenXorPrf::<$inner, $cipher>::commit(
                        &self.key,
                        &nonce.try_into()?,
                    )?;
                    if !bool::from(::subtle::ConstantTimeEq::ct_eq(
                        ::core::borrow::Borrow::borrow(&want_cx),
                        got_cx,
                    )) {
                        Err($crate::aead::OpenError::Authentication)
                    } else {
                        <$inner as $crate::aead::Aead>::new(&key).open_in_place(
                            nonce,
                            data,
                            overhead,
                            additional_data,
                        )
                    }
                }
            }
        };
    }
    pub(crate) use utc_aead;

    /// Implements the Hash-then-Encrypt (HtE) transform to turn
    /// a CMT-1 AEAD into a CMT-4 AEAD.
    macro_rules! hte_aead {
        ($name:ident, $inner:ty, $hash:ty, $doc:expr) => {
            #[doc = $doc]
            #[cfg_attr(docs, doc(cfg(feature = "committing-aead")))]
            pub struct $name {
                key: <$inner as $crate::aead::Aead>::Key,
            }

            impl $name {
                fn hash(&self, nonce: &[u8], ad: &[u8]) -> $crate::aead::KeyData<$inner> {
                    // The nonce length is fixed, so use
                    // HMAC(K || N || A)[1 : k] per Theorem 3.2.
                    let tag = {
                        let mut hmac = $crate::hmac::Hmac::<
                            $hash,
                            {
                                <<$inner as $crate::aead::Aead>::KeySize as
                                                                    ::typenum::Unsigned>::USIZE
                            },
                        >::new(&self.key.as_bytes()[..]);
                        hmac.update(nonce);
                        hmac.update(ad);
                        hmac.tag()
                    };
                    let mut key = $crate::aead::KeyData::<$inner>::default();
                    let k = ::core::cmp::min(
                        tag.len(),
                        ::core::borrow::Borrow::<[u8]>::borrow(&key).len(),
                    );
                    ::core::borrow::BorrowMut::<[u8]>::borrow_mut(&mut key)
                        .copy_from_slice(&tag.as_bytes()[..k]);
                    key
                }
            }

            // The `where` bound is important as it enforces the
            // requirement that `$inner` be a CMT-1 AEAD.
            #[cfg_attr(docs, doc(cfg(feature = "committing-aead")))]
            impl $crate::aead::CommittingAead for $name where $inner: $crate::aead::Cmt1Aead {}

            #[cfg_attr(docs, doc(cfg(feature = "committing-aead")))]
            impl $crate::aead::Cmt1Aead for $name {}

            #[cfg_attr(docs, doc(cfg(feature = "committing-aead")))]
            impl $crate::aead::Cmt3Aead for $name {}

            #[cfg_attr(docs, doc(cfg(feature = "committing-aead")))]
            impl $crate::aead::Cmt4Aead for $name where $inner: $crate::aead::Cmt1Aead {}

            #[cfg_attr(docs, doc(cfg(feature = "committing-aead")))]
            impl $crate::aead::Aead for $name {
                const ID: $crate::aead::AeadId = $crate::aead::AeadId::$name;
                const LIFETIME: $crate::aead::Lifetime = <$inner as $crate::aead::Aead>::LIFETIME;

                type KeySize = <$inner as $crate::aead::Aead>::KeySize;
                type NonceSize = <$inner as $crate::aead::Aead>::NonceSize;
                // HtE has no additional overhead.
                type Overhead = <$inner as $crate::aead::Aead>::Overhead;

                const MAX_PLAINTEXT_SIZE: u64 = <$inner as $crate::aead::Aead>::MAX_PLAINTEXT_SIZE;
                const MAX_ADDITIONAL_DATA_SIZE: u64 =
                    <$inner as $crate::aead::Aead>::MAX_ADDITIONAL_DATA_SIZE;

                type Key = <$inner as $crate::aead::Aead>::Key;
                type Nonce = <$inner as $crate::aead::Aead>::Nonce;

                #[inline]
                fn new(key: &Self::Key) -> Self {
                    Self { key: key.clone() }
                }

                fn seal(
                    &self,
                    dst: &mut [u8],
                    nonce: &[u8],
                    plaintext: &[u8],
                    additional_data: &[u8],
                ) -> ::core::result::Result<(), $crate::aead::SealError> {
                    $crate::aead::check_seal_params::<Self>(
                        dst,
                        nonce,
                        plaintext,
                        additional_data,
                    )?;

                    let out = &mut dst[..plaintext.len() + Self::OVERHEAD];
                    let key = self.hash(nonce, additional_data);
                    <$inner as $crate::aead::Aead>::new(&key).seal(
                        out,
                        nonce,
                        plaintext,
                        additional_data,
                    )
                }

                fn seal_in_place(
                    &self,
                    nonce: &[u8],
                    data: &mut [u8],
                    overhead: &mut [u8],
                    additional_data: &[u8],
                ) -> ::core::result::Result<(), $crate::aead::SealError> {
                    $crate::aead::check_seal_in_place_params::<Self>(
                        nonce,
                        data,
                        overhead,
                        additional_data,
                    )?;

                    let key = self.hash(nonce, additional_data);
                    <$inner as $crate::aead::Aead>::new(&key).seal_in_place(
                        nonce,
                        data,
                        overhead,
                        additional_data,
                    )
                }

                fn open(
                    &self,
                    dst: &mut [u8],
                    nonce: &[u8],
                    ciphertext: &[u8],
                    additional_data: &[u8],
                ) -> ::core::result::Result<(), $crate::aead::OpenError> {
                    $crate::aead::check_open_params::<Self>(
                        dst,
                        nonce,
                        ciphertext,
                        additional_data,
                    )?;

                    let key = self.hash(nonce, additional_data);
                    <$inner as $crate::aead::Aead>::new(&key).open(
                        dst,
                        nonce,
                        ciphertext,
                        additional_data,
                    )
                }

                fn open_in_place(
                    &self,
                    nonce: &[u8],
                    data: &mut [u8],
                    overhead: &[u8],
                    additional_data: &[u8],
                ) -> ::core::result::Result<(), $crate::aead::OpenError> {
                    $crate::aead::check_open_in_place_params::<Self>(
                        nonce,
                        data,
                        overhead,
                        additional_data,
                    )?;

                    let key = self.hash(nonce, additional_data);
                    <$inner as $crate::aead::Aead>::new(&key).open_in_place(
                        nonce,
                        data,
                        overhead,
                        additional_data,
                    )
                }
            }
        };
    }
    pub(crate) use hte_aead;
}
#[cfg(feature = "committing-aead")]
#[cfg_attr(docs, doc(cfg(feature = "committing-aead")))]
pub use committing::*;
