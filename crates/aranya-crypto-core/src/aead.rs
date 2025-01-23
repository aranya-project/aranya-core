//! Authenticated Encryption with Additional Associated Data per
//! [RFC 5116].
//!
//! [RFC 5116]: https://www.rfc-editor.org/rfc/rfc5116

use core::{
    cmp::{Eq, PartialEq},
    fmt::{self, Debug},
    iter::IntoIterator,
    mem::{self, size_of},
    ops::{BitXor, Deref, DerefMut},
    result::Result,
};

use aranya_buggy::{Bug, BugExt};
use generic_array::{ArrayLength, GenericArray, IntoArrayLength};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};
use typenum::{
    generic_const_mappings::Const,
    type_operators::{IsGreaterOrEqual, IsLess},
    Unsigned, U16, U65536,
};

#[doc(inline)]
pub use crate::hpke::AeadId;
use crate::{
    csprng::{Csprng, Random},
    kdf::{Expand, Kdf, KdfError, Prk},
    keys::{raw_key, SecretKey, SecretKeyBytes},
    util::const_assert,
    zeroize::Zeroize,
};

// Some of the bounds for `Aead` are at least 32 bits, prevent
// the crate from being built for, e.g., a 16-bit CPU. If we ever
// need to support such a CPU we will need to revisit the API.
const_assert!(size_of::<usize>() >= 4);

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

impl core::error::Error for BufferTooSmallError {}

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

impl core::error::Error for InvalidNonceSize {}

/// An error from an [`Aead`] seal.
#[derive(Debug, Eq, PartialEq)]
pub enum SealError {
    /// An internal bug was discovered.
    Bug(Bug),
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
            Self::Bug(err) => err.msg(),
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
            Self::Bug(err) => write!(f, "{}", err),
            Self::BufferTooSmall(err) => write!(f, "{}", err),
            Self::InvalidNonceSize(err) => write!(f, "{}", err),
            _ => write!(f, "{}", self.as_str()),
        }
    }
}

impl core::error::Error for SealError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Bug(err) => Some(err),
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

impl From<Bug> for SealError {
    fn from(value: Bug) -> Self {
        SealError::Bug(value)
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
    /// An internal bug was discovered.
    Bug(Bug),
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
            Self::Bug(err) => err.msg(),
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
            Self::Bug(err) => write!(f, "{}", err),
            Self::BufferTooSmall(err) => write!(f, "{}", err),
            Self::InvalidNonceSize(err) => write!(f, "{}", err),
            _ => write!(f, "{}", self.as_str()),
        }
    }
}

impl core::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Bug(err) => Some(err),
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

impl From<Bug> for OpenError {
    fn from(value: Bug) -> Self {
        OpenError::Bug(value)
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
/// # use aranya_crypto_core::aead::Lifetime;
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
    /// The key can handle an unlimited number of messages or
    /// bytes.
    Unlimited,
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
            Self::Unlimited => u64::MAX,
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
            Self::Unlimited => Some(Self::Unlimited),
            Self::Messages(x) => x.checked_sub(1).map(Self::Messages),
            Self::Bytes(x) => x.checked_sub(bytes).map(Self::Bytes),
        }
    }

    /// Decrements the lifetime by the length of the plaintext,
    /// `bytes`.
    #[inline]
    #[must_use]
    pub fn consume_mut(&mut self, bytes: u64) -> bool {
        self.consume(bytes).inspect(|v| *self = *v).is_some()
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
    /// the size of the authentication tag and key commitment.
    ///
    /// Must be at least 16 octets (128 bits).
    type Overhead: ArrayLength + IsGreaterOrEqual<U16> + 'static;
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
    type Key: SecretKey<Size = Self::KeySize>;

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
        mut dst: &mut [u8],
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), SealError> {
        check_seal_params::<Self>(&mut dst, nonce, plaintext, additional_data)?;
        dst[..plaintext.len()].copy_from_slice(plaintext);
        let tag_idx = dst
            .len()
            .checked_sub(Self::OVERHEAD)
            .assume("out length must be >= overhead")?;
        let (dst, overhead) = dst.split_at_mut(tag_idx);
        self.seal_in_place(nonce, dst, overhead, additional_data)
            // Encryption failed, make sure that we do not
            // release any invalid plaintext to the caller.
            .inspect_err(|_| dst.zeroize())
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

        let max = ciphertext.len().checked_sub(Self::OVERHEAD).assume(
            "`ciphertext.len() >= Self::OVERHEAD` should be enforced by `check_open_params`",
        )?;
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

/// Shorthand which the compiler does not understand without
/// a good amount of hand holding.
pub type KeyData<A> = SecretKeyBytes<<<A as Aead>::Key as SecretKey>::Size>;

/// An authentication tag.
pub type Tag<A> = GenericArray<u8, <A as Aead>::Overhead>;

const fn check_aead_params<A: Aead + ?Sized>() {
    const {
        assert!(A::KEY_SIZE >= 16);
        assert!(A::OVERHEAD >= 16);
        assert!(A::MAX_PLAINTEXT_SIZE >= u32::MAX as u64);
        assert!(A::MAX_CIPHERTEXT_SIZE == A::MAX_PLAINTEXT_SIZE + (A::OVERHEAD as u64));
        assert!(A::MAX_ADDITIONAL_DATA_SIZE >= u32::MAX as u64);
    }
}

/// Checks that the parameters to [`Aead::seal`] have the correct
/// lengths, etc.
///
/// Trims `dst` to `..plaintext.len() + A::OVERHEAD` if correctly sized.
pub fn check_seal_params<A: Aead + ?Sized>(
    dst: &mut &mut [u8],
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
    *dst = &mut mem::take(dst)[..need];

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
    let Some(max_len) = A::MAX_PLAINTEXT_SIZE.checked_sub(A::OVERHEAD as u64) else {
        return Err(OpenError::Other(
            "implementation bug: `Aead::MAX_PLAINTEXT_SIZE < Aead::OVERHEAD`",
        ));
    };
    if data.len() as u64 > max_len {
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

impl<N: ArrayLength> AeadKey<N> {
    // Used by `crate::rust::Aes256Gcm::new`.
    pub(crate) fn as_array<const U: usize>(&self) -> &[u8; U]
    where
        Const<U>: IntoArrayLength<ArrayLength = N>,
    {
        self.0.as_array()
    }
}

/// An [`Aead`] nonce.
#[derive(Clone, Default, Hash, Eq, PartialEq, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(bound = "")]
#[serde(transparent)]
pub struct Nonce<N: ArrayLength>(GenericArray<u8, N>);

impl<N: ArrayLength> Nonce<N> {
    /// The size in octets of the nonce.
    pub const SIZE: usize = N::USIZE;

    /// Returns the size in octets of the nonce.
    #[inline]
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        Self::SIZE
    }

    pub(crate) const fn from_bytes(nonce: GenericArray<u8, N>) -> Self {
        Self(nonce)
    }

    pub(crate) fn try_from_slice(data: &[u8]) -> Result<Self, InvalidNonceSize> {
        let nonce = GenericArray::try_from_slice(data).map_err(|_| InvalidNonceSize)?;
        Ok(Self(nonce.clone()))
    }
}

impl<N: ArrayLength> Copy for Nonce<N> where N::ArrayType<u8>: Copy {}

impl<N: ArrayLength> Debug for Nonce<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Nonce").field(&self.0).finish()
    }
}

impl<N: ArrayLength> Deref for Nonce<N> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<N: ArrayLength> DerefMut for Nonce<N> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<N: ArrayLength> BitXor for Nonce<N> {
    type Output = Self;

    #[inline]
    fn bitxor(mut self, rhs: Self) -> Self::Output {
        for (x, y) in self.0.iter_mut().zip(&rhs.0) {
            *x ^= y;
        }
        self
    }
}

impl<N: ArrayLength> BitXor for &Nonce<N> {
    type Output = Nonce<N>;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut lhs = self.clone();
        for (x, y) in lhs.0.iter_mut().zip(&rhs.0) {
            *x ^= y;
        }
        lhs
    }
}

impl<N: ArrayLength> ConstantTimeEq for Nonce<N> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<N: ArrayLength> Random for Nonce<N> {
    fn random<R: Csprng>(rng: &mut R) -> Self {
        Self(Random::random(rng))
    }
}

impl<N: ArrayLength> Expand for Nonce<N>
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

impl<N: ArrayLength> TryFrom<&[u8]> for Nonce<N> {
    type Error = InvalidNonceSize;

    fn try_from(data: &[u8]) -> Result<Self, InvalidNonceSize> {
        Self::try_from_slice(data)
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
    use core::{fmt, marker::PhantomData, num::NonZeroU64, result::Result};

    use aranya_buggy::{Bug, BugExt};
    use generic_array::{ArrayLength, GenericArray};
    use typenum::{
        type_operators::{IsGreaterOrEqual, IsLess},
        Unsigned, U16, U65536,
    };

    use super::{Aead, KeyData, Nonce, OpenError, SealError};
    use crate::import::{ExportError, ImportError};

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
    #[doc(hidden)]
    pub struct CtrThenXorPrf<A, C> {
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
            nonce: &Nonce<A::NonceSize>,
        ) -> Result<(GenericArray<u8, C::BlockSize>, KeyData<A>), Bug> {
            let mut cx = Default::default();
            let key = Self::commit_into(&mut cx, key, nonce)?;
            Ok((cx, key))
        }

        /// Same as [`commit`][Self::commit], but writes directly
        /// to `cx`.
        pub fn commit_into(
            cx: &mut GenericArray<u8, C::BlockSize>,
            key: &A::Key,
            nonce: &Nonce<A::NonceSize>,
        ) -> Result<KeyData<A>, Bug> {
            /// Pad is a one-to-one encoding that converts the
            /// pair (M,i) in {0,1}^m x {1,...,2^(n-m)} into an
            /// n-bit string.
            ///
            /// We let `i` be a `u64` since it's large enough to
            /// never overflow.
            #[inline(always)]
            fn pad<C: BlockCipher>(
                m: &[u8],
                i: NonZeroU64,
            ) -> Result<GenericArray<u8, C::BlockSize>, Bug> {
                // This is checked by `Self`'s generic bounds, but it
                // doesn't hurt to double check.
                debug_assert!(m.len() < C::BlockSize::USIZE);

                let mut b = GenericArray::<u8, C::BlockSize>::default();
                b[..m.len()].copy_from_slice(m);
                let x = i.get().to_le_bytes();
                let n = usize::checked_sub(b.len(), m.len())
                    .assume("nonce size <= block size")?
                    .min(x.len());
                b[m.len()..].copy_from_slice(&x[..n]);
                Ok(b)
            }

            let mut i = NonZeroU64::MIN;
            let cipher = C::new(key);
            let nonce = nonce.as_ref();

            let v_1 = {
                // X_i <- pad(M, i)
                let x_1 = pad::<C>(nonce, i)?;

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
            for chunk in key.as_bytes_mut().chunks_mut(C::BLOCK_SIZE) {
                i = i
                    .checked_add(1)
                    // It should be impossible to overflow. At
                    // one nanosecond per op, this will take
                    // upward of 500 years.
                    .assume("should be impossible to overflow")?;

                // V_i <- E_k(X_i);
                let v_i = {
                    // X_i <- pad(M, i)
                    let mut x_i = pad::<C>(nonce, i)?;
                    cipher.encrypt_block(&mut x_i);
                    x_i
                };
                chunk.copy_from_slice(&v_i[..chunk.len()]);
            }
            Ok(key)
        }
    }

    /// An error occurred during the UNAE-then-Commit transform.
    #[derive(Debug, Eq, PartialEq)]
    pub enum UtcError {
        /// An internal bug was discovered.
        Bug(Bug),
        /// The transformed AEAD key could not be imported.
        Import(ImportError),
    }

    impl UtcError {
        const fn as_str(&self) -> &'static str {
            match self {
                Self::Bug(_) => "bug",
                Self::Import(_) => "unable to import HtE transformed key",
            }
        }
    }

    impl fmt::Display for UtcError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Bug(err) => write!(f, "{}: {err}", self.as_str()),
                Self::Import(err) => write!(f, "{}: {err}", self.as_str()),
            }
        }
    }

    impl core::error::Error for UtcError {
        fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
            match self {
                Self::Bug(err) => Some(err),
                Self::Import(err) => Some(err),
            }
        }
    }

    impl From<Bug> for UtcError {
        fn from(err: Bug) -> Self {
            Self::Bug(err)
        }
    }

    impl From<ImportError> for UtcError {
        fn from(err: ImportError) -> Self {
            Self::Import(err)
        }
    }

    impl From<UtcError> for SealError {
        fn from(err: UtcError) -> SealError {
            SealError::Other(err.as_str())
        }
    }

    impl From<UtcError> for OpenError {
        fn from(err: UtcError) -> OpenError {
            OpenError::Other(err.as_str())
        }
    }

    /// Implements the UNAE-Then-Commit (UtC) transform to turn
    /// a standard AEAD into a CMT-1 AEAD.
    ///
    /// - `name`: The name of the resulting [`Aead`].
    /// - `inner`: The underlying [`Aead`].
    /// - `cipher`: The underlying [`BlockCipher`].
    /// - `doc`: A string to use for documentation.
    ///
    /// # ⚠️ Warning
    /// <div class="warning">
    /// This is a low-level feature. You should not be using it
    /// unless you understand what you are doing.
    /// </div>
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// # #[cfg(feature = "committing-aead")]
    /// # {
    /// use aranya_crypto_core::utc_aead;
    /// utc_aead!(Cmt1Aes256Gcm, Aes256Gcm, Aes256, "CMT-1 AES-256-GCM.");
    /// # }
    /// ```
    #[cfg_attr(feature = "committing-aead", macro_export)]
    #[cfg_attr(docsrs, doc(cfg(feature = "committing-aead")))]
    macro_rules! utc_aead {
        ($name:ident, $inner:ty, $cipher:ty, $doc:expr) => {
            #[doc = $doc]
            pub struct $name {
                key: <$inner as $crate::aead::Aead>::Key,
            }

            impl $name {
                const COMMITMENT_SIZE: usize = <<$cipher as $crate::aead::BlockCipher>::BlockSize as
                                                                        $crate::typenum::Unsigned>::USIZE;
            }

            impl $crate::aead::CommittingAead for $name {}

            impl $crate::aead::Cmt1Aead for $name {}

            impl $crate::aead::Aead for $name {
                const ID: $crate::aead::AeadId = $crate::aead::AeadId::$name;
                const LIFETIME: $crate::aead::Lifetime = <$inner as $crate::aead::Aead>::LIFETIME;

                type KeySize = <$inner as $crate::aead::Aead>::KeySize;
                type NonceSize = <$inner as $crate::aead::Aead>::NonceSize;
                type Overhead = $crate::typenum::Sum<
                    <$inner as $crate::aead::Aead>::Overhead,
                    // UtC has one block of overhead.
                    <$cipher as $crate::aead::BlockCipher>::BlockSize,
                >;

                const MAX_PLAINTEXT_SIZE: u64 = <$inner as $crate::aead::Aead>::MAX_PLAINTEXT_SIZE;
                const MAX_ADDITIONAL_DATA_SIZE: u64 =
                    <$inner as $crate::aead::Aead>::MAX_ADDITIONAL_DATA_SIZE;

                type Key = <$inner as $crate::aead::Aead>::Key;

                #[inline]
                fn new(key: &Self::Key) -> Self {
                    Self { key: key.clone() }
                }

                fn seal(
                    &self,
                    mut dst: &mut [u8],
                    nonce: &[u8],
                    plaintext: &[u8],
                    additional_data: &[u8],
                ) -> ::core::result::Result<(), $crate::aead::SealError> {
                    $crate::aead::check_seal_params::<Self>(
                        &mut dst,
                        nonce,
                        plaintext,
                        additional_data,
                    )?;

                    let (dst, cx) = $crate::aranya_buggy::BugExt::assume(
                        dst.split_last_chunk_mut::<{Self::COMMITMENT_SIZE}>(),
                        "`COMMITMENT_SIZE` fits in `out`",
                    )?;
                    let key_bytes = $crate::aead::CtrThenXorPrf::<$inner, $cipher>::commit_into(
                        cx.into(),
                        &self.key,
                        &nonce.try_into()?,
                    )?;
                    let key = $crate::import::Import::<_>::import(key_bytes.as_bytes())
                        .map_err($crate::aead::UtcError::Import)?;
                    <$inner as $crate::aead::Aead>::new(&key).seal(
                        dst,
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

                    let (tag, cx) = $crate::aranya_buggy::BugExt::assume(
                        overhead.split_last_chunk_mut::<{Self::COMMITMENT_SIZE}>(),
                        "`COMMITMENT_SIZE` fits in `overhead`",
                    )?;
                    let key_bytes = $crate::aead::CtrThenXorPrf::<$inner, $cipher>::commit_into(
                        cx.into(),
                        &self.key,
                        &nonce.try_into()?,
                    )?;
                    let key = $crate::import::Import::<_>::import(key_bytes.as_bytes())
                        .map_err($crate::aead::UtcError::Import)?;
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

                    let (ciphertext, got_cx) = $crate::aranya_buggy::BugExt::assume(
                        ciphertext.split_last_chunk::<{Self::COMMITMENT_SIZE}>(),
                        "`COMMITMENT_SIZE` fits in `ciphertext`",
                    )?;
                    let (want_cx, key_bytes) = $crate::aead::CtrThenXorPrf::<$inner, $cipher>::commit(
                        &self.key,
                        &nonce.try_into()?,
                    )?;
                    if !bool::from($crate::subtle::ConstantTimeEq::ct_eq(
                        want_cx.as_slice(),
                        got_cx,
                    )) {
                        Err($crate::aead::OpenError::Authentication)
                    } else {
                        let key = $crate::import::Import::<_>::import(key_bytes.as_bytes())
                            .map_err($crate::aead::UtcError::Import)?;
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

                    let (overhead, got_cx) = $crate::aranya_buggy::BugExt::assume(
                        overhead.split_last_chunk::<{Self::COMMITMENT_SIZE}>(),
                        "`COMMITMENT_SIZE` fits in `overhead`",
                    )?;
                    let (want_cx, key_bytes) = $crate::aead::CtrThenXorPrf::<$inner, $cipher>::commit(
                        &self.key,
                        &nonce.try_into()?,
                    )?;
                    if !bool::from($crate::subtle::ConstantTimeEq::ct_eq(
                        want_cx.as_slice(),
                        got_cx,
                    )) {
                        Err($crate::aead::OpenError::Authentication)
                    } else {
                        let key = $crate::import::Import::<_>::import(key_bytes.as_bytes())
                            .map_err($crate::aead::UtcError::Import)?;
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

    /// An error occurred during the Hash-then-Encrypt transform.
    #[derive(Debug, Eq, PartialEq)]
    pub enum HteError {
        /// The current AEAD key could not be exported.
        Export(ExportError),
        /// The transformed AEAD key could not be imported.
        Import(ImportError),
    }

    impl HteError {
        const fn as_str(&self) -> &'static str {
            match self {
                Self::Export(_) => "unable to export inner secret key",
                Self::Import(_) => "unable to import HtE transformed key",
            }
        }
    }

    impl fmt::Display for HteError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Export(err) => write!(f, "{}: {err}", self.as_str()),
                Self::Import(err) => write!(f, "{}: {err}", self.as_str()),
            }
        }
    }

    impl core::error::Error for HteError {
        fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
            match self {
                Self::Export(err) => Some(err),
                Self::Import(err) => Some(err),
            }
        }
    }

    impl From<ExportError> for HteError {
        fn from(err: ExportError) -> Self {
            Self::Export(err)
        }
    }

    impl From<ImportError> for HteError {
        fn from(err: ImportError) -> Self {
            Self::Import(err)
        }
    }

    impl From<HteError> for SealError {
        fn from(err: HteError) -> SealError {
            SealError::Other(err.as_str())
        }
    }

    impl From<HteError> for OpenError {
        fn from(err: HteError) -> OpenError {
            OpenError::Other(err.as_str())
        }
    }

    /// Implements the Hash-then-Encrypt (HtE) transform to turn
    /// a CMT-1 AEAD into a CMT-4 AEAD.
    ///
    /// - `name`: The name of the resulting [`Aead`].
    /// - `inner`: The underlying [`Aead`].
    /// - `hash`: A hash function.
    /// - `doc`: A string to use for documentation.
    ///
    /// # ⚠️ Warning
    /// <div class="warning">
    /// This is a low-level feature. You should not be using it
    /// unless you understand what you are doing.
    /// </div>
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// # #[cfg(feature = "committing-aead")]
    /// # {
    /// use aranya_crypto_core::hte_aead;
    /// hte_aead!(Cmt4Aes256Gcm, Cmt1Aes256Gcm, Sha256, "CMT-4 AES-256-GCM.");
    /// # }
    /// ```
    #[cfg_attr(feature = "committing-aead", macro_export)]
    #[cfg_attr(docsrs, doc(cfg(feature = "committing-aead")))]
    macro_rules! hte_aead {
        ($name:ident, $inner:ty, $hash:ty, $doc:expr) => {
            #[doc = $doc]
            pub struct $name {
                key: <$inner as $crate::aead::Aead>::Key,
            }

            impl $name {
                fn hash(
                    &self,
                    nonce: &[u8],
                    ad: &[u8],
                ) -> ::core::result::Result<
                    <$inner as $crate::aead::Aead>::Key,
                    $crate::aead::HteError,
                > {
                    // The nonce length is fixed, so use
                    // HMAC(K || N || A)[1 : k] per Theorem 3.2.
                    let tag = {
                        let key = $crate::keys::SecretKey::try_export_secret(&self.key)?;
                        let mut hmac = $crate::hmac::Hmac::<$hash>::new(key.as_bytes());
                        hmac.update(nonce);
                        hmac.update(ad);
                        hmac.tag()
                    };
                    let mut key_bytes = $crate::generic_array::GenericArray::<
                        u8,
                        <<$inner as $crate::aead::Aead>::Key as $crate::keys::SecretKey>::Size,
                    >::default();
                    let k = ::core::cmp::min(tag.len(), key_bytes.as_slice().len());
                    key_bytes
                        .as_mut_slice()
                        .copy_from_slice(&tag.as_bytes()[..k]);
                    let key =
                        <<$inner as $crate::aead::Aead>::Key as $crate::import::Import<_>>::import(
                            key_bytes.as_slice(),
                        )?;
                    Ok(key)
                }
            }

            // The `where` bound is important as it enforces the
            // requirement that `$inner` be a CMT-1 AEAD.
            impl $crate::aead::CommittingAead for $name where $inner: $crate::aead::Cmt1Aead {}

            impl $crate::aead::Cmt1Aead for $name {}

            impl $crate::aead::Cmt3Aead for $name {}

            impl $crate::aead::Cmt4Aead for $name where $inner: $crate::aead::Cmt1Aead {}

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

                #[inline]
                fn new(key: &Self::Key) -> Self {
                    Self { key: key.clone() }
                }

                fn seal(
                    &self,
                    mut dst: &mut [u8],
                    nonce: &[u8],
                    plaintext: &[u8],
                    additional_data: &[u8],
                ) -> ::core::result::Result<(), $crate::aead::SealError> {
                    $crate::aead::check_seal_params::<Self>(
                        &mut dst,
                        nonce,
                        plaintext,
                        additional_data,
                    )?;

                    let key = self.hash(nonce, additional_data)?;
                    <$inner as $crate::aead::Aead>::new(&key).seal(
                        dst,
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

                    let key = self.hash(nonce, additional_data)?;
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

                    let key = self.hash(nonce, additional_data)?;
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

                    let key = self.hash(nonce, additional_data)?;
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
#[cfg_attr(docsrs, doc(cfg(feature = "committing-aead")))]
pub use committing::*;
