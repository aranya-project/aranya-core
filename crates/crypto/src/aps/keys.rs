use core::fmt;

use buggy::Bug;
use byteorder::{ByteOrder, LittleEndian};
pub use hpke::MessageLimitReached;

use super::shared::{RawOpenKey, RawSealKey};
use crate::{
    aead,
    hpke::{self, HpkeError, OpenCtx, SealCtx},
    import::ImportError,
    CipherSuite,
};

/// A sequence number.
#[derive(Copy, Clone, Debug, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Seq(hpke::Seq);

impl Seq {
    /// The zero value of a `Seq`.
    pub const ZERO: Self = Self(hpke::Seq::ZERO);

    /// Creates a sequence number.
    pub const fn new(seq: u64) -> Self {
        Self(hpke::Seq::new(seq))
    }

    /// Converts itself to a `u64`.
    pub const fn to_u64(&self) -> u64 {
        self.0.to_u64()
    }

    /// Returns the maximum allowed sequence number.
    ///
    /// For testing only.
    #[cfg(any(test, feature = "test_util"))]
    pub(crate) fn max<N: ::generic_array::ArrayLength>() -> u64 {
        hpke::Seq::max::<N>()
    }
}

impl fmt::Display for Seq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

macro_rules! packed {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident $($tokens:tt)*
    ) => {
        $(#[$meta])*
        $vis struct $name $($tokens)*
        impl $name {
            /// The size in bytes of the packed struct.
            $vis const PACKED_SIZE: usize = {
                #[repr(packed)]
                #[allow(dead_code)]
                $vis struct $name $($tokens)*
                ::core::mem::size_of::<$name>()
            };
        }
    };
}

packed! {
    /// The authenticated data for each encryotion.
    ///
    /// Note that the sequence number is not part of the AD because
    /// it is included in the nonce.
    pub struct AuthData {
        /// The APS version number.
        pub version: u32,
        /// The channel's label.
        pub label: u32,
    }
}

impl AuthData {
    fn to_bytes(&self) -> [u8; Self::PACKED_SIZE] {
        let mut b = [0u8; Self::PACKED_SIZE];
        LittleEndian::write_u32(&mut b[0..4], self.version);
        LittleEndian::write_u32(&mut b[4..8], self.label);
        b
    }
}

/// An encryption key.
pub struct SealKey<CS: CipherSuite> {
    ctx: SealCtx<CS::Aead>,
}

impl<CS: CipherSuite> SealKey<CS> {
    /// The size in bytes of the overhead added to the plaintext.
    pub const OVERHEAD: usize = SealCtx::<CS::Aead>::OVERHEAD;

    /// Creates an encryption key from its raw parts.
    pub fn from_raw(key: &RawSealKey<CS>, seq: Seq) -> Result<Self, ImportError> {
        let RawSealKey { key, base_nonce } = key;
        let ctx = SealCtx::new(key, base_nonce, seq.0)?;
        Ok(Self { ctx })
    }

    /// Encrypts and authenticates `plaintext`, returning the
    /// resulting sequence number.
    ///
    /// The resulting ciphertext is written to `dst`, which must
    /// be at least `plaintext.len()` + [`OVERHEAD`][Self::OVERHEAD]
    /// bytes long.
    pub fn seal(
        &mut self,
        dst: &mut [u8],
        plaintext: &[u8],
        ad: &AuthData,
    ) -> Result<Seq, SealError> {
        let seq = self.ctx.seal(dst, plaintext, &ad.to_bytes())?;
        Ok(Seq(seq))
    }

    /// Encrypts and authenticates `plaintext` in place,
    /// returning the resulting sequence number.
    pub fn seal_in_place(
        &mut self,
        data: impl AsMut<[u8]>,
        tag: &mut [u8],
        ad: &AuthData,
    ) -> Result<Seq, SealError> {
        let seq = self.ctx.seal_in_place(data, tag, &ad.to_bytes())?;
        Ok(Seq(seq))
    }

    /// Returns the current sequence number.
    #[inline]
    pub fn seq(&self) -> Seq {
        Seq(self.ctx.seq())
    }
}

/// An error from [`SealKey`].
#[derive(Debug, Eq, PartialEq)]
pub enum SealError {
    /// The maximum nuumber of messages have been encrypted with
    /// this particular key.
    MessageLimitReached,
    /// Some other error occurred.
    Other(HpkeError),
    /// An internal bug was discovered.
    Bug(Bug),
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageLimitReached => f.write_str("message limit reached"),
            Self::Other(err) => write!(f, "{err}"),
            Self::Bug(err) => write!(f, "{err}"),
        }
    }
}

impl trouble::Error for SealError {
    fn source(&self) -> Option<&(dyn trouble::Error + 'static)> {
        match self {
            Self::Other(err) => Some(err),
            _ => None,
        }
    }
}

impl From<Bug> for SealError {
    fn from(err: Bug) -> Self {
        Self::Bug(err)
    }
}

impl From<HpkeError> for SealError {
    fn from(err: HpkeError) -> Self {
        match err {
            HpkeError::MessageLimitReached => Self::MessageLimitReached,
            err => Self::Other(err),
        }
    }
}

/// A decryption key.
pub struct OpenKey<CS: CipherSuite> {
    ctx: OpenCtx<CS::Aead>,
}

impl<CS: CipherSuite> OpenKey<CS> {
    /// The size in bytes of the overhead added to the plaintext.
    pub const OVERHEAD: usize = OpenCtx::<CS::Aead>::OVERHEAD;

    /// Creates decryption key from a raw key.
    pub fn from_raw(key: &RawOpenKey<CS>) -> Result<Self, ImportError> {
        let RawOpenKey { key, base_nonce } = key;
        // We unconditionally set the sequence number to zero
        // because `OpenKey` only supports decrypting with an
        // explicit sequence number.
        let ctx = OpenCtx::new(key, base_nonce, Seq::ZERO.0)?;
        Ok(Self { ctx })
    }

    /// Decrypts and authenticates `ciphertext` at a particular
    /// sequence number.
    ///
    /// The resulting plaintext is written to `dst`, which must
    /// must be at least `ciphertext.len()` - [`OVERHEAD`][Self::OVERHEAD]
    /// bytes long.
    pub fn open(
        &self,
        dst: &mut [u8],
        ciphertext: &[u8],
        ad: &AuthData,
        seq: Seq,
    ) -> Result<(), OpenError> {
        self.ctx.open_at(dst, ciphertext, &ad.to_bytes(), seq.0)?;
        Ok(())
    }

    /// Decrypts and authenticates `ciphertext` at a particular
    /// sequence number.
    ///
    /// The resulting plaintext is written to `dst`, which must
    /// must be at least `ciphertext.len()` - [`OVERHEAD`][Self::OVERHEAD]
    /// bytes long.
    pub fn open_in_place(
        &self,
        data: impl AsMut<[u8]>,
        tag: &[u8],
        ad: &AuthData,
        seq: Seq,
    ) -> Result<(), OpenError> {
        self.ctx
            .open_in_place_at(data, tag, &ad.to_bytes(), seq.0)?;
        Ok(())
    }
}

/// An error from [`OpenKey`].
#[derive(Debug, Eq, PartialEq)]
pub enum OpenError {
    /// The ciphertext could not be authenticated.
    Authentication,
    /// The sequence number is out of range.
    ///
    /// Note that [`SealKey`] will never produce sequence numbers
    /// that are out of range. See
    /// [`SealError::MessageLimitReached`] for more information.
    MessageLimitReached,
    /// Some other error occurred.
    Other(HpkeError),
    /// An internal bug was discovered.
    Bug(Bug),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication => f.write_str("authentication error"),
            Self::MessageLimitReached => f.write_str("message limit reached"),
            Self::Other(err) => write!(f, "{err}"),
            Self::Bug(err) => write!(f, "{err}"),
        }
    }
}

impl trouble::Error for OpenError {
    fn source(&self) -> Option<&(dyn trouble::Error + 'static)> {
        match self {
            Self::Other(err) => Some(err),
            _ => None,
        }
    }
}

impl From<Bug> for OpenError {
    fn from(err: Bug) -> Self {
        Self::Bug(err)
    }
}

impl From<HpkeError> for OpenError {
    fn from(err: HpkeError) -> Self {
        match err {
            HpkeError::Open(aead::OpenError::Authentication) => Self::Authentication,
            HpkeError::MessageLimitReached => Self::MessageLimitReached,
            err => Self::Other(err),
        }
    }
}
