use core::{cmp::Ordering, fmt};

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

/// Identifies the position of a ciphertext in a channel.
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
    pub(crate) fn max<N: crate::generic_array::ArrayLength>() -> u64 {
        hpke::Seq::max::<N>()
    }
}

impl From<Seq> for u64 {
    fn from(seq: Seq) -> u64 {
        seq.to_u64()
    }
}

impl From<u64> for Seq {
    fn from(seq: u64) -> Self {
        Self::new(seq)
    }
}

impl PartialEq<u64> for Seq {
    fn eq(&self, other: &u64) -> bool {
        PartialEq::eq(&self.to_u64(), other)
    }
}

impl PartialOrd<u64> for Seq {
    fn partial_cmp(&self, other: &u64) -> Option<Ordering> {
        PartialOrd::partial_cmp(&self.to_u64(), other)
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
        /// The AFC version number.
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
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum SealError {
    /// The maximum nuumber of messages have been encrypted with
    /// this particular key.
    #[error("message limit reached")]
    MessageLimitReached,
    /// Some other error occurred.
    #[error(transparent)]
    Other(HpkeError),
    /// An internal bug was discovered.
    #[error(transparent)]
    Bug(#[from] Bug),
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
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum OpenError {
    /// The ciphertext could not be authenticated.
    #[error("authentication error")]
    Authentication,
    /// The sequence number is out of range.
    ///
    /// Note that [`SealKey`] will never produce sequence numbers
    /// that are out of range. See
    /// [`SealError::MessageLimitReached`] for more information.
    #[error("message limit reached")]
    MessageLimitReached,
    /// Some other error occurred.
    #[error(transparent)]
    Other(HpkeError),
    /// An internal bug was discovered.
    #[error(transparent)]
    Bug(#[from] Bug),
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
