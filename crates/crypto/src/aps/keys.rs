use core::mem;

use byteorder::{ByteOrder, LittleEndian};
pub use hpke::MessageLimitReached;

use crate::{
    aead::{Aead, KeyData, Nonce},
    engine::Engine,
    error::Error,
    hpke::{self, HpkeError, OpenCtx, SealCtx},
};

/// A sequence number.
#[derive(Debug, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Seq<E: Engine + ?Sized>(hpke::Seq<E::Aead>);

impl<E: Engine + ?Sized> Seq<E> {
    /// The zero value of a `Seq`.
    pub const ZERO: Self = Self(hpke::Seq::<E::Aead>::ZERO);

    /// Creates a sequence number.
    ///
    /// It returns an error if the sequence number is out of
    /// range.
    pub fn new(seq: u64) -> Result<Self, MessageLimitReached> {
        Ok(Self(hpke::Seq::new(seq)?))
    }

    /// Converts itself to a `u64`.
    pub const fn to_u64(&self) -> u64 {
        self.0.to_u64()
    }
}

/// The authenticated data for each encryotion.
///
/// Note that the sequence number is not part of the AD because
/// it is included in the nonce.
// `repr(packed)` so we can get its unpadded size; see the `SIZE`
// constant.
#[repr(packed)]
struct AuthData {
    version: u32,
    label: u32,
}

impl AuthData {
    const SIZE: usize = mem::size_of::<Self>();

    fn into_bytes(self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        LittleEndian::write_u32(&mut b[0..4], self.version);
        LittleEndian::write_u32(&mut b[4..8], self.label);
        b
    }
}

/// An encryption key.
pub struct SealKey<E: Engine + ?Sized> {
    ctx: SealCtx<E::Aead>,
}

impl<E: Engine + ?Sized> SealKey<E> {
    /// The size in bytes of the overhead added to the plaintext.
    pub const OVERHEAD: usize = SealCtx::<E::Aead>::OVERHEAD;

    /// Creates an encryption key from its raw parts.
    pub fn from_raw(
        key: &KeyData<E::Aead>,
        base_nonce: &Nonce<<E::Aead as Aead>::NonceSize>,
        seq: Seq<E>,
    ) -> Result<Self, Error> {
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
        (version, label): (u32, u32),
    ) -> Result<Seq<E>, HpkeError> {
        let ad = AuthData { version, label };
        let seq = self.ctx.seal(dst, plaintext, &ad.into_bytes())?;
        Ok(Seq(seq))
    }

    /// Encrypts and authenticates `plaintext` in place,
    /// returning the resulting sequence number.
    pub fn seal_in_place(
        &mut self,
        data: impl AsMut<[u8]>,
        tag: &mut [u8],
        (version, label): (u32, u32),
    ) -> Result<Seq<E>, HpkeError> {
        let ad = AuthData { version, label };
        let seq = self.ctx.seal_in_place(data, tag, &ad.into_bytes())?;
        Ok(Seq(seq))
    }

    /// Returns the current sequence number.
    pub fn seq(&self) -> Seq<E> {
        Seq(self.ctx.seq())
    }
}

/// A decryption key.
pub struct OpenKey<E: Engine + ?Sized> {
    ctx: OpenCtx<E::Aead>,
}

impl<E: Engine + ?Sized> OpenKey<E> {
    /// The size in bytes of the overhead added to the plaintext.
    pub const OVERHEAD: usize = OpenCtx::<E::Aead>::OVERHEAD;

    /// Creates decryption key from a raw key.
    pub fn from_raw(
        key: &KeyData<E::Aead>,
        base_nonce: &Nonce<<E::Aead as Aead>::NonceSize>,
        seq: Seq<E>,
    ) -> Result<Self, Error> {
        let ctx = OpenCtx::new(key, base_nonce, seq.0)?;
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
        (version, label): (u32, u32),
        seq: Seq<E>,
    ) -> Result<(), HpkeError> {
        let ad = AuthData { version, label };
        self.ctx.open_at(dst, ciphertext, &ad.into_bytes(), seq.0)
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
        (version, label): (u32, u32),
        seq: Seq<E>,
    ) -> Result<(), HpkeError> {
        let ad = AuthData { version, label };
        self.ctx
            .open_in_place_at(data, tag, &ad.into_bytes(), seq.0)
    }
}
