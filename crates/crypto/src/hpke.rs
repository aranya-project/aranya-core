//! Hybrid Public Key Encryption per [RFC 9180].
//!
//! # Warning
//!
//! This is a low-level module. You should not be using it
//! directly unless you are implementing an engine.
//!
//! ## Notation
//!
//! - `sk`: a private key; shorthand for "*S*ecret *K*ey"
//! - `pk`: a public key; shorthand for "*P*ublic *K*ey"
//! - `skR`, `pkR`: a receiver's secret or public key
//! - `skS`, `pkS`: a sender's secret or public key
//! - `skE`, `pkE`: an ephemeral secret or public key
//! - `encap`, `decap`: see [Encapsulate](#Encapsulate).
//!
//! [RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180.html

#![forbid(unsafe_code)]
// We use the same variable names used in the HPKE RFC.
#![allow(non_snake_case)]

use core::{
    borrow::{Borrow, BorrowMut},
    fmt::{self, Debug, Display},
    marker::PhantomData,
    num::NonZeroU16,
    result::Result,
};

use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

use crate::{
    aead::{Aead, IndCca2, KeyData, OpenError, SealError},
    csprng::Csprng,
    import::{ExportError, Import, ImportError},
    kdf::{Kdf, KdfError},
    kem::{Kem, KemError},
};

macro_rules! i2osp {
    ($v:expr) => {
        $v.to_be_bytes()
    };
}

/// An HPKE operation mode.
#[cfg_attr(test, derive(Debug))]
pub enum Mode<'a, T> {
    /// The most basic operation mode.
    Base,
    /// Extends the base mode by allowing the recipient to
    /// authenticate that the sender possessed a particular
    /// pre-shared key.
    Psk(Psk<'a>),
    /// Extends the base mode by allowing the recipient to
    /// authenticate that the sender possessed a particular
    /// private key.
    Auth(T),
    /// A combination of [`Mode::Auth`] and [`Mode::Psk`].
    AuthPsk(T, Psk<'a>),
}

impl<T> Display for Mode<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base => write!(f, "mode_base"),
            Self::Psk(_) => write!(f, "mode_psk"),
            Self::Auth(_) => write!(f, "mode_auth"),
            Self::AuthPsk(_, _) => write!(f, "mode_auth_psk"),
        }
    }
}

impl<'a, T> Mode<'a, T> {
    // The default `psk` and `psk_id` are empty strings. See
    // section 5.1.
    const DEFAULT_PSK: Psk<'static> = Psk {
        psk: &[],
        psk_id: &[],
    };

    /// Converts from `Mode<'_, T>` to `Mode<'_, &T>`.
    pub const fn as_ref(&self) -> Mode<'_, &T> {
        match *self {
            Self::Base => Mode::Base,
            Self::Psk(psk) => Mode::Psk(psk),
            Self::Auth(ref k) => Mode::Auth(k),
            Self::AuthPsk(ref k, psk) => Mode::AuthPsk(k, psk),
        }
    }

    fn psk(&self) -> &Psk<'a> {
        match self {
            Mode::Psk(psk) => psk,
            Mode::AuthPsk(_, psk) => psk,
            _ => &Self::DEFAULT_PSK,
        }
    }

    const fn id(&self) -> u8 {
        match self {
            Self::Base => 0x00,
            Self::Psk(_) => 0x01,
            Self::Auth(_) => 0x02,
            Self::AuthPsk(_, _) => 0x03,
        }
    }
}

/// A pre-shared key and its ID.
#[cfg_attr(test, derive(Debug))]
#[derive(Copy, Clone)]
pub struct Psk<'a> {
    /// The pre-shared key.
    psk: &'a [u8],
    // The pre-shared key's ID.
    psk_id: &'a [u8],
}

impl<'a> Psk<'a> {
    /// Creates a [`Psk`] from a pre-shared key and its ID.
    pub fn new(psk: &'a [u8], psk_id: &'a [u8]) -> Result<Self, HpkeError> {
        // See Section 5.1, `VerifyPSKInputs`.
        if psk.is_empty() || psk_id.is_empty() {
            Err(HpkeError::InvalidPsk)
        } else {
            Ok(Self { psk, psk_id })
        }
    }
}

impl ConstantTimeEq for Psk<'_> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.psk.ct_eq(other.psk) & self.psk_id.ct_eq(other.psk_id)
    }
}

/// KEM algorithm identifiers.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize, MaxSize)]
pub enum KemId {
    /// DHKEM(P-256, HKDF-SHA256).
    DhKemP256HkdfSha256,
    /// DHKEM(P-384, HKDF-SHA384).
    DhKemP384HkdfSha384,
    /// DHKEM(P-521, HKDF-SHA512).
    DhKemP521HkdfSha512,
    /// DHKEM(X25519, HKDF-SHA256).
    DhKemX25519HkdfSha256,
    /// DHKEM(X448, HKDF-SHA512).
    DhKemX448HkdfSha512,
    /// Some other KEM.
    ///
    /// Non-zero since 0x0000 is marked as 'reserved'.
    Other(NonZeroU16),
}

impl KemId {
    pub(crate) const fn to_u16(self) -> u16 {
        match self {
            Self::DhKemP256HkdfSha256 => 0x0010,
            Self::DhKemP384HkdfSha384 => 0x0011,
            Self::DhKemP521HkdfSha512 => 0x0012,
            Self::DhKemX25519HkdfSha256 => 0x0020,
            Self::DhKemX448HkdfSha512 => 0x0021,
            Self::Other(id) => id.get(),
        }
    }

    pub(crate) const fn to_be_bytes(self) -> [u8; 2] {
        i2osp!(self.to_u16())
    }
}

impl Display for KemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DhKemP256HkdfSha256 => write!(f, "DHKEM(P-256, HKDF-SHA256)"),
            Self::DhKemP384HkdfSha384 => write!(f, "DHKEM(P-384, HKDF-SHA384)"),
            Self::DhKemP521HkdfSha512 => write!(f, "DHKEM(P-521, HKDF-SHA512)"),
            Self::DhKemX25519HkdfSha256 => write!(f, "DHKEM(X25519, HKDF-SHA256)"),
            Self::DhKemX448HkdfSha512 => write!(f, "DHKEM(X448, HKDF-SHA512)"),
            Self::Other(id) => write!(f, "Kem({:#02x})", id),
        }
    }
}

/// KDF algorithm identifiers.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize, MaxSize)]
pub enum KdfId {
    /// HKDF-SHA256.
    HkdfSha256,
    /// HKDF-SHA384.
    HkdfSha384,
    /// HKDF-SHA512.
    HkdfSha512,
    /// Some other KDF.
    ///
    /// Non-zero since 0x0000 is marked as 'reserved'.
    Other(NonZeroU16),
}

impl KdfId {
    pub(crate) const fn to_u16(self) -> u16 {
        match self {
            Self::HkdfSha256 => 0x0001,
            Self::HkdfSha384 => 0x0002,
            Self::HkdfSha512 => 0x0003,
            Self::Other(id) => id.get(),
        }
    }

    pub(crate) const fn to_be_bytes(self) -> [u8; 2] {
        i2osp!(self.to_u16())
    }
}

impl Display for KdfId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HkdfSha256 => write!(f, "HkdfSha256"),
            Self::HkdfSha384 => write!(f, "HkdfSha384"),
            Self::HkdfSha512 => write!(f, "HkdfSha512"),
            Self::Other(id) => write!(f, "Kdf({:#02x})", id),
        }
    }
}

/// AEAD algorithm identifiers.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize, MaxSize)]
pub enum AeadId {
    /// AES-128-GCM.
    Aes128Gcm,
    /// AES-256-GCM.
    Aes256Gcm,
    /// ChaCha20Poly1305.
    ChaCha20Poly1305,
    /// CMT-1 AES-256-GCM.
    ///
    /// Not an official RFC ID.
    Cmt1Aes256Gcm,
    /// CMT-4 AES-256-GCM.
    ///
    /// Not an official RFC ID.
    Cmt4Aes256Gcm,
    /// Some other AEAD.
    ///
    /// Non-zero since 0x0000 is marked as 'reserved'.
    Other(NonZeroU16),
    /// Export-only AEAD.
    ExportOnly,
}

impl AeadId {
    pub(crate) const fn to_u16(self) -> u16 {
        match self {
            Self::Aes128Gcm => 0x0001,
            Self::Aes256Gcm => 0x0002,
            Self::ChaCha20Poly1305 => 0x0003,
            Self::Cmt1Aes256Gcm => 0xfffd,
            Self::Cmt4Aes256Gcm => 0xfffe,
            Self::Other(id) => id.get(),
            Self::ExportOnly => 0xffff,
        }
    }

    pub(crate) const fn to_be_bytes(self) -> [u8; 2] {
        i2osp!(self.to_u16())
    }
}

impl Display for AeadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aes128Gcm => write!(f, "Aes128Gcm"),
            Self::Aes256Gcm => write!(f, "Aes256Gcm"),
            Self::ChaCha20Poly1305 => write!(f, "ChaCha20Poly1305"),
            Self::Cmt1Aes256Gcm => write!(f, "Cmt1Aes256Gcm"),
            Self::Cmt4Aes256Gcm => write!(f, "Cmt4Aes256Gcm"),
            Self::Other(id) => write!(f, "Aead({:#02x})", id),
            Self::ExportOnly => write!(f, "ExportOnly"),
        }
    }
}

/// An error from an [`Hpke`].
#[derive(Debug, Eq, PartialEq)]
pub enum HpkeError {
    /// An AEAD seal operation failed.
    Seal(SealError),
    /// An AEAD open operation failed.
    Open(OpenError),
    /// A KDF operation failed.
    Kdf(KdfError),
    /// A KEM operation failed.
    Kem(KemError),
    /// A key could not be imported.
    Import(ImportError),
    /// A key could not be exported.
    Export(ExportError),
    /// The pre-shared key or its ID are invalid.
    InvalidPsk,
    /// The encryption context has been used to send the maximum
    /// number of messages.
    MessageLimitReached,
}

impl Display for HpkeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Seal(err) => write!(f, "{}", err),
            Self::Open(err) => write!(f, "{}", err),
            Self::Kdf(err) => write!(f, "{}", err),
            Self::Kem(err) => write!(f, "{}", err),
            Self::Import(err) => write!(f, "{}", err),
            Self::Export(err) => write!(f, "{}", err),
            Self::InvalidPsk => write!(f, "invalid pre-shared key"),
            Self::MessageLimitReached => write!(f, "message limit reached"),
        }
    }
}

impl trouble::Error for HpkeError {
    fn source(&self) -> Option<&(dyn trouble::Error + 'static)> {
        match self {
            Self::Seal(err) => Some(err),
            Self::Open(err) => Some(err),
            Self::Kdf(err) => Some(err),
            Self::Kem(err) => Some(err),
            Self::Import(err) => Some(err),
            Self::Export(err) => Some(err),
            Self::InvalidPsk => None,
            Self::MessageLimitReached => None,
        }
    }
}

impl From<SealError> for HpkeError {
    fn from(err: SealError) -> Self {
        Self::Seal(err)
    }
}

impl From<OpenError> for HpkeError {
    fn from(err: OpenError) -> Self {
        Self::Open(err)
    }
}

impl From<KdfError> for HpkeError {
    fn from(err: KdfError) -> Self {
        Self::Kdf(err)
    }
}

impl From<KemError> for HpkeError {
    fn from(err: KemError) -> Self {
        Self::Kem(err)
    }
}

impl From<ImportError> for HpkeError {
    fn from(err: ImportError) -> Self {
        Self::Import(err)
    }
}

impl From<ExportError> for HpkeError {
    fn from(err: ExportError) -> Self {
        Self::Export(err)
    }
}

/// Hybrid Public Key Encryption (HPKE) per [RFC 9180].
///
/// [RFC 9180]: <https://www.rfc-editor.org/rfc/rfc9180.html>
pub struct Hpke<K, F, A> {
    _kem: PhantomData<K>,
    _kdf: PhantomData<F>,
    _aead: PhantomData<A>,
}

impl<K: Kem, F: Kdf, A: Aead + IndCca2> Hpke<K, F, A> {
    /// Creates a randomized encryption context for encrypting
    /// messages for the receiver, `pkR`.
    ///
    /// It returns the encryption context and an encapsulated
    /// symmetric key which can be used by the receiver to
    /// decrypt messages.
    ///
    /// The `info` parameter provides contextual binding.
    #[allow(clippy::type_complexity)]
    pub fn setup_send<R: Csprng>(
        rng: &mut R,
        mode: Mode<'_, &K::DecapKey>,
        pkR: &K::EncapKey,
        info: &[u8],
    ) -> Result<(K::Encap, SendCtx<K, F, A>), HpkeError> {
        let (shared_secret, enc) = match mode {
            Mode::Auth(skS) | Mode::AuthPsk(skS, _) => K::auth_encap::<R>(rng, pkR, skS)?,
            Mode::Base | Mode::Psk(_) => K::encap::<R>(rng, pkR)?,
        };
        let ctx = Self::key_schedule(mode, &shared_secret, info)?;
        Ok((enc, SendCtx(ctx)))
    }

    /// Deterministically creates an encryption context for
    /// encrypting messages for the receiver, `pkR`.
    ///
    /// It returns the encryption context and an encapsulated
    /// symmetric key which can be used by the receiver to
    /// decrypt messages.
    ///
    /// The `info` parameter provides contextual binding.
    ///
    /// # Warning
    ///
    /// The security of this function relies on choosing the
    /// correct value for `skE`. It is a catastrophic error if
    /// you do not ensure all of the following properties:
    ///
    /// - it must be cryptographically secure
    /// - it must never be reused
    #[allow(clippy::type_complexity)]
    pub fn setup_send_deterministically(
        mode: Mode<'_, &K::DecapKey>,
        pkR: &K::EncapKey,
        info: &[u8],
        skE: K::DecapKey,
    ) -> Result<(K::Encap, SendCtx<K, F, A>), HpkeError> {
        let (shared_secret, enc) = match mode {
            Mode::Auth(skS) | Mode::AuthPsk(skS, _) => {
                K::auth_encap_deterministically(pkR, skS, skE)?
            }
            Mode::Base | Mode::Psk(_) => K::encap_deterministically(pkR, skE)?,
        };
        let ctx = Self::key_schedule(mode, &shared_secret, info)?;
        Ok((enc, SendCtx(ctx)))
    }

    /// Creates an encryption context that can decrypt messages
    /// from a particular sender (the creator of `enc`).
    ///
    /// The `mode` and `info` parameters must be the same
    /// parameters used by the sender.
    pub fn setup_recv(
        mode: Mode<'_, &K::EncapKey>,
        enc: &K::Encap,
        skR: &K::DecapKey,
        info: &[u8],
    ) -> Result<RecvCtx<K, F, A>, HpkeError> {
        let shared_secret = match mode {
            Mode::Auth(pkS) | Mode::AuthPsk(pkS, _) => K::auth_decap(enc, skR, pkS)?,
            Mode::Base | Mode::Psk(_) => K::decap(enc, skR)?,
        };
        let ctx = Self::key_schedule(mode, &shared_secret, info)?;
        Ok(RecvCtx(ctx))
    }

    /// The "HPKE" suite ID.
    ///
    /// ```text
    /// suite_id = concat(
    ///     "HPKE",
    ///     I2OSP(kem_id, 2),
    ///     I2OSP(kdf_id, 2),
    ///     I2OSP(aead_id, 2),
    /// )
    /// ```
    #[rustfmt::skip]
    const HPKE_SUITE_ID: [u8; 10] = [
        b'H',
        b'P',
        b'K',
        b'E',
        i2osp!(K::ID)[0], i2osp!(K::ID)[1],
        i2osp!(F::ID)[0], i2osp!(F::ID)[1],
        i2osp!(A::ID)[0], i2osp!(A::ID)[1],
    ];

    fn key_schedule<T>(
        mode: Mode<'_, T>,
        shared_secret: &K::Secret,
        info: &[u8],
    ) -> Result<Context<K, F, A>, HpkeError> {
        let Psk { psk, psk_id } = mode.psk();

        //  psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
        let psk_id_hash = Self::labeled_extract(b"", b"psk_id_hash", psk_id);

        //  info_hash = LabeledExtract("", "info_hash", info)
        let info_hash = Self::labeled_extract(b"", b"info_hash", info);

        //  key_schedule_context = concat(mode, psk_id_hash, info_hash)
        let ks_ctx = Info::KeySched([mode.id()], psk_id_hash, info_hash);

        //  secret = LabeledExtract(shared_secret, "secret", psk)
        let secret = Self::labeled_extract(shared_secret.borrow(), b"secret", psk);

        // key = LabeledExpand(secret, "key", key_schedule_context, Nk)
        let key = Self::labeled_expand::<KeyData<A>, 3>(&secret, b"key", &ks_ctx)?;

        // base_nonce = LabeledExpand(secret, "base_nonce",
        //                      key_schedule_context, Nn)
        let base_nonce = Self::labeled_expand(&secret, b"base_nonce", &ks_ctx)?;

        // exporter_secret = LabeledExpand(secret, "exp",
        //                           key_schedule_context, Nh)
        let exporter_secret = Self::labeled_expand(&secret, b"exp", &ks_ctx)?;

        Ok(Context::new(
            &A::Key::import(key.borrow())?,
            base_nonce,
            exporter_secret,
        ))
    }

    /// Performs `LabeledExtract`.
    fn labeled_extract<const N: usize>(salt: &[u8], label: &[u8; N], ikm: &[u8]) -> F::Prk {
        // def LabeledExtract(salt, label, ikm):
        //     labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
        let labeled_ikm = ["HPKE-v1".as_bytes(), &Self::HPKE_SUITE_ID, label, ikm];
        // Note that `Kdf::extract` takes its arguments in
        // a different order than the HPKE RFC.
        //
        //     Extract(salt, labeled_ikm)
        F::extract_multi(&labeled_ikm, salt)
    }

    /// Performs `LabeledExpand`.
    fn labeled_expand<T: BorrowMut<[u8]> + Default, const N: usize>(
        prk: &F::Prk,
        label: &[u8; N],
        info: &Info<'_, F>,
    ) -> Result<T, KdfError> {
        let mut out = T::default();
        Self::labeled_expand_out(out.borrow_mut(), prk, label, info)?;
        Ok(out)
    }

    /// Performs `LabeledExpand`.
    fn labeled_expand_out<const N: usize>(
        out: &mut [u8],
        prk: &F::Prk,
        label: &[u8; N],
        info: &Info<'_, F>,
    ) -> Result<(), KdfError> {
        let (a, b, c) = info.parts();
        // def LabeledExpand(prk, label, info, L):
        //     labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id,
        //                 label, info)
        let labeled_info = [
            &(i2osp!(out.len() as u16))[..],
            "HPKE-v1".as_bytes(),
            &Self::HPKE_SUITE_ID,
            label,
            a,
            b,
            c,
        ];
        // Note that `Kdf::expand` takes its arguments in
        // a different order than the HPKE RFC.
        //
        //     return Expand(prk, labeled_info, L)
        F::expand_multi(out, prk, &labeled_info)?;
        Ok(())
    }
}

enum Info<'a, F: Kdf> {
    KeySched([u8; 1], F::Prk, F::Prk),
    Export(&'a [u8]),
}

impl<F: Kdf> Info<'_, F> {
    fn parts(&self) -> (&[u8], &[u8], &[u8]) {
        match self {
            Self::KeySched(a, b, c) => (a.as_ref(), b.borrow(), c.borrow()),
            Self::Export(v) => (v, b"", b""),
        }
    }
}

/// An encryption context that encrypts messages for a particular
/// recipient.
pub struct SendCtx<K: Kem, F: Kdf, A: Aead + IndCca2>(Context<K, F, A>);

impl<K: Kem, F: Kdf, A: Aead + IndCca2> SendCtx<K, F, A> {
    /// The size in bytes of the overhead added to the plaintext.
    pub const OVERHEAD: usize = A::OVERHEAD;

    /// Encrypts and authenticates `plaintext`.
    ///
    /// The resulting ciphertext is written to `dst`, which must
    /// be at least `plaintext.len()` + [`Self::OVERHEAD`] bytes
    /// long.
    pub fn seal(
        &mut self,
        dst: &mut [u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), HpkeError> {
        let nonce = self.0.compute_nonce();
        self.0
            .aead
            .seal(dst, nonce.borrow(), plaintext, additional_data)?;
        self.0.incr_seq()?;
        Ok(())
    }

    /// Exports a secret from the encryption context.
    pub fn export(&self, out: &mut [u8], context: &[u8]) -> Result<(), KdfError> {
        self.0.export(out, context)
    }
}

/// An encryption context that decrypts messages from
/// a particular sender.
pub struct RecvCtx<K: Kem, F: Kdf, A: Aead + IndCca2>(Context<K, F, A>);

impl<K: Kem, F: Kdf, A: Aead + IndCca2> RecvCtx<K, F, A> {
    /// The size in bytes of the overhead added to the plaintext.
    pub const OVERHEAD: usize = A::OVERHEAD;

    /// Decrypts and authenticates `ciphertext`.
    ///
    /// The resulting plaintext is written to `dst`, which must
    /// must be at least `ciphertext.len()` - [`Self::OVERHEAD`]
    /// bytes long.
    pub fn open(
        &mut self,
        dst: &mut [u8],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), HpkeError> {
        let nonce = self.0.compute_nonce();
        self.0
            .aead
            .open(dst, nonce.borrow(), ciphertext, additional_data)?;
        self.0.incr_seq()?;
        Ok(())
    }

    /// Exports a secret from the encryption context.
    pub fn export(&self, out: &mut [u8], context: &[u8]) -> Result<(), KdfError> {
        self.0.export(out, context)
    }
}

/// Encryption/decryption context.
struct Context<K: Kem, F: Kdf, A: Aead + IndCca2> {
    aead: A,
    base_nonce: A::Nonce,
    exporter_secret: F::Prk,
    /// Incremented after each call to `seal` or `open`.
    ///
    /// This should be the size of the nonce, but it's
    /// vanishingly unlikely that we'll ever overflow. Since
    /// encryption contexts can only be used serially, we can
    /// only overflow if the user actually performs 2^64-1
    /// operations. At an impossible one nanosecond per op, this
    /// will take upward of 500 years.
    seq: u64,
    _kem: PhantomData<K>,
}

impl<K: Kem, F: Kdf, A: Aead + IndCca2> Context<K, F, A> {
    fn new(key: &A::Key, base_nonce: A::Nonce, exporter_secret: F::Prk) -> Self {
        Context {
            aead: A::new(key),
            base_nonce,
            exporter_secret,
            seq: 0,
            _kem: PhantomData,
        }
    }

    fn export(&self, out: &mut [u8], context: &[u8]) -> Result<(), KdfError> {
        // def Context.Export(exporter_context, L):
        //   return LabeledExpand(self.exporter_secret, "sec",
        //                        exporter_context, L)
        Hpke::<K, F, A>::labeled_expand_out(
            out,
            &self.exporter_secret,
            b"sec",
            &Info::Export(context),
        )
    }

    /// Returns `2^n - 1` or [`u64::MAX`] if the operation would
    /// overflow.
    const fn seq_max(n: usize) -> u64 {
        if n > 8 {
            u64::MAX
        } else {
            (1 << (8 * n as u64)) - 1
        }
    }

    /// Increments the nonce.
    fn incr_seq(&mut self) -> Result<(), HpkeError> {
        // if self.seq >= (1 << (8*Nn)) - 1:
        //     raise MessageLimitReachedError
        //  self.seq += 1
        if self.seq >= Self::seq_max(A::NONCE_SIZE) {
            Err(HpkeError::MessageLimitReached)
        } else {
            self.seq = self.seq.checked_add(1).expect("this should never happen");
            Ok(())
        }
    }

    /// Returns the next nonce in the sequence.
    fn compute_nonce(&self) -> A::Nonce {
        //  seq_bytes = I2OSP(seq, Nn)
        let seq_bytes = {
            // NB: this assumes that default returns all zeros.
            // If a third-party crypto impl doesn't, the tests
            // should catch it.
            let mut out = A::Nonce::default();
            let seq = i2osp!(self.seq);
            let len = out.borrow().len();
            if len >= seq.len() {
                out.borrow_mut()[len - seq.len()..].copy_from_slice(&seq);
            } else {
                out.borrow_mut().copy_from_slice(&seq[..len]);
            }
            out
        };
        // xor(self.base_nonce, seq_bytes)
        let mut nonce = self.base_nonce.clone();
        for (x, y) in nonce.borrow_mut().iter_mut().zip(seq_bytes.borrow()) {
            *x ^= y;
        }
        nonce
    }
}
