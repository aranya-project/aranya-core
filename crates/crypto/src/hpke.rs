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
    fmt::{self, Debug, Display},
    marker::PhantomData,
    num::NonZeroU16,
    result::Result,
};

use buggy::{bug, Bug, BugExt};
use generic_array::ArrayLength;
use subtle::{Choice, ConstantTimeEq};

use crate::{
    aead::{Aead, IndCca2, KeyData, Nonce, OpenError, SealError},
    csprng::Csprng,
    import::{ExportError, Import, ImportError},
    kdf::{Context, Expand, Kdf, KdfError, Prk},
    kem::{Kem, KemError},
    AlgId,
};

/// Converts `v` to a big-endian byte array.
macro_rules! i2osp {
    ($v:expr) => {
        $v.to_be_bytes()
    };
    ($v:expr, $n:ty) => {{
        let src = $v.to_be_bytes();
        let mut dst = generic_array::GenericArray::<u8, $n>::default();
        // Copy `src` into `dst`, padding with zeros on the
        // left.
        //
        // NB: the compiler knows how to optimize this. Don't
        // rewrite it without verifying the assembly.
        let idx = dst.len().abs_diff(src.len());
        if dst.len() >= src.len() {
            dst[idx..].copy_from_slice(&src);
        } else {
            dst.copy_from_slice(&src[idx..]);
        }
        dst
    }};
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

/// The PSK or its ID are empty.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InvalidPsk;

impl Display for InvalidPsk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid pre-shared key: PSK or PSK ID are empty")
    }
}

impl trouble::Error for InvalidPsk {}

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
    pub fn new(psk: &'a [u8], psk_id: &'a [u8]) -> Result<Self, InvalidPsk> {
        // See Section 5.1, `VerifyPSKInputs`.
        if psk.is_empty() || psk_id.is_empty() {
            Err(InvalidPsk)
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

/// KEM algorithm identifiers per [IANA].
///
/// [IANA]: https://www.iana.org/assignments/hpke/hpke.xhtml
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, AlgId)]
pub enum KemId {
    /// DHKEM(P-256, HKDF-SHA256).
    #[alg_id(0x0010)]
    DhKemP256HkdfSha256,
    /// DHKEM(P-384, HKDF-SHA384).
    #[alg_id(0x0011)]
    DhKemP384HkdfSha384,
    /// DHKEM(P-521, HKDF-SHA512).
    #[alg_id(0x0012)]
    DhKemP521HkdfSha512,
    /// DHKEM(CP-256, HKDF-SHA256)
    #[alg_id(0x0013)]
    DhKemCp256HkdfSha256,
    /// DHKEM(CP-384, HKDF-SHA384)
    #[alg_id(0x0014)]
    DhKemCp384HkdfSha384,
    /// DHKEM(CP-521, HKDF-SHA512)
    #[alg_id(0x0015)]
    DhKemCp521HkdfSha512,
    /// DHKEM(secp256k1, HKDF-SHA256)
    #[alg_id(0x0016)]
    DhKemSecp256k1HkdfSha256,
    /// DHKEM(X25519, HKDF-SHA256).
    #[alg_id(0x0020)]
    DhKemX25519HkdfSha256,
    /// DHKEM(X448, HKDF-SHA512).
    #[alg_id(0x0021)]
    DhKemX448HkdfSha512,
    /// X25519Kyber768Draft00
    #[alg_id(0x0030)]
    X25519Kyber768Draft00,
    /// Some other KEM.
    ///
    /// Non-zero since 0x0000 is marked as 'reserved'.
    #[alg_id(Other)]
    Other(NonZeroU16),
}

impl Display for KemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DhKemP256HkdfSha256 => write!(f, "DHKEM(P-256, HKDF-SHA256)"),
            Self::DhKemP384HkdfSha384 => write!(f, "DHKEM(P-384, HKDF-SHA384)"),
            Self::DhKemP521HkdfSha512 => write!(f, "DHKEM(P-521, HKDF-SHA512)"),
            Self::DhKemCp256HkdfSha256 => write!(f, "DHKEM(CP-256, HKDF-SHA256)"),
            Self::DhKemCp384HkdfSha384 => write!(f, "DHKEM(CP-384, HKDF-SHA384)"),
            Self::DhKemCp521HkdfSha512 => write!(f, "DHKEM(CP-521, HKDF-SHA512)"),
            Self::DhKemSecp256k1HkdfSha256 => write!(f, "DHKEM(secp256k1, HKDF-SHA256)"),
            Self::DhKemX25519HkdfSha256 => write!(f, "DHKEM(X25519, HKDF-SHA256)"),
            Self::DhKemX448HkdfSha512 => write!(f, "DHKEM(X448, HKDF-SHA512)"),
            Self::X25519Kyber768Draft00 => write!(f, "X25519Kyber768Draft00"),
            Self::Other(id) => write!(f, "Kem({:#02x})", id),
        }
    }
}

/// KDF algorithm identifiers per [IANA].
///
/// [IANA]: https://www.iana.org/assignments/hpke/hpke.xhtml
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, AlgId)]
pub enum KdfId {
    /// HKDF-SHA256.
    #[alg_id(0x0001)]
    HkdfSha256,
    /// HKDF-SHA384.
    #[alg_id(0x0002)]
    HkdfSha384,
    /// HKDF-SHA512.
    #[alg_id(0x0003)]
    HkdfSha512,
    /// Some other KDF.
    ///
    /// Non-zero since 0x0000 is marked as 'reserved'.
    #[alg_id(Other)]
    Other(NonZeroU16),
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

/// AEAD algorithm identifiers per [IANA].
///
/// [IANA]: https://www.iana.org/assignments/hpke/hpke.xhtml
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, AlgId)]
pub enum AeadId {
    /// AES-128-GCM.
    #[alg_id(0x0001)]
    Aes128Gcm,
    /// AES-256-GCM.
    #[alg_id(0x0002)]
    Aes256Gcm,
    /// ChaCha20Poly1305.
    #[alg_id(0x0003)]
    ChaCha20Poly1305,
    /// CMT-1 AES-256-GCM.
    ///
    /// Not an official RFC ID.
    #[alg_id(0xfffd)]
    Cmt1Aes256Gcm,
    /// CMT-4 AES-256-GCM.
    ///
    /// Not an official RFC ID.
    #[alg_id(0xfffe)]
    Cmt4Aes256Gcm,
    /// Some other AEAD.
    ///
    /// Non-zero since 0x0000 is marked as 'reserved'.
    #[alg_id(Other)]
    Other(NonZeroU16),
    /// Export-only AEAD.
    #[alg_id(0xffff)]
    ExportOnly,
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
    /// The encryption context has been used to send the maximum
    /// number of messages.
    MessageLimitReached,
    /// An internal bug was discovered.
    Bug(Bug),
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
            Self::MessageLimitReached => write!(f, "message limit reached"),
            Self::Bug(err) => write!(f, "{err}"),
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
            Self::MessageLimitReached => None,
            Self::Bug(err) => Some(err),
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

impl From<Bug> for HpkeError {
    fn from(err: Bug) -> Self {
        Self::Bug(err)
    }
}

impl From<MessageLimitReached> for HpkeError {
    fn from(_err: MessageLimitReached) -> Self {
        Self::MessageLimitReached
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
        Ok((enc, ctx.into_send_ctx()))
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
        Ok((enc, ctx.into_send_ctx()))
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
        Ok(ctx.into_recv_ctx())
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
    ) -> Result<Schedule<K, F, A>, HpkeError> {
        let Psk { psk, psk_id } = mode.psk();

        //  psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
        let psk_id_hash = Self::labeled_extract(b"", "psk_id_hash", psk_id);

        //  info_hash = LabeledExtract("", "info_hash", info)
        let info_hash = Self::labeled_extract(b"", "info_hash", info);

        //  key_schedule_context = concat(mode, psk_id_hash, info_hash)
        let ks_ctx = [&[mode.id()], psk_id_hash.as_bytes(), info_hash.as_bytes()];

        //  secret = LabeledExtract(shared_secret, "secret", psk)
        let secret = Self::labeled_extract(shared_secret.as_ref(), "secret", psk);

        // key = LabeledExpand(secret, "key", key_schedule_context, Nk)
        let key = Self::labeled_expand(&secret, "key", &ks_ctx)?;

        // base_nonce = LabeledExpand(secret, "base_nonce",
        //                      key_schedule_context, Nn)
        let base_nonce = Self::labeled_expand(&secret, "base_nonce", &ks_ctx)?;

        // exporter_secret = LabeledExpand(secret, "exp",
        //                           key_schedule_context, Nh)
        let exporter_secret = Self::labeled_expand(&secret, "exp", &ks_ctx)?;

        Ok(Schedule {
            key,
            base_nonce,
            exporter_secret,
            _kem: PhantomData,
        })
    }

    const HPKE_CTX: Context = Context {
        domain: "HPKE-v1",
        suite_ids: &Self::HPKE_SUITE_ID,
    };

    /// Performs `LabeledExtract`.
    fn labeled_extract(salt: &[u8], label: &'static str, ikm: &[u8]) -> Prk<F::PrkSize> {
        // def LabeledExtract(salt, label, ikm):
        //     labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
        //     return Extract(salt, labeled_ikm)
        Self::HPKE_CTX.labeled_extract::<F>(salt, label, ikm)
    }

    /// Performs `LabeledExpand`.
    fn labeled_expand<T: Expand>(
        prk: &Prk<F::PrkSize>,
        label: &'static str,
        info: &[&[u8]],
    ) -> Result<T, KdfError> {
        // def LabeledExpand(prk, label, info, L):
        //     labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id,
        //                 label, info)
        //     return Expand(prk, labeled_info, L)
        let key = Self::HPKE_CTX.labeled_expand::<F, T>(prk, label, info)?;
        Ok(key)
    }

    /// Performs `LabeledExpand`.
    fn labeled_expand_into(
        out: &mut [u8],
        prk: &Prk<F::PrkSize>,
        label: &'static str,
        info: &[&[u8]],
    ) -> Result<(), KdfError> {
        // def LabeledExpand(prk, label, info, L):
        //     labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id,
        //                 label, info)
        //     return Expand(prk, labeled_info, L)
        Self::HPKE_CTX.labeled_expand_into::<F>(out, prk, label, info)
    }
}

struct Schedule<K: Kem, F: Kdf, A: Aead + IndCca2> {
    key: KeyData<A>,
    base_nonce: Nonce<A::NonceSize>,
    exporter_secret: Prk<F::PrkSize>,
    _kem: PhantomData<K>,
}

impl<K: Kem, F: Kdf, A: Aead + IndCca2> Schedule<K, F, A> {
    fn into_send_ctx(self) -> SendCtx<K, F, A> {
        SendCtx {
            seal: Either::Right((self.key, self.base_nonce)),
            export: ExportCtx::new(self.exporter_secret),
        }
    }

    fn into_recv_ctx(self) -> RecvCtx<K, F, A> {
        RecvCtx {
            open: Either::Right((self.key, self.base_nonce)),
            export: ExportCtx::new(self.exporter_secret),
        }
    }
}

/// Either `L` or `R`.
enum Either<L, R> {
    Left(L),
    Right(R),
}

impl<L, R> Either<L, R> {
    fn get_or_insert_left<F, E>(&mut self, f: F) -> Result<&mut L, E>
    where
        F: FnOnce(&R) -> Result<L, E>,
        E: From<Bug>,
    {
        match self {
            Self::Left(left) => Ok(left),
            Self::Right(right) => {
                *self = Self::Left(f(right)?);
                match self {
                    Self::Left(left) => Ok(left),
                    Self::Right(_) => bug!("we just assigned `Self::Left`"),
                }
            }
        }
    }
}

type RawKey<A> = (KeyData<A>, Nonce<<A as Aead>::NonceSize>);

/// An encryption context that encrypts messages for a particular
/// recipient.
pub struct SendCtx<K: Kem, F: Kdf, A: Aead + IndCca2> {
    seal: Either<SealCtx<A>, RawKey<A>>,
    export: ExportCtx<K, F, A>,
}

impl<K: Kem, F: Kdf, A: Aead + IndCca2> SendCtx<K, F, A> {
    /// The size in bytes of the overhead added to the plaintext.
    pub const OVERHEAD: usize = SealCtx::<A>::OVERHEAD;

    pub(crate) fn into_raw_parts(self) -> Option<(KeyData<A>, Nonce<A::NonceSize>)> {
        match self.seal {
            Either::Left(_) => None,
            Either::Right((key, base_nonce)) => Some((key, base_nonce)),
        }
    }

    fn seal_ctx(&mut self) -> Result<&mut SealCtx<A>, ImportError> {
        self.seal
            .get_or_insert_left(|(key, nonce)| SealCtx::new(key, nonce, Seq::ZERO))
    }

    /// Encrypts and authenticates `plaintext`, returning the
    /// sequence number.
    ///
    /// The resulting ciphertext is written to `dst`, which must
    /// be at least `plaintext.len()` + [`OVERHEAD`][Self::OVERHEAD]
    /// bytes long.
    pub fn seal(
        &mut self,
        dst: &mut [u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Seq, HpkeError> {
        self.seal_ctx()?.seal(dst, plaintext, additional_data)
    }

    /// Encrypts and authenticates `data` in-place, returning the
    /// sequence number.
    pub fn seal_in_place(
        &mut self,
        data: impl AsMut<[u8]>,
        tag: &mut [u8],
        additional_data: &[u8],
    ) -> Result<Seq, HpkeError> {
        self.seal_ctx()?.seal_in_place(data, tag, additional_data)
    }

    /// Exports a secret from the encryption context.
    pub fn export<T>(&self, context: &[u8]) -> Result<T, KdfError>
    where
        T: Expand,
    {
        self.export.export(context)
    }

    /// Exports a secret from the encryption context, writing it
    /// to `out`.
    pub fn export_into(&self, out: &mut [u8], context: &[u8]) -> Result<(), KdfError> {
        self.export.export_into(out, context)
    }
}

/// An encryption context that can only encrypt messages for
/// a particular recipient.
///
/// Unlike [`SendCtx`], it cannot export secrets.
pub struct SealCtx<A: Aead + IndCca2> {
    aead: A,
    base_nonce: Nonce<A::NonceSize>,
    /// Incremented after each call to `seal`.
    seq: Seq,
}

impl<A: Aead + IndCca2> SealCtx<A> {
    /// The size in bytes of the overhead added to the plaintext.
    pub const OVERHEAD: usize = A::OVERHEAD;

    pub(crate) fn new(
        key: &KeyData<A>,
        base_nonce: &Nonce<A::NonceSize>,
        seq: Seq,
    ) -> Result<Self, ImportError> {
        let key = A::Key::import(key.as_bytes())?;
        Ok(Self {
            aead: A::new(&key),
            base_nonce: base_nonce.clone(),
            seq,
        })
    }

    fn compute_nonce(&self) -> Result<Nonce<A::NonceSize>, MessageLimitReached> {
        self.seq.compute_nonce::<A::NonceSize>(&self.base_nonce)
    }

    fn increment_seq(&mut self) -> Result<Seq, Bug> {
        self.seq.increment::<A::NonceSize>()
    }

    /// Encrypts and authenticates `plaintext`, returning the
    /// sequence number.
    ///
    /// The resulting ciphertext is written to `dst`, which must
    /// be at least `plaintext.len()` + [`OVERHEAD`][Self::OVERHEAD]
    /// bytes long.
    pub fn seal(
        &mut self,
        dst: &mut [u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Seq, HpkeError> {
        let nonce = self.compute_nonce()?;
        self.aead.seal(dst, &nonce, plaintext, additional_data)?;
        let prev = self.increment_seq()?;
        Ok(prev)
    }

    /// Encrypts and authenticates `data` in place, returning the
    /// sequence number.
    pub fn seal_in_place(
        &mut self,
        mut data: impl AsMut<[u8]>,
        tag: &mut [u8],
        additional_data: &[u8],
    ) -> Result<Seq, HpkeError> {
        let nonce = self.compute_nonce()?;
        self.aead
            .seal_in_place(&nonce, data.as_mut(), tag, additional_data)?;
        let prev = self.increment_seq()?;
        Ok(prev)
    }

    /// Returns the current sequence number.
    pub fn seq(&self) -> Seq {
        self.seq
    }
}

/// An encryption context that decrypts messages from
/// a particular sender.
pub struct RecvCtx<K: Kem, F: Kdf, A: Aead + IndCca2> {
    open: Either<OpenCtx<A>, RawKey<A>>,
    export: ExportCtx<K, F, A>,
}

impl<K: Kem, F: Kdf, A: Aead + IndCca2> RecvCtx<K, F, A> {
    /// The size in bytes of the overhead added to the plaintext.
    pub const OVERHEAD: usize = OpenCtx::<A>::OVERHEAD;

    pub(crate) fn into_raw_parts(self) -> Option<(KeyData<A>, Nonce<A::NonceSize>)> {
        match self.open {
            Either::Left(_) => None,
            Either::Right((key, base_nonce)) => Some((key, base_nonce)),
        }
    }

    fn open_ctx(&mut self) -> Result<&mut OpenCtx<A>, ImportError> {
        self.open
            .get_or_insert_left(|(key, nonce)| OpenCtx::new(key, nonce, Seq::ZERO))
    }

    /// Decrypts and authenticates `ciphertext` using the
    /// internal sequence number.
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
        self.open_ctx()?.open(dst, ciphertext, additional_data)
    }

    /// Decrypts and authenticates `ciphertext` at a particular
    /// sequence number.
    ///
    /// The resulting plaintext is written to `dst`, which must
    /// must be at least `ciphertext.len()` - [`Self::OVERHEAD`]
    /// bytes long.
    pub fn open_at(
        &mut self,
        dst: &mut [u8],
        ciphertext: &[u8],
        additional_data: &[u8],
        seq: Seq,
    ) -> Result<(), HpkeError> {
        self.open_ctx()?
            .open_at(dst, ciphertext, additional_data, seq)
    }

    /// Decrypts and authenticates `ciphertext`.
    pub fn open_in_place(
        &mut self,
        data: impl AsMut<[u8]>,
        tag: &[u8],
        additional_data: &[u8],
    ) -> Result<(), HpkeError> {
        self.open_ctx()?.open_in_place(data, tag, additional_data)
    }

    /// Decrypts and authenticates `ciphertext` at a particular
    /// sequence number.
    pub fn open_in_place_at(
        &mut self,
        data: impl AsMut<[u8]>,
        tag: &[u8],
        additional_data: &[u8],
        seq: Seq,
    ) -> Result<(), HpkeError> {
        self.open_ctx()?
            .open_in_place_at(data, tag, additional_data, seq)
    }

    /// Exports a secret from the encryption context.
    pub fn export<T>(&self, context: &[u8]) -> Result<T, KdfError>
    where
        T: Expand,
    {
        self.export.export(context)
    }

    /// Exports a secret from the encryption context, writing it
    /// to `out`.
    pub fn export_into(&self, out: &mut [u8], context: &[u8]) -> Result<(), KdfError> {
        self.export.export_into(out, context)
    }
}

/// An encryption context that can only decrypt messages from
/// a particular sender.
///
/// Unlike [`RecvCtx`], it cannot export secrets.
pub struct OpenCtx<A: Aead + IndCca2> {
    aead: A,
    base_nonce: Nonce<A::NonceSize>,
    /// Incremented after each call to `open`.
    seq: Seq,
}

impl<A: Aead + IndCca2> OpenCtx<A> {
    /// The size in bytes of the overhead added to the plaintext.
    pub const OVERHEAD: usize = A::OVERHEAD;

    pub(crate) fn new(
        key: &KeyData<A>,
        base_nonce: &Nonce<A::NonceSize>,
        seq: Seq,
    ) -> Result<Self, ImportError> {
        let key = A::Key::import(key.as_bytes())?;
        Ok(Self {
            aead: A::new(&key),
            base_nonce: base_nonce.clone(),
            seq,
        })
    }

    fn increment_seq(&mut self) -> Result<Seq, Bug> {
        self.seq.increment::<A::NonceSize>()
    }

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
        self.open_at(dst, ciphertext, additional_data, self.seq)?;
        self.increment_seq()?;
        Ok(())
    }

    /// Decrypts and authenticates `ciphertext` at a particular
    /// sequence number.
    ///
    /// The resulting plaintext is written to `dst`, which must
    /// must be at least `ciphertext.len()` - [`Self::OVERHEAD`]
    /// bytes long.
    pub fn open_at(
        &self,
        dst: &mut [u8],
        ciphertext: &[u8],
        additional_data: &[u8],
        seq: Seq,
    ) -> Result<(), HpkeError> {
        let nonce = seq.compute_nonce::<A::NonceSize>(&self.base_nonce)?;
        self.aead.open(dst, &nonce, ciphertext, additional_data)?;
        Ok(())
    }

    /// Decrypts and authenticates `ciphertext`.
    pub fn open_in_place(
        &mut self,
        mut data: impl AsMut<[u8]>,
        tag: &[u8],
        additional_data: &[u8],
    ) -> Result<(), HpkeError> {
        self.open_in_place_at(data.as_mut(), tag, additional_data, self.seq)?;
        self.increment_seq()?;
        Ok(())
    }

    /// Decrypts and authenticates `ciphertext` at a particular
    /// sequence number.
    pub fn open_in_place_at(
        &self,
        mut data: impl AsMut<[u8]>,
        tag: &[u8],
        additional_data: &[u8],
        seq: Seq,
    ) -> Result<(), HpkeError> {
        let nonce = seq.compute_nonce::<A::NonceSize>(&self.base_nonce)?;
        self.aead
            .open_in_place(&nonce, data.as_mut(), tag, additional_data)?;
        Ok(())
    }
}

/// HPKE's message limit has been reached.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MessageLimitReached;

impl Display for MessageLimitReached {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("message limit reached")
    }
}

impl trouble::Error for MessageLimitReached {}

/// Sequence numbers ensure nonce uniqueness.
#[derive(Copy, Clone, Debug, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Seq {
    /// The sequence number.
    ///
    /// It's encoded as a big-endian integer (I2OSP) and XORed
    /// with the `base_nonce`.
    ///
    /// This should be the size of the nonce, but it's
    /// vanishingly unlikely that we'll ever overflow. Since
    /// encryption contexts ([`SealCtx`], etc.) can only be used
    /// serially, we can only overflow if the user actually
    /// performs 2^64-1 operations. At an impossible one
    /// nanosecond per encryption, this will take upward of 500
    /// years.
    seq: u64,
}

impl Seq {
    /// The zero value of a `Seq`.
    pub const ZERO: Self = Self::new(0);

    /// Creates a sequence number.
    #[inline]
    pub const fn new(seq: u64) -> Self {
        Self { seq }
    }

    /// Converts itself to a `u64`.
    #[inline]
    pub const fn to_u64(self) -> u64 {
        self.seq
    }

    /// Returns the maximum allowed sequence number.
    pub(crate) const fn max<N: ArrayLength>() -> u64 {
        // 1<<(8*N) - 1
        let shift = 8usize.saturating_mul(N::USIZE);
        match 1u64.checked_shl(shift as u32) {
            Some(v) => v.saturating_sub(1),
            None => u64::MAX,
        }
    }

    /// Increments the sequence by one and returns the *previous*
    /// sequence number.
    fn increment<N: ArrayLength>(&mut self) -> Result<Self, Bug> {
        // if self.seq >= (1 << (8*Nn)) - 1:
        //     raise MessageLimitReachedError
        if self.seq >= Self::max::<N>() {
            // We only call `Seq::increment` after computing the
            // nonce, which requires `seq < Self::max`.
            bug!("`Seq::increment` called after limit reached");
        }
        // self.seq += 1
        let prev = self.seq;
        self.seq = prev
            .checked_add(1)
            .assume("`Seq` overflow should be impossible")?;
        Ok(Self { seq: prev })
    }

    /// Computes the per-message nonce.
    fn compute_nonce<N: ArrayLength>(
        self,
        base_nonce: &Nonce<N>,
    ) -> Result<Nonce<N>, MessageLimitReached> {
        if self.seq >= Self::max::<N>() {
            Err(MessageLimitReached)
        } else {
            //  seq_bytes = I2OSP(seq, Nn)
            let seq_bytes = i2osp!(self.seq, N);
            // xor(self.base_nonce, seq_bytes)
            Ok(base_nonce ^ &Nonce::from_bytes(seq_bytes))
        }
    }
}

impl Display for Seq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.seq)
    }
}

struct ExportCtx<K: Kem, F: Kdf, A: Aead + IndCca2> {
    exporter_secret: Prk<F::PrkSize>,
    _etc: PhantomData<(K, A)>,
}

impl<K: Kem, F: Kdf, A: Aead + IndCca2> ExportCtx<K, F, A> {
    fn new(exporter_secret: Prk<F::PrkSize>) -> Self {
        Self {
            exporter_secret,
            _etc: PhantomData,
        }
    }

    /// Exports a secret from the context.
    fn export<T>(&self, context: &[u8]) -> Result<T, KdfError>
    where
        T: Expand,
    {
        // def Context.Export(exporter_context, L):
        //   return LabeledExpand(self.exporter_secret, "sec",
        //                        exporter_context, L)
        Hpke::<K, F, A>::labeled_expand(&self.exporter_secret, "sec", &[context])
    }

    /// Exports a secret from the context, writing it to `out`.
    fn export_into(&self, out: &mut [u8], context: &[u8]) -> Result<(), KdfError> {
        // def Context.Export(exporter_context, L):
        //   return LabeledExpand(self.exporter_secret, "sec",
        //                        exporter_context, L)
        Hpke::<K, F, A>::labeled_expand_into(out, &self.exporter_secret, "sec", &[context])
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use std::{collections::HashSet, ops::RangeInclusive};

    use postcard::experimental::max_size::MaxSize;
    use typenum::{U1, U2};

    use super::*;

    /// Tests that [`Seq::compute_nonce`] generates correct
    /// nonces.
    #[test]
    fn test_seq_compute_nonce() {
        let base = Nonce::<U1>::try_from_slice(&[0xfe]).expect("should be able to create nonce");
        let cases = [
            (0, Ok(&[0xfe])),
            (1, Ok(&[0xff])),
            (2, Ok(&[0xfc])),
            (4, Ok(&[0xfa])),
            (254, Ok(&[0x00])),
            (255, Err(MessageLimitReached)),
            (256, Err(MessageLimitReached)),
            (257, Err(MessageLimitReached)),
            (u64::MAX, Err(MessageLimitReached)),
        ];
        for (input, output) in cases {
            let got = Seq::new(input).compute_nonce::<U1>(&base);
            let want = output.map(|s| Nonce::try_from_slice(s).expect("unable to create nonce"));
            assert_eq!(got, want, "seq = {input}");
        }
    }

    /// Tests that all nonces are unique.
    #[test]
    fn test_seq_unique_nonce() {
        let base =
            Nonce::<U2>::try_from_slice(&[0xfe, 0xfe]).expect("should be able to create nonce");
        let mut seen = HashSet::new();
        for v in 0..u16::MAX {
            let got = Seq::new(u64::from(v))
                .compute_nonce::<U2>(&base)
                .expect("unable to create nonce");
            assert!(seen.insert(got), "duplicate nonce: {got:?}");
        }
    }

    #[test]
    fn test_invalid_psk() {
        let err = Psk::new(&[], &[]).expect_err("should get `InvalidPsk`");
        assert_eq!(err, InvalidPsk);
    }

    #[test]
    fn test_psk_ct_eq() {
        let cases = [
            (true, ("abc", "123"), ("abc", "123")),
            (false, ("a", "b"), ("a", "x")),
            (false, ("a", "b"), ("x", "b")),
            (false, ("a", "b"), ("c", "d")),
        ];
        for (pass, lhs, rhs) in cases {
            let lhs = Psk::new(lhs.0.as_bytes(), lhs.1.as_bytes()).expect("should not fail");
            let rhs = Psk::new(rhs.0.as_bytes(), rhs.1.as_bytes()).expect("should not fail");
            assert_eq!(pass, bool::from(lhs.ct_eq(&rhs)));
        }
    }

    /// Tests that [`AeadId`] is assigned correctly.
    #[test]
    fn test_aead_id() {
        // NB: we include two unofficiant IDs.
        let unassigned = 0x0004..=0xFFFE - 2;
        for id in unassigned {
            let want = AeadId::Other(NonZeroU16::new(id).expect("`id` should be non-zero"));
            let encoded = postcard::to_vec::<_, { u16::POSTCARD_MAX_SIZE }>(&id)
                .expect("should be able to encode `u16`");
            let got: AeadId = postcard::from_bytes(&encoded).unwrap_or_else(|err| {
                panic!("should be able to decode unassigned `AeadId` {id}: {err}")
            });
            assert_eq!(got, want);
        }
    }

    /// Tests that [`KdfId`] is assigned correctly.
    #[test]
    fn test_kdf_id() {
        let unassigned = 0x0004..=0xFFFF;
        for id in unassigned {
            let want = KdfId::Other(NonZeroU16::new(id).expect("`id` should be non-zero"));
            let encoded = postcard::to_vec::<_, { u16::POSTCARD_MAX_SIZE }>(&id)
                .expect("should be able to encode `u16`");
            let got: KdfId = postcard::from_bytes(&encoded).unwrap_or_else(|err| {
                panic!("should be able to decode unassigned `KdfId` {id}: {err}")
            });
            assert_eq!(got, want);
        }
    }

    /// Tests that [`KemId`] is assigned correctly.
    #[test]
    fn test_kem_id() {
        let unassigned: [RangeInclusive<u16>; 3] =
            [0x0001..=0x000F, 0x0022..=0x002F, 0x0031..=0xFFFF];
        for id in unassigned.into_iter().flatten() {
            let want = KemId::Other(NonZeroU16::new(id).expect("`id` should be non-zero"));
            let encoded = postcard::to_vec::<_, { u16::POSTCARD_MAX_SIZE }>(&id)
                .expect("should be able to encode `u16`");
            let got: KemId = postcard::from_bytes(&encoded).unwrap_or_else(|err| {
                panic!("should be able to decode unassigned `KemId` {id}: {err}")
            });
            assert_eq!(got, want);
        }
    }
}
