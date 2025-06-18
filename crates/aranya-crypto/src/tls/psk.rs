use core::{cell::OnceCell, fmt, marker::PhantomData};

use buggy::{Bug, BugExt};
use derive_where::derive_where;
use serde::{Deserialize, Serialize};
use spideroak_crypto::{
    aead::Tag,
    hex::Hex,
    hpke::Mode,
    kdf::{self, Kdf},
    keys::SecretKeyBytes,
};
use zerocopy::{ByteEq, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    aranya::{Encap, EncryptionKey, EncryptionPublicKey},
    ciphersuite::{CipherSuite, CipherSuiteExt},
    engine::unwrapped,
    error::Error,
    generic_array::GenericArray,
    hpke::{self, Mode},
    id::{custom_id, IdError, Identified},
    policy::{GroupId, PolicyId},
    subtle::{Choice, ConstantTimeEq},
    tls::{self, CipherSuiteId},
    util::{self, Hpke},
    zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing},
    Csprng, Random,
};

type Prk<CS> = kdf::Prk<<<CS as CipherSuite>::Kdf as Kdf>::PrkSize>;

/// Prefix-free domain separation for [`PskSeed`].
const SEED_DOMAIN: &[u8] = b"SeedForAranyaTls-v1";

/// Prefix-free domain separation for [`Psk`].
const PSK_DOMAIN: &[u8] = b"PskForAranyaTls-v1";

custom_id! {
    /// Uniquely identifies a [`PskSeed`].
    #[derive(Immutable, IntoBytes, KnownLayout, Unaligned)]
    pub struct PskSeedId;
}

/// A cryptographic seed used to derive multiple [`Psk`]s.
///
/// # Example
///
/// ```rust
/// # #[cfg(all(feature = "alloc", not(feature = "trng")))]
/// # {
/// use aranya_crypto::{
///     default::{
///         DefaultCipherSuite,
///         DefaultEngine,
///     },
///     PolicyId,
///     Rng,
///     subtle::ConstantTimeEq,
///     tls::{CipherSuiteId, PskSeed},
/// };
/// type CS = DefaultCipherSuite;
/// // NB: In a real application the policy ID would be
/// // deterministically generated from the policy used to create
/// // the team.
/// let policy_id = PolicyId::random(&mut Rng);
/// let seed = PskSeed::<CS>::new(&mut Rng, &policy_id);
///
/// let psk1 = seed.generate_psk(CipherSuiteId::TlsAes128GcmSha256).unwrap();
/// let psk2 = seed.generate_psk(CipherSuiteId::TlsAes256GcmSha384).unwrap();
/// assert!(!bool::from(psk1.ct_eq(&psk2)));
///
/// let psk1 = seed.generate_psk(CipherSuiteId::TlsAes128GcmSha256).unwrap();
/// let psk2 = seed.generate_psk(CipherSuiteId::TlsAes128GcmSha256).unwrap();
/// assert!(bool::from(psk1.ct_eq(&psk2)));
/// # }
/// ```
#[derive_where(Clone, Debug)]
pub struct PskSeed<CS: CipherSuite> {
    #[derive_where(skip(Debug))]
    prk: Prk<CS>,
    // The ID is computed with `labeled_expand(...)`, which can
    // be slow, relative to just returning a struct field,
    // anyway. We could compute it in the constructor, but then
    // (a) the constructor becomes fallible, and (b) that doesn't
    // play well with `unwrapped!`. Instead, just cache the
    // result.
    id: OnceCell<Result<PskSeedId, Bug>>,
    _marker: PhantomData<CS>,
}

impl<CS: CipherSuite> PskSeed<CS> {
    /// Generates a random `PskSeed`.
    pub fn new<R>(rng: &mut R, group: &GroupId) -> Self
    where
        R: Csprng,
    {
        let ikm = Zeroizing::new(Random::random(rng));
        Self::from_ikm(&ikm, group)
    }

    /// Imports a `PskSeed` from an existing IKM in a manner
    /// similar to [RFC 9258].
    ///
    /// - `ikm` must be cryptographically secure, but need not be
    ///   uniformly random.
    ///
    /// [RFC 9258]: https://datatracker.ietf.org/doc/html/rfc9258
    pub fn import_from_ikm(ikm: &[u8; 32], group: &GroupId) -> Self {
        Self::from_ikm(ikm, group)
    }

    /// Creates a `PskSeed` from some IKM.
    ///
    /// Only `pub(crate)` for testing purposes.
    pub(crate) fn from_ikm(ikm: &[u8; 32], group: &GroupId) -> Self {
        let prk = CS::labeled_extract(SEED_DOMAIN, &[], b"prk", [group.as_bytes(), ikm]);
        Self::from_prk(prk)
    }

    /// Only broken out for `unwrapped!`.
    fn from_prk(prk: Prk<CS>) -> Self {
        Self {
            prk,
            id: OnceCell::new(),
            _marker: PhantomData,
        }
    }

    /// Attempts to compute the PSK seed ID.
    fn try_id(&self) -> Result<&PskSeedId, &Bug> {
        self.id
            .get_or_init(|| {
                // KDFs have the property that their output does
                // not reaveal anything about the secret input.
                // Specifically, an attacker with knowledge of
                // the structure of the secret and with the
                // ability to perform arbitrary queries should
                // not be able to distinguish the KDF's output
                // from a random bitstring with a probability
                // greater than 50%. (See [hkdf], definition 7.)
                //
                // This means that so long as we have proper
                // domain separation, we can use the KDF to
                // generate the ID from the secret itself.
                //
                // The docs for `CipherSuite::Kdf` state that it
                // should be able to expand at least 64 octets.
                // IDs are 32 octets, so this should never fail.
                //
                // [hkdf]: https://eprint.iacr.org/2010/264.pdf]
                let id = CS::labeled_expand(SEED_DOMAIN, &self.prk, b"id", [])
                    .assume("should be able to generate PSK seed ID")?;
                Ok(PskSeedId(id))
            })
            .as_ref()
    }

    /// Generates PSKs for the provided cipher suites.
    ///
    /// - `context` is a unique constant string that describes
    ///   that the PSKs are being used for. For example, it could
    ///   be `b"quic-syncer-v4"`.
    ///
    /// This method is deterministic over each (`PskSeed`,
    /// `context`, `GroupId`, and `CipherSuiteId` tuple). Calling
    /// it with the same tuple will generate the same PSKs.
    pub fn generate_psks<I>(
        self,
        context: &'static [u8],
        group: GroupId,
        policy: PolicyId,
        suites: I,
    ) -> impl Iterator<Item = Result<Psk<CS>, Error>>
    where
        I: Iterator<Item = CipherSuiteId>,
    {
        suites.into_iter().map(move |suite| {
            let id = ImportedIdentity {
                external_identity: *self.try_id().map_err(Bug::clone)?,
                context: PskCtx { group, policy },
                target_protocol: tls::Version::Tls13,
                target_kdf: suite,
            };
            let secret =
                CS::labeled_expand(PSK_DOMAIN, &self.prk, b"psk", [id.as_bytes(), context])?;
            Ok(Psk {
                id: PskId(id),
                secret,
                _marker: PhantomData,
            })
        })
    }
}

impl<CS: CipherSuite> ZeroizeOnDrop for PskSeed<CS> {}
impl<CS: CipherSuite> Drop for PskSeed<CS> {
    #[inline]
    fn drop(&mut self) {
        util::is_zeroize_on_drop(&self.prk);
    }
}

unwrapped! {
    name: PskSeed;
    type: Prk;
    into: |key: Self| { key.prk.clone() };
    from: |prk| { Self::from_prk(prk) };
}

impl<CS: CipherSuite> Identified for PskSeed<CS> {
    type Id = PskSeedId;

    #[inline]
    fn id(&self) -> Result<Self::Id, IdError> {
        let id = self.try_id().map_err(Bug::clone)?;
        Ok(*id)
    }
}

impl<CS: CipherSuite> ConstantTimeEq for PskSeed<CS> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        // `self.id` is derived from `self.prk`, so ignore it.
        self.prk.ct_eq(&other.prk)
    }
}

/// From [RFC 9258].
///
/// ```text
/// struct {
///    opaque external_identity<1...2^16-1>;
///    opaque context<0..2^16-1>;
///    uint16 target_protocol;
///    uint16 target_kdf;
/// } ImportedIdentity;
/// ```
///
/// [RFC 9258]: https://datatracker.ietf.org/doc/html/rfc9258
#[repr(C)]
#[derive(Copy, Clone, Debug, Immutable, IntoBytes, KnownLayout, Serialize, Deserialize)]
struct ImportedIdentity {
    // NB: These two fields are variable-length in the RFC (and
    // therefore have leading length bytes), but fixed length
    // here.
    external_identity: PskSeedId,
    context: PskCtx,
    target_protocol: tls::Version,
    // NB: In RFC 9258 this is just the KDF, but we bind it to
    // the entire cipher suite instead.
    target_kdf: CipherSuiteId,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Immutable, IntoBytes, KnownLayout, Serialize, Deserialize)]
struct PskCtx {
    group: GroupId,
    policy: PolicyId,
}

impl<CS: CipherSuite> EncryptionKey<CS> {
    /// Uses `self` to encrypt and authenticate the [`PskSeed`]
    /// such that it can only be decrypted by the holder of the
    /// private half of `peer_pk`.
    ///
    /// It is an error if `pk` is the public key for `self`.
    pub fn seal_psk_seed<R: Csprng>(
        &self,
        rng: &mut R,
        seed: &PskSeed<CS>,
        peer_pk: &EncryptionPublicKey<CS>,
        group: &GroupId,
    ) -> Result<(Encap<CS>, EncryptedPskSeed<CS>), Error> {
        if &self.public()? == peer_pk {
            return Err(Error::InvalidArgument("same `EncryptionKey`"));
        }
        // info = concat(
        //     "PskSeed-v1",
        //     group,
        // )
        let info = Info {
            domain: *b"PskSeed-v1",
            group: *group,
        };
        let (enc, mut ctx) =
            hpke::setup_send::<CS, _>(rng, Mode::Auth(&self.key), &peer_pk.0, [info.as_bytes()])?;
        let mut ciphertext = seed.prk.clone().into_bytes().into_bytes();
        let mut tag = Tag::<CS::Aead>::default();
        ctx.seal_in_place(&mut ciphertext, &mut tag, info.as_bytes())
            .inspect_err(|_| ciphertext.zeroize())?;
        Ok((Encap(enc), EncryptedPskSeed { ciphertext, tag }))
    }

    /// Uses `self` to decrypt and authenticate a [`PskSeed`]
    /// that was encrypted by `peer_pk`.
    pub fn open_psk_seed(
        &self,
        encap: &Encap<CS>,
        ciphertext: EncryptedPskSeed<CS>,
        peer_pk: &EncryptionPublicKey<CS>,
        group: &GroupId,
    ) -> Result<PskSeed<CS>, Error> {
        let EncryptedPskSeed {
            mut ciphertext,
            tag,
        } = ciphertext;

        // info = concat(
        //     "PskSeed-v1",
        //     group,
        // )
        let info = Info {
            domain: *b"PskSeed-v1",
            group: *group,
        };
        let mut ctx = hpke::setup_recv::<CS>(
            Mode::Auth(&peer_pk.0),
            &encap.0,
            &self.key,
            [info.as_bytes()],
        )?;
        ctx.open_in_place(&mut ciphertext, &tag, info.as_bytes())?;

        let prk = Prk::<CS>::new(SecretKeyBytes::new(ciphertext));
        Ok(PskSeed::from_prk(prk))
    }
}

/// An encrypted [`PskSeed`].
#[derive_where(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedPskSeed<CS: CipherSuite> {
    // NB: These are only `pub(crate)` for testing purposes.
    pub(crate) ciphertext: GenericArray<u8, <<CS as CipherSuite>::Kdf as Kdf>::PrkSize>,
    pub(crate) tag: Tag<CS::Aead>,
}

/// A TLS 1.3 external pre-shared key.
///
/// See [RFC 8446] section 4.2.11 for more information about
/// PSKs.
///
/// [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446#autoid-37
#[derive_where(Clone, Debug)]
pub struct Psk<CS> {
    #[derive_where(skip(Debug))]
    secret: [u8; 32],
    id: PskId,
    _marker: PhantomData<CS>,
}

impl<CS: CipherSuite> Psk<CS> {
    /// Returns the PSK identity.
    ///
    /// See [RFC 8446] section 4.2.11 for more information about
    /// PSKs.
    ///
    /// [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446#autoid-37
    pub fn identity(&self) -> &PskId {
        &self.id
    }

    /// Returns the raw PSK secret.
    ///
    /// See [RFC 8446] section 4.2.11 for more information about
    /// PSKs.
    ///
    /// [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446#autoid-37
    pub fn raw_secret_bytes(&self) -> &[u8] {
        &self.secret
    }
}

impl<CS> ZeroizeOnDrop for Psk<CS> {}
impl<CS> Drop for Psk<CS> {
    #[inline]
    fn drop(&mut self) {
        self.secret.zeroize()
    }
}

impl<CS> ConstantTimeEq for Psk<CS> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        // Both `self.secret` and `self.id` are derived from the
        // same seed and cipher suite, so we can ignore
        // `self.id`. The likelihood that two PSKs generated from
        // different seeds will have the same ID is
        // cryptographically negligible.
        self.secret.ct_eq(&other.secret)
    }
}

/// Uniquely identifies a [`Psk`].
///
/// # Note About `PartialEq`
///
/// `PskId` is not a secret, so it can be freely compared with
/// [`PartialEq`]. However, doing so may leak knowledge about
/// which PSKs are present. In general, prefer [`ConstantTimeEq`]
/// to [`PartialEq`].
#[derive(Copy, Clone, Debug, ByteEq, Immutable, IntoBytes, KnownLayout, Serialize, Deserialize)]
pub struct PskId(ImportedIdentity);

impl PskId {
    /// Returns the seed's unique ID.
    pub const fn seed_id(&self) -> &PskSeedId {
        &self.0.external_identity
    }

    /// Returns the group ID.
    pub const fn group_id(&self) -> &GroupId {
        &self.0.context.group
    }

    /// Returns the TLS 1.3 cipher suite ID.
    pub const fn cipher_suite(&self) -> CipherSuiteId {
        self.0.target_kdf
    }

    /// Converts the ID to its byte encoding.
    pub const fn as_bytes(&self) -> &[u8] {
        let bytes: &[u8; 100] = zerocopy::transmute_ref!(self);
        bytes
    }
}

impl ConstantTimeEq for PskId {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

impl fmt::Display for PskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Hex::new(self.as_bytes()).fmt(f)
    }
}
