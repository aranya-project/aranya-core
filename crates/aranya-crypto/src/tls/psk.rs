use core::{cell::OnceCell, fmt, marker::PhantomData};

use buggy::{Bug, BugExt};
use serde::{Deserialize, Serialize};
use spideroak_crypto::{
    aead::Tag,
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
    id::{custom_id, IdError, Identified},
    policy::{GroupId, PolicyId},
    subtle::{Choice, ConstantTimeEq},
    tls::CipherSuiteId,
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
pub struct PskSeed<CS: CipherSuite> {
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
    pub fn new<R>(rng: &mut R, policy: &PolicyId) -> Self
    where
        R: Csprng,
    {
        let ikm = Zeroizing::new(Random::random(rng));
        Self::from_ikm(&ikm, policy)
    }

    /// Creates a `PskSeed` from some IKM.
    ///
    /// Only `pub(crate)` for testing purposes.
    pub(crate) fn from_ikm(ikm: &[u8; 32], policy: &PolicyId) -> Self {
        let prk = CS::labeled_extract(SEED_DOMAIN, policy.as_bytes(), b"prk", ikm);
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

    /// Generates a PSK for the cipher suite.
    ///
    /// This method is deterministic over the `PskSeed` and
    /// cipher suite: calling it with the same `PskSeed` and
    /// cipher suite will generate the same PSK.
    pub fn generate_psk(&self, suite: CipherSuiteId) -> Result<Psk<CS>, Error> {
        let id = PskId {
            id: *self.try_id().map_err(Bug::clone)?,
            suite,
        };
        let secret = CS::labeled_expand(PSK_DOMAIN, &self.prk, b"psk", [suite.as_bytes()])?;
        Ok(Psk {
            id,
            secret,
            _marker: PhantomData,
        })
    }
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
        // info = H(
        //     "PskSeed-v1",
        //     suite_id,
        //     group,
        // )
        let info = CS::tuple_hash(b"PskSeed-v1", [group.as_bytes()]);
        let (enc, mut ctx) = Hpke::<CS>::setup_send(rng, Mode::Auth(&self.key), &peer_pk.0, &info)?;
        let mut ciphertext = seed.prk.clone().into_bytes().into_bytes();
        let mut tag = Tag::<CS::Aead>::default();
        ctx.seal_in_place(&mut ciphertext, &mut tag, &info)
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

        // info = H(
        //     "PskSeed-v1",
        //     suite_id,
        //     group,
        // )
        let info = CS::tuple_hash(b"PskSeed-v1", [group.as_bytes()]);
        let mut ctx = Hpke::<CS>::setup_recv(Mode::Auth(&peer_pk.0), &encap.0, &self.key, &info)?;
        ctx.open_in_place(&mut ciphertext, &tag, &info)?;

        let prk = Prk::<CS>::new(SecretKeyBytes::new(ciphertext));
        Ok(PskSeed::from_prk(prk))
    }
}

impl<CS: CipherSuite> Clone for PskSeed<CS> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            prk: self.prk.clone(),
            id: self.id.clone(),
            _marker: PhantomData,
        }
    }
}

impl<CS: CipherSuite> fmt::Debug for PskSeed<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Avoid leaking `seed`.
        f.debug_struct("PskSeed")
            .field("id", &self.try_id())
            .finish_non_exhaustive()
    }
}

impl<CS: CipherSuite> ZeroizeOnDrop for PskSeed<CS> {}
impl<CS: CipherSuite> Drop for PskSeed<CS> {
    #[inline]
    fn drop(&mut self) {
        util::val_is_zeroize_on_drop(&self.prk);
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

/// An encrypted [`PskSeed`].
#[derive(Serialize, Deserialize)]
#[serde(bound = "CS: CipherSuite")]
pub struct EncryptedPskSeed<CS: CipherSuite> {
    // NB: These are only `pub(crate)` for testing purposes.
    pub(crate) ciphertext: GenericArray<u8, <<CS as CipherSuite>::Kdf as Kdf>::PrkSize>,
    pub(crate) tag: Tag<CS::Aead>,
}

impl<CS: CipherSuite> Clone for EncryptedPskSeed<CS> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            ciphertext: self.ciphertext.clone(),
            tag: self.tag.clone(),
        }
    }
}

impl<CS: CipherSuite> fmt::Debug for EncryptedPskSeed<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedPskSeed")
            .field("ciphertext", &self.ciphertext)
            .field("tag", &self.tag)
            .finish()
    }
}

/// A TLS 1.3 external pre-shared key.
///
/// See [RFC 8446] section 4.2.11 for more information about
/// PSKs.
///
/// [RFC 8446]: https://datatracker.ietf.org/doc/html/rfc8446#autoid-37
pub struct Psk<CS> {
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

impl<CS> Clone for Psk<CS> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            secret: self.secret,
            _marker: PhantomData,
        }
    }
}

impl<CS> fmt::Debug for Psk<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Avoid leaking `secret`.
        f.debug_struct("Psk")
            .field("id", &self.id)
            .finish_non_exhaustive()
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
pub struct PskId {
    id: PskSeedId,
    suite: CipherSuiteId,
}

impl PskId {
    /// Returns the seed's unique ID.
    pub const fn seed_id(&self) -> &PskSeedId {
        &self.id
    }

    /// Returns the TLS 1.3 cipher suite ID.
    pub const fn cipher_suite(&self) -> CipherSuiteId {
        self.suite
    }

    /// Converts the ID to its byte encoding.
    pub const fn as_bytes(&self) -> &[u8; 34] {
        zerocopy::transmute_ref!(self)
    }
}

impl ConstantTimeEq for PskId {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

impl From<(PskSeedId, CipherSuiteId)> for PskId {
    #[inline]
    fn from((id, suite): (PskSeedId, CipherSuiteId)) -> Self {
        Self { id, suite }
    }
}

impl fmt::Display for PskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { id, suite } = self;
        write!(f, "Psk-{id}-{suite}")
    }
}
