use core::cell::OnceCell;

use buggy::BugExt;
use serde::{Deserialize, Serialize};
use spideroak_crypto::{
    csprng::Random,
    hash::{Digest, Hash},
    hpke::{Hpke, Mode},
    import::ImportError,
    kem::Kem,
    subtle::{Choice, ConstantTimeEq},
};

use crate::{
    afc::{
        keys::{OpenKey, SealKey, Seq},
        shared::{RawOpenKey, RawSealKey, RootChannelKey},
    },
    aranya::{DeviceId, Encap, EncryptionKey, EncryptionPublicKey},
    ciphersuite::{CipherSuite, CipherSuiteExt},
    engine::{Engine, unwrapped},
    error::Error,
    id::{Id, IdError, custom_id},
    misc::sk_misc,
};

/// Contextual information for a unidirectional AFC channel.
///
/// In a unidirectional channel, one device is permitted to encrypt
/// messages and one device is permitted to receive decrypt
/// messages.
///
/// ```rust
/// # #[cfg(all(feature = "alloc", not(feature = "trng")))]
/// # {
/// use {
///     core::borrow::{Borrow, BorrowMut},
///     aranya_crypto::{
///         afc::{
///             AuthData,
///             OpenKey,
///             SealKey,
///             UniAuthorSecret,
///             UniChannel,
///             UniOpenKey,
///             UniPeerEncap,
///             UniSealKey,
///             UniSecrets,
///         },
///         CipherSuite,
///         Csprng,
///         default::{
///             DefaultCipherSuite,
///             DefaultEngine,
///         },
///         Engine,
///         Id,
///         IdentityKey,
///         EncryptionKey,
///         Rng,
///     }
/// };
///
/// fn key_from_author<CS: CipherSuite>(
///     ch: &UniChannel<'_, CS>,
///     secret: UniAuthorSecret<CS>,
/// ) -> SealKey<CS> {
///     let key = UniSealKey::from_author_secret(ch, secret)
///         .expect("should be able to decapsulate author secret");
///     key.into_key().expect("should be able to create `SealKey`")
/// }
///
/// fn key_from_peer<CS: CipherSuite>(
///     ch: &UniChannel<'_, CS>,
///     encap: UniPeerEncap<CS>,
/// ) -> OpenKey<CS>{
///     let key = UniOpenKey::from_peer_encap(ch, encap)
///         .expect("should be able to decapsulate peer key");
///     key.into_key().expect("should be able to create `OpenKey`")
/// }
///
/// type E = DefaultEngine<Rng, DefaultCipherSuite>;
/// let (mut eng, _) = E::from_entropy(Rng);
///
/// let parent_cmd_id = Id::random(&mut eng);
/// let label = 42u32;
///
/// let device1_sk = EncryptionKey::<<E as Engine>::CS>::new(&mut eng);
/// let device1_id = IdentityKey::<<E as Engine>::CS>::new(&mut eng).id().expect("device1 ID should be valid");
///
/// let device2_sk = EncryptionKey::<<E as Engine>::CS>::new(&mut eng);
/// let device2_id = IdentityKey::<<E as Engine>::CS>::new(&mut eng).id().expect("device2 ID should be valid");
///
/// // device1 creates the channel keys and sends the encapsulation
/// // to device2...
/// let device1_ch = UniChannel {
///     parent_cmd_id,
///     our_sk: &device1_sk,
///     their_pk: &device2_sk.public().expect("receiver encryption key should be valid"),
///     seal_id: device1_id,
///     open_id: device2_id,
///     label,
/// };
/// let UniSecrets { author, peer } = UniSecrets::new(&mut eng, &device1_ch)
///     .expect("unable to create `UniSecrets`");
/// let mut device1 = key_from_author(&device1_ch, author);
///
/// // ...and device2 decrypts the encapsulation to discover the
/// // channel keys.
/// let device2_ch = UniChannel {
///     parent_cmd_id,
///     our_sk: &device2_sk,
///     their_pk: &device1_sk.public().expect("receiver encryption key should be valid"),
///     seal_id: device1_id,
///     open_id: device2_id,
///     label,
/// };
/// let device2 = key_from_peer(&device2_ch, peer);
///
/// fn test<CS: CipherSuite>(seal: &mut SealKey<CS>, open: &OpenKey<CS>) {
///     const GOLDEN: &[u8] = b"hello, world!";
///     const ADDITIONAL_DATA: &[u8] = b"authenticated, but not encrypted data";
///
///     let version = 4;
///     let label = 1234;
///     let (ciphertext, seq) = {
///         let mut dst = vec![0u8; GOLDEN.len() + SealKey::<CS>::OVERHEAD];
///         let ad = AuthData { version, label };
///         let seq = seal.seal(&mut dst, GOLDEN, &ad)
///             .expect("should be able to encrypt plaintext");
///         (dst, seq)
///     };
///     let plaintext = {
///         let mut dst = vec![0u8; ciphertext.len()];
///         let ad = AuthData { version, label };
///         open.open(&mut dst, &ciphertext, &ad, seq)
///             .expect("should be able to decrypt ciphertext");
///         dst.truncate(ciphertext.len() - OpenKey::<CS>::OVERHEAD);
///         dst
///     };
///     assert_eq!(&plaintext, GOLDEN);
/// }
/// test(&mut device1, &device2); // device1 -> device2
/// # }
/// ```
pub struct UniChannel<'a, CS: CipherSuite> {
    /// The ID of the parent command.
    pub parent_cmd_id: Id,
    /// Our secret encryption key.
    pub our_sk: &'a EncryptionKey<CS>,
    /// Their public encryption key.
    pub their_pk: &'a EncryptionPublicKey<CS>,
    /// The device that is permitted to encrypt messages.
    pub seal_id: DeviceId,
    /// The device that is permitted to decrypt messages.
    pub open_id: DeviceId,
    /// The policy label applied to the channel.
    pub label: u32,
}

impl<CS: CipherSuite> UniChannel<'_, CS> {
    pub(crate) fn info(&self) -> Digest<<CS::Hash as Hash>::DigestSize> {
        // info = H(
        //     "AfcUnidirectionalKey",
        //     suite_id,
        //     engine_id,
        //     parent_cmd_id,
        //     seal_id,
        //     open_id,
        //     i2osp(label, 4),
        // )
        CS::tuple_hash(
            b"AfcUnidirectionalKey",
            [
                self.parent_cmd_id.as_bytes(),
                self.seal_id.as_bytes(),
                self.open_id.as_bytes(),
                &self.label.to_be_bytes(),
            ],
        )
    }
}

/// A unirectional channel author's secret.
pub struct UniAuthorSecret<CS: CipherSuite> {
    key: RootChannelKey<CS>,
    id: OnceCell<Result<UniAuthorSecretId, IdError>>,
}

sk_misc!(UniAuthorSecret, UniAuthorSecretId);

impl<CS: CipherSuite> ConstantTimeEq for UniAuthorSecret<CS> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.key.ct_eq(&other.key)
    }
}

unwrapped! {
    name: UniAuthorSecret;
    type: Decap;
    into: |key: Self| { key.key.into_inner() };
    from: |key| { Self { key: RootChannelKey::new(key), id: OnceCell::new() } };
}

/// A unirectional channel peer's encapsulated secret.
///
/// This should be freely shared with the channel peer.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct UniPeerEncap<CS: CipherSuite> {
    encap: Encap<CS>,
    #[serde(skip)]
    id: OnceCell<UniChannelId>,
}

impl<CS: CipherSuite> UniPeerEncap<CS> {
    /// Uniquely identifies the unirectional channel.
    #[inline]
    pub fn id(&self) -> UniChannelId {
        *self
            .id
            .get_or_init(|| UniChannelId(Id::new::<CS>(self.as_bytes(), b"UniChannelId")))
    }

    /// Encodes itself as bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.encap.as_bytes()
    }

    /// Returns itself from its byte encoding.
    #[inline]
    pub fn from_bytes(data: &[u8]) -> Result<Self, ImportError> {
        Ok(Self {
            encap: Encap::from_bytes(data)?,
            id: OnceCell::new(),
        })
    }

    fn as_inner(&self) -> &<CS::Kem as Kem>::Encap {
        self.encap.as_inner()
    }
}

custom_id! {
    /// Uniquely identifies a unidirectional channel.
    pub struct UniChannelId;
}

/// The secrets for a unirectional channel.
pub struct UniSecrets<CS: CipherSuite> {
    /// The author's secret.
    pub author: UniAuthorSecret<CS>,
    /// The peer's encapsulation.
    pub peer: UniPeerEncap<CS>,
}

impl<CS: CipherSuite> UniSecrets<CS> {
    /// Creates a new set of encapsulated secrets for the
    /// unidirectional channel.
    pub fn new<E: Engine<CS = CS>>(eng: &mut E, ch: &UniChannel<'_, CS>) -> Result<Self, Error> {
        // Only the channel author calls this function.
        let author_sk = ch.our_sk;
        let peer_pk = ch.their_pk;

        if ch.seal_id == ch.open_id {
            return Err(Error::same_device_id());
        }

        let root_sk = RootChannelKey::random(eng);
        let peer = {
            let (enc, _) = Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_send_deterministically(
                Mode::Auth(&author_sk.key),
                &peer_pk.0,
                &ch.info(),
                // TODO(eric): should HPKE take a ref?
                root_sk.clone().into_inner(),
            )?;
            UniPeerEncap {
                encap: Encap(enc),
                id: OnceCell::new(),
            }
        };
        let author = UniAuthorSecret {
            key: root_sk,
            id: OnceCell::new(),
        };

        Ok(UniSecrets { author, peer })
    }

    /// Uniquely identifies the unirectional channel.
    #[inline]
    pub fn id(&self) -> UniChannelId {
        self.peer.id()
    }
}

macro_rules! uni_key {
    ($name:ident, $inner:ident, $doc:expr $(,)?) => {
        #[doc = $doc]
        pub struct $name<CS: CipherSuite>($inner<CS>);

        impl<CS: CipherSuite> $name<CS> {
            /// Creates the channel author's unidirectional
            /// channel key.
            pub fn from_author_secret(
                ch: &UniChannel<'_, CS>,
                secret: UniAuthorSecret<CS>,
            ) -> Result<Self, Error> {
                // Only the channel author calls this function.
                let author_sk = ch.our_sk;
                let peer_pk = ch.their_pk;

                if ch.seal_id == ch.open_id {
                    return Err(Error::same_device_id());
                }

                let (_, ctx) = Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_send_deterministically(
                    Mode::Auth(&author_sk.key),
                    &peer_pk.0,
                    &ch.info(),
                    secret.key.into_inner(),
                )?;
                let key = {
                    // `SendCtx` only gets rid of the raw key
                    // after the first call to `seal`, etc., so
                    // it should still exist at this point.
                    let (key, base_nonce) = ctx
                        .into_raw_parts()
                        .assume("`SendCtx` should still contain the raw key")?;
                    $inner { key, base_nonce }
                };
                Ok(Self(key))
            }

            /// Decrypts and authenticates an encapsulated key
            /// received from a peer.
            pub fn from_peer_encap(
                ch: &UniChannel<'_, CS>,
                enc: UniPeerEncap<CS>,
            ) -> Result<Self, Error> {
                // Only the channel peer calls this function.
                let peer_sk = ch.our_sk;
                let author_pk = ch.their_pk;

                if ch.seal_id == ch.open_id {
                    return Err(Error::same_device_id());
                }

                let info = ch.info();
                let ctx = Hpke::<CS::Kem, CS::Kdf, CS::Aead>::setup_recv(
                    Mode::Auth(&author_pk.0),
                    enc.as_inner(),
                    &peer_sk.key,
                    &info,
                )?;
                let key = {
                    // `Recv` only gets rid of the raw key after
                    // the first call to `open`, etc., so it
                    // should still exist at this point.
                    let (key, base_nonce) = ctx
                        .into_raw_parts()
                        .assume("`RecvCtx` should still contain the raw key")?;
                    $inner { key, base_nonce }
                };
                Ok(Self(key))
            }

            /// Returns the raw key material.
            pub fn into_raw_key(self) -> $inner<CS> {
                self.0
            }

            /// Returns the raw key material.
            #[cfg(any(test, feature = "test_util"))]
            pub(crate) fn as_raw_key(&self) -> &$inner<CS> {
                &self.0
            }
        }
    };
}
uni_key!(
    UniSealKey,
    RawSealKey,
    "A unidirectional channel encryption key.",
);

impl<CS: CipherSuite> UniSealKey<CS> {
    /// Returns the channel key.
    pub fn into_key(self) -> Result<SealKey<CS>, Error> {
        let seal = SealKey::from_raw(&self.0, Seq::ZERO)?;
        Ok(seal)
    }
}

uni_key!(
    UniOpenKey,
    RawOpenKey,
    "A unidirectional channel decryption key.",
);

impl<CS: CipherSuite> UniOpenKey<CS> {
    /// Returns the channel key.
    pub fn into_key(self) -> Result<OpenKey<CS>, Error> {
        let open = OpenKey::from_raw(&self.0)?;
        Ok(open)
    }
}
