//! Cryptography code for [APS].
//!
//! [APS]: https://github.com/spideroak-inc/aps

use {
    crate::{
        aead::{Aead, KeyData},
        aranya::UserId,
        ciphersuite::SuiteIds,
        engine::Engine,
        error::Error,
        hybrid_array::{
            typenum::{Sum, U64},
            ArraySize, ByteArray,
        },
        id::{custom_id, Id},
        import::{try_import, ImportError, InvalidSizeError},
        kdf::{Kdf, KdfError},
        mac::Mac,
        zeroize::ZeroizeOnDrop,
    },
    core::{
        borrow::{Borrow, BorrowMut},
        iter::zip,
        marker::PhantomData,
        ops::Add,
    },
    subtle::{Choice, ConstantTimeEq},
};

// This is different from the rest of the `crypto` API in that it
// allows users to directly access key material (`ChannelKeys`).
// Unfortunately, we have to allow this since APS needs to store
// the raw key material.

custom_id!(ChannelSeedId, "Uniquely identifies a [`ChannelSeed`].");

/// Per-channel encryption keys.
pub struct ChannelKeys<T> {
    seal_key: T,
    open_key: T,
}

impl<T: Borrow<[u8]>> ChannelKeys<T> {
    /// The key used to encrypt data for a peer.
    pub fn seal_key(&self) -> &[u8] {
        self.seal_key.borrow()
    }

    /// The key used to decrypt data from a peer.
    pub fn open_key(&self) -> &[u8] {
        self.open_key.borrow()
    }
}

/// The seed used to derive the encryption keys for an APS
/// channel.
#[derive(ZeroizeOnDrop)]
pub struct ChannelSeed<E> {
    seed: [u8; 64],
    _e: PhantomData<E>,
}

impl<E> Clone for ChannelSeed<E> {
    fn clone(&self) -> Self {
        Self {
            seed: self.seed,
            _e: PhantomData,
        }
    }
}

impl<E: Engine + ?Sized> ChannelSeed<E> {
    /// Creates a new, random `ChannelSeed`.
    pub fn new(eng: &mut E) -> Self {
        let mut seed = [0u8; 64];
        eng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    /// Uniquely identifies the `ChannelSeed`.
    ///
    /// Two seeds with the same ID are the same seed.
    #[inline]
    pub fn id(&self) -> ChannelSeedId {
        // ID = MAC(
        //     key=ChannelSeed,
        //     message="ChannelSeed-v1" || suite_id,
        //     outputBytes=64,
        // )
        let mut h = E::Mac::new(&self.seed.into());
        h.update(b"ChannelSeed-v1");
        h.update(&SuiteIds::from_suite::<E>().into_bytes());
        ChannelSeedId(h.tag().into())
    }

    /// Derives the keys for a particular channel.
    ///
    /// `cmd_id` is the ID of the command that created the seed.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", not(feature = "moonshot")))]
    /// # {
    /// use crypto::{
    ///     aps::{ChannelKeys, ChannelSeed},
    ///     Csprng,
    ///     DefaultCipherSuite,
    ///     DefaultEngine,
    ///     Id,
    ///     IdentityKey,
    ///     Rng,
    /// };
    ///
    /// # type E = DefaultEngine<Rng, DefaultCipherSuite>;
    /// let (mut eng, _) = DefaultEngine::<Rng, DefaultCipherSuite>::from_entropy(Rng);
    /// let user1 = IdentityKey::<E>::new(&mut eng).id();
    /// let user2 = IdentityKey::<E>::new(&mut eng).id();
    /// let cmd_id = Id::random(&mut eng);
    ///
    /// let label = 123;
    /// let seed = ChannelSeed::new(&mut eng);
    /// let ck1 = seed
    ///     .derive_keys(label, &user1, &user2, &cmd_id)
    ///     .expect("unable to derive `ChannelKeys`");
    /// let ck2 = seed
    ///     .derive_keys(label, &user2, &user1, &cmd_id)
    ///     .expect("unable to derive `ChannelKeys`");
    ///
    /// // `ck1` and `ck2` should be the reverse of each other.
    /// assert_eq!(ck1.seal_key(), ck2.open_key());
    /// assert_eq!(ck1.open_key(), ck2.seal_key());
    /// # }
    /// ```
    pub fn derive_keys(
        &self,
        label: u32,
        our_id: &UserId,
        peer_id: &UserId,
        cmd_id: &Id,
    ) -> Result<ChannelKeys<KeyData<E::Aead>>, Error> {
        if our_id == peer_id {
            return Err(Error::InvalidArgument("same `UserId`"));
        }

        let mut salt = [0u8; 64];
        for (dst, (x, y)) in zip(&mut salt, zip(our_id.as_array(), peer_id.as_array())) {
            *dst = x ^ y;
        }

        // seal_key is the key we use to encrypt for the peer, so
        // configure it with the peer's UserID for that reason.
        let seal_key = self.derive_key(&salt, label, peer_id, our_id, cmd_id)?;

        // open_key is the key we use to decrypt from the peer,
        // so configure it with our UserID for that reason.
        let open_key = self.derive_key(&salt, label, our_id, peer_id, cmd_id)?;

        Ok(ChannelKeys { seal_key, open_key })
    }

    /// Derive either the `SealKey` or `OpenKey`.
    fn derive_key(
        &self,
        salt: &[u8; 64],
        label: u32,
        id1: &UserId,
        id2: &UserId,
        cmd_id: &Id,
    ) -> Result<KeyData<E::Aead>, KdfError> {
        debug_assert_ne!(id1, id2);

        let prk = Self::labeled_extract(salt, "APSv1_prk", &self.seed);
        Self::labeled_expand(&prk, "APSv1_key", label, id1, id2, cmd_id)
    }

    fn labeled_extract(
        salt: &[u8; 64],
        label: &'static str,
        ikm: &[u8; 64],
    ) -> <E::Kdf as Kdf>::Prk {
        let labeled_ikm = [
            "kdf-ext-v1".as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            label.as_bytes(),
            ikm,
        ];
        E::Kdf::extract_multi(&labeled_ikm, salt)
    }

    fn labeled_expand(
        prk: &<E::Kdf as Kdf>::Prk,
        label: &'static str,
        aps_label: u32,
        id1: &UserId,
        id2: &UserId,
        cmd_id: &Id,
    ) -> Result<KeyData<E::Aead>, KdfError> {
        debug_assert_ne!(id1, id2);

        let mut out = KeyData::<E::Aead>::default();
        // We know all possible enumerations of `T` and they all
        // must have a length <= 2^16 - 1.
        assert!(out.borrow().len() <= (u16::MAX as usize));
        let labeled_info = [
            &(out.borrow().len() as u16).to_be_bytes(),
            "kdf-exp-v1".as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            label.as_bytes(),
            &aps_label.to_be_bytes(),
            id1.as_bytes(),
            id2.as_bytes(),
            cmd_id.as_bytes(),
        ];
        E::Kdf::expand_multi(out.borrow_mut(), prk, &labeled_info)?;
        Ok(out)
    }

    // Utility routines for other modules.

    /// Returns the underlying seed.
    pub(crate) const fn raw_seed(&self) -> &[u8; 64] {
        &self.seed
    }

    pub(crate) fn from_seed(seed: [u8; 64]) -> Self {
        Self {
            seed,
            _e: PhantomData,
        }
    }

    /// Tries to create itself from bytes.
    ///
    /// NB: `ChannelSeed` does not implement `Import<[u8]>` or
    /// `TryFrom` or `Try` because we do not want to expose this
    /// functionality to users.
    pub(crate) fn try_from(data: &[u8]) -> Result<Self, ImportError> {
        Ok(Self::from_seed(try_import(data)?))
    }
}

impl<E> ConstantTimeEq for ChannelSeed<E> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.seed.ct_eq(&other.seed)
    }
}

/// An encrypted [`ChannelSeed`].
pub struct EncryptedChannelSeed<E: Engine + ?Sized>(
    pub(crate) ByteArray<Sum<<E::Aead as Aead>::TagSize, U64>>,
)
where
    <E::Aead as Aead>::TagSize: Add<U64>,
    Sum<<E::Aead as Aead>::TagSize, U64>: ArraySize;

impl<E: Engine + ?Sized> EncryptedChannelSeed<E>
where
    <E::Aead as Aead>::TagSize: Add<U64>,
    Sum<<E::Aead as Aead>::TagSize, U64>: ArraySize,
{
    const SIZE: usize = 64 + E::Aead::TAG_SIZE;

    /// Encodes itself as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Returns itself from its byte encoding.
    pub fn from_bytes(data: &[u8]) -> Result<Self, InvalidSizeError> {
        let v = data.try_into().map_err(|_| InvalidSizeError {
            got: data.len(),
            want: Self::SIZE..Self::SIZE,
        })?;
        Ok(Self(v))
    }
}
