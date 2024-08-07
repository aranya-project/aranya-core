#![forbid(unsafe_code)]

use core::{marker::PhantomData, result::Result};

use buggy::Bug;
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};
use typenum::U64;

use crate::{
    aead::{Aead, BufferTooSmallError, KeyData, OpenError, SealError, Tag},
    aranya::VerifyingKey,
    ciphersuite::SuiteIds,
    csprng::{Csprng, Random},
    engine::unwrapped,
    error::Error,
    hash::{tuple_hash, Digest, Hash},
    hmac::Hmac,
    id::{custom_id, Id, IdError, Identified},
    import::Import,
    kdf,
    zeroize::{Zeroize, ZeroizeOnDrop},
    CipherSuite,
};

/// Key material used to derive per-event encryption keys.
pub struct GroupKey<CS> {
    seed: [u8; 64],
    _cs: PhantomData<CS>,
}

impl<CS> ZeroizeOnDrop for GroupKey<CS> {}
impl<CS> Drop for GroupKey<CS> {
    fn drop(&mut self) {
        self.seed.zeroize()
    }
}

impl<CS> Clone for GroupKey<CS> {
    fn clone(&self) -> Self {
        Self {
            seed: self.seed,
            _cs: PhantomData,
        }
    }
}

impl<CS: CipherSuite> GroupKey<CS> {
    /// Creates a new, random `GroupKey`.
    pub fn new<R: Csprng>(rng: &mut R) -> GroupKey<CS> {
        Self::from_seed(Random::random(rng))
    }

    /// Uniquely identifies the [`GroupKey`].
    ///
    /// Two keys with the same ID are the same key.
    #[inline]
    pub fn id(&self) -> GroupKeyId {
        // ID = HMAC(
        //     key=GroupKey,
        //     message="GroupKeyId-v1" || suite_id,
        //     outputBytes=64,
        // )
        let mut h = Hmac::<CS::Hash>::new(&self.seed);
        h.update(b"GroupKeyId-v1");
        h.update(&SuiteIds::from_suite::<CS>().into_bytes());
        GroupKeyId(h.tag().into_array().into())
    }

    /// The size in bytes of the overhead added to plaintexts
    /// encrypted with [`seal`][Self::seal].
    pub const OVERHEAD: usize = CS::Aead::NONCE_SIZE + CS::Aead::OVERHEAD;

    /// Returns the size in bytes of the overhead added to
    /// plaintexts encrypted with [`seal`][Self::seal].
    ///
    /// Same as [`OVERHEAD`][Self::OVERHEAD].
    pub const fn overhead(&self) -> usize {
        Self::OVERHEAD
    }

    /// Encrypts and authenticates `plaintext` in a particular
    /// context.
    ///
    /// The resulting ciphertext is written to `dst`, which must
    /// be at least [`overhead`][Self::overhead] bytes longer
    /// than `plaintext.len()`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", not(feature = "moonshot")))]
    /// # {
    /// use crypto::{
    ///     Context,
    ///     default::{
    ///         DefaultCipherSuite,
    ///         DefaultEngine,
    ///     },
    ///     GroupKey,
    ///     Id,
    ///     Rng,
    ///     SigningKey,
    /// };
    ///
    /// const MESSAGE: &[u8] = b"hello, world!";
    /// const LABEL: &str = "doc test";
    /// const PARENT: Id = Id::default();
    /// let author = SigningKey::<DefaultCipherSuite>::new(&mut Rng).public().expect("signing key should be valid");
    ///
    /// let key = GroupKey::new(&mut Rng);
    ///
    /// let ciphertext = {
    ///     let mut dst = vec![0u8; MESSAGE.len() + key.overhead()];
    ///     key.seal(&mut Rng, &mut dst, MESSAGE, Context{
    ///         label: LABEL,
    ///         parent: PARENT,
    ///         author_sign_pk: &author,
    ///     }).expect("should not fail");
    ///     dst
    /// };
    /// let plaintext = {
    ///     let mut dst = vec![0u8; ciphertext.len() - key.overhead()];
    ///     key.open(&mut dst, &ciphertext, Context{
    ///         label: LABEL,
    ///         parent: PARENT,
    ///         author_sign_pk: &author,
    ///     }).expect("should not fail");
    ///     dst
    /// };
    /// assert_eq!(&plaintext, MESSAGE);
    /// # }
    /// ```
    pub fn seal<R: Csprng>(
        &self,
        rng: &mut R,
        dst: &mut [u8],
        plaintext: &[u8],
        ctx: Context<'_, CS>,
    ) -> Result<(), Error> {
        if dst.len() < self.overhead() {
            // Not enough room in `dst`.
            let required = self
                .overhead()
                .checked_add(plaintext.len())
                .ok_or(Error::Bug(Bug::new(
                    "overhead + plaintext length must not wrap",
                )))?;
            return Err(Error::Seal(SealError::BufferTooSmall(BufferTooSmallError(
                Some(required),
            ))));
        }
        let (nonce, out) = dst.split_at_mut(CS::Aead::NONCE_SIZE);
        rng.fill_bytes(nonce);
        let info = ctx.to_bytes()?;
        let key = self.derive_key(&info)?;
        Ok(CS::Aead::new(&key).seal(out, nonce, plaintext, &info)?)
    }

    /// Decrypts and authenticates `ciphertext` in a particular
    /// context.
    ///
    /// The resulting plaintext is written to `dst`, which must
    /// be at least as long as the original plaintext (i.e.,
    /// `ciphertext.len()` - [`overhead`][Self::overhead] bytes
    /// long).
    pub fn open(
        &self,
        dst: &mut [u8],
        ciphertext: &[u8],
        ctx: Context<'_, CS>,
    ) -> Result<(), Error> {
        if ciphertext.len() < self.overhead() {
            // Can't find the nonce and/or tag, so it's obviously
            // invalid.
            return Err(OpenError::Authentication.into());
        }
        let (nonce, ciphertext) = ciphertext.split_at(CS::Aead::NONCE_SIZE);
        let info = ctx.to_bytes()?;
        let key = self.derive_key(&info)?;
        Ok(CS::Aead::new(&key).open(dst, nonce, ciphertext, &info)?)
    }

    const EXTRACT_CTX: kdf::Context = kdf::Context {
        domain: "kdf-ext-v1",
        suite_ids: &SuiteIds::from_suite::<CS>().into_bytes(),
    };

    const EXPAND_CTX: kdf::Context = kdf::Context {
        domain: "kdf-exp-v1",
        suite_ids: &SuiteIds::from_suite::<CS>().into_bytes(),
    };

    /// Derives a key for [`Self::open`] and [`Self::seal`].
    fn derive_key(&self, info: &[u8]) -> Result<<CS::Aead as Aead>::Key, Error> {
        // GroupKey = KDF(
        //     key={0,1}^512,
        //     salt={0}^512,
        //     info=concat(
        //         L,
        //         "kdf-exp-v1",
        //         suite_id,
        //         "EventKey_key",
        //         parent,
        //     ),
        //     outputBytes=64,
        // )
        let prk = Self::EXTRACT_CTX.labeled_extract::<CS::Kdf>(&[], "EventKey_prk", &self.seed);
        let key = Self::EXPAND_CTX.labeled_expand::<CS::Kdf, KeyData<CS::Aead>>(
            &prk,
            "EventKey_key",
            &[info],
        )?;
        Ok(<<CS::Aead as Aead>::Key as Import<_>>::import(
            key.as_bytes(),
        )?)
    }

    // Utility routines for other modules.

    /// Returns the underlying seed.
    pub(crate) const fn raw_seed(&self) -> &[u8; 64] {
        &self.seed
    }

    /// Creates itself from the seed.
    pub(crate) const fn from_seed(seed: [u8; 64]) -> Self {
        Self {
            seed,
            _cs: PhantomData,
        }
    }
}

unwrapped! {
    name: GroupKey;
    type: Seed;
    into: |key: Self| { key.seed };
    from: |seed: [u8;64] | { Self::from_seed(seed) };
}

impl<CS: CipherSuite> Identified for GroupKey<CS> {
    type Id = GroupKeyId;

    #[inline]
    fn id(&self) -> Result<Self::Id, IdError> {
        Ok(self.id())
    }
}

impl<CS: CipherSuite> ConstantTimeEq for GroupKey<CS> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.seed.ct_eq(&other.seed)
    }
}

/// Contextual binding for [`GroupKey::seal`] and
/// [`GroupKey::open`].
pub struct Context<'a, CS: CipherSuite> {
    /// Describes what is being encrypted.
    ///
    /// For example, it could be an event name.
    pub label: &'a str,
    /// The stable ID of the parent event.
    pub parent: Id,
    /// The public key of the author of the encrypted data.
    pub author_sign_pk: &'a VerifyingKey<CS>,
}

impl<CS: CipherSuite> Context<'_, CS> {
    /// Converts the [`Context`] to its byte representation.
    fn to_bytes(&self) -> Result<Digest<<CS::Hash as Hash>::DigestSize>, Error> {
        // Ideally, this would simple be the actual concatenation
        // of `Context`'s fields. However, we need to be
        // `no_alloc` and without `const_generic_exprs` it's
        // quite difficult to concatenate the fields into
        // a fixed-size buffer.
        //
        // So, we instead hash the fields into a fixed-size
        // buffer. We use `tuple_hash` out of paranoia, but
        // a regular hash should also suffice.
        Ok(tuple_hash::<CS::Hash, _>([
            self.label.as_bytes(),
            self.parent.as_ref(),
            self.author_sign_pk.id()?.as_bytes(),
        ]))
    }
}

custom_id! {
    /// Uniquely identifies a [`GroupKey`].
    pub struct GroupKeyId;
}

/// An encrypted [`GroupKey`].
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedGroupKey<CS: CipherSuite> {
    pub(crate) ciphertext: GenericArray<u8, U64>,
    pub(crate) tag: Tag<CS::Aead>,
}

impl<CS: CipherSuite> Clone for EncryptedGroupKey<CS> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            ciphertext: self.ciphertext,
            tag: self.tag.clone(),
        }
    }
}
