#![forbid(unsafe_code)]

use core::{cell::OnceCell, marker::PhantomData, result::Result};

use buggy::Bug;
use serde::{Deserialize, Serialize};
use spideroak_crypto::{
    aead::{Aead, BufferTooSmallError, KeyData, OpenError, SealError, Tag},
    csprng::{Csprng, Random},
    hash::{Digest, Hash},
    import::Import,
    subtle::{Choice, ConstantTimeEq},
    typenum::U64,
    zeroize::{Zeroize, ZeroizeOnDrop},
};

use crate::{
    aranya::VerifyingKey,
    ciphersuite::{CipherSuite, CipherSuiteExt},
    engine::unwrapped,
    error::Error,
    generic_array::GenericArray,
    id::{custom_id, Id, IdError, Identified},
};

/// Key material used to derive per-event encryption keys.
pub struct GroupKey<CS> {
    seed: [u8; 64],
    id: OnceCell<Result<GroupKeyId, IdError>>,
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
            id: OnceCell::new(),
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
    pub fn id(&self) -> Result<GroupKeyId, IdError> {
        self.id
            .get_or_init(|| {
                // prk = LabeledExtract(
                //     "GroupKeyId-v1",
                //     {0}^n,
                //     "prk",
                //     seed,
                // )
                // GroupKey = LabeledExpand(
                //     "GroupKeyId-v1",
                //     prk,
                //     "id",
                //     {0}^0,
                // )
                const DOMAIN: &[u8] = b"GroupKeyId-v1";
                let prk = CS::labeled_extract(DOMAIN, &[], b"prk", &self.seed);
                CS::labeled_expand(DOMAIN, &prk, b"id", [])
                    .map_err(|_| IdError("unable to expand PRK"))
                    .map(GroupKeyId)
            })
            .clone()
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
    /// # #[cfg(all(feature = "alloc", not(feature = "trng")))]
    /// # {
    /// use aranya_crypto::{
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

    /// Derives a key for [`Self::open`] and [`Self::seal`].
    fn derive_key(&self, info: &[u8]) -> Result<<CS::Aead as Aead>::Key, Error> {
        // prk = LabeledExtract(
        //     "kdf-ext-v1",
        //     {0}^n,
        //     "EventKey_prk",
        //     seed,
        // )
        // GroupKey = LabeledExpand(
        //     "kdf-exp-v1",
        //     prk,
        //     "EventKey_key",
        //     info,
        // )
        let prk = CS::labeled_extract(b"kdf-ext-v1", &[], b"EventKey_prk", &self.seed);
        let key: KeyData<CS::Aead> =
            CS::labeled_expand(b"kdr-exp-v1", &prk, b"EventKey_key", [info])?;
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
            id: OnceCell::new(),
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
        self.id()
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
        Ok(CS::tuple_hash(
            b"GroupKey",
            [
                self.label.as_bytes(),
                self.parent.as_ref(),
                self.author_sign_pk.id()?.as_bytes(),
            ],
        ))
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
