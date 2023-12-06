#![forbid(unsafe_code)]

use core::{
    borrow::{Borrow, BorrowMut},
    fmt,
    marker::PhantomData,
    result::Result,
};

use subtle::{Choice, ConstantTimeEq};

use crate::{
    aead::{Aead, BufferTooSmallError, KeyData, OpenError, SealError},
    aranya::VerifyingKey,
    ciphersuite::SuiteIds,
    csprng::Csprng,
    engine::Engine,
    error::Error,
    hash::{tuple_hash, Hash},
    id::Id,
    import::{try_import, Import, ImportError},
    kdf::{Kdf, KdfError},
    mac::Mac,
    zeroize::{Zeroize, ZeroizeOnDrop},
};

/// Key material used to derive per-event encryption keys.
pub struct GroupKey<E: ?Sized> {
    seed: [u8; 64],
    _cs: PhantomData<E>,
}

impl<E: ?Sized> ZeroizeOnDrop for GroupKey<E> {}
impl<E: ?Sized> Drop for GroupKey<E> {
    fn drop(&mut self) {
        self.seed.zeroize()
    }
}

impl<E: Engine + ?Sized> Clone for GroupKey<E> {
    fn clone(&self) -> Self {
        Self {
            seed: self.seed,
            _cs: PhantomData,
        }
    }
}

impl<E: Engine + ?Sized> GroupKey<E> {
    /// Creates a new, random `GroupKey`.
    pub fn new<R: Csprng>(rng: &mut R) -> GroupKey<E> {
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    /// Uniquely identifies the [`GroupKey`].
    ///
    /// Two keys with the same ID are the same key.
    #[inline]
    pub fn id(&self) -> GroupKeyId {
        // ID = MAC(
        //     key=GroupKey,
        //     message="GroupKeyId-v1" || suite_id,
        //     outputBytes=64,
        // )
        let mut h = E::Mac::new(&self.seed.into());
        h.update(b"GroupKeyId-v1");
        h.update(&SuiteIds::from_suite::<E>().into_bytes());
        GroupKeyId(h.tag().into())
    }

    /// The size in bytes of the overhead added to plaintexts
    /// encrypted with [`seal`][Self::seal].
    pub const OVERHEAD: usize = E::Aead::NONCE_SIZE + E::Aead::OVERHEAD;

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
    ///     DefaultCipherSuite,
    ///     DefaultEngine,
    ///     GroupKey,
    ///     Id,
    ///     Rng,
    ///     SigningKey,
    /// };
    ///
    /// const MESSAGE: &[u8] = b"hello, world!";
    /// const LABEL: &str = "doc test";
    /// const PARENT: Id = Id::default();
    /// let author = SigningKey::<DefaultEngine<Rng, DefaultCipherSuite>>::new(&mut Rng).public();
    ///
    /// let key = GroupKey::new(&mut Rng);
    ///
    /// let ciphertext = {
    ///     let mut dst = vec![0u8; MESSAGE.len() + key.overhead()];
    ///     key.seal(&mut Rng, &mut dst, MESSAGE, Context{
    ///         label: LABEL,
    ///         parent: PARENT,
    ///         author: &author,
    ///     }).expect("should not fail");
    ///     dst
    /// };
    /// let plaintext = {
    ///     let mut dst = vec![0u8; ciphertext.len() - key.overhead()];
    ///     key.open(&mut dst, &ciphertext, Context{
    ///         label: LABEL,
    ///         parent: PARENT,
    ///         author: &author,
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
        ctx: Context<'_, E>,
    ) -> Result<(), Error> {
        if dst.len() < self.overhead() {
            // Not enough room in `dst`.
            return Err(Error::Seal(SealError::BufferTooSmall(BufferTooSmallError(
                Some(self.overhead() + plaintext.len()),
            ))));
        }
        let (nonce, out) = dst.split_at_mut(E::Aead::NONCE_SIZE);
        rng.fill_bytes(nonce);
        let info = ctx.to_bytes();
        let key = self.derive_key(&info)?;
        Ok(E::Aead::new(&key).seal(out, nonce, plaintext, &info)?)
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
        ctx: Context<'_, E>,
    ) -> Result<(), Error> {
        if ciphertext.len() < self.overhead() {
            // Can't find the nonce and/or tag, so it's obviously
            // invalid.
            return Err(OpenError::Authentication.into());
        }
        let (nonce, ciphertext) = ciphertext.split_at(E::Aead::NONCE_SIZE);
        let info = ctx.to_bytes();
        let key = self.derive_key(&info)?;
        Ok(E::Aead::new(&key).open(dst, nonce, ciphertext, &info)?)
    }

    /// Derives a key for [`Self::open`] and [`Self::seal`].
    fn derive_key(&self, info: &[u8]) -> Result<<E::Aead as Aead>::Key, Error> {
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
        let prk = Self::labeled_extract(&[], b"EventKey_prk", &self.seed);
        let key = Self::labeled_expand::<KeyData<E::Aead>, 12>(&prk, b"EventKey_key", info)?;
        Ok(<<E::Aead as Aead>::Key as Import<_>>::import(key.borrow())?)
    }

    fn labeled_extract<const N: usize>(
        salt: &[u8],
        label: &[u8; N],
        ikm: &[u8; 64],
    ) -> <E::Kdf as Kdf>::Prk {
        let labeled_ikm = [
            "kdf-ext-v1".as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            label,
            ikm,
        ];
        E::Kdf::extract_multi(&labeled_ikm, salt)
    }

    fn labeled_expand<T: Borrow<[u8]> + BorrowMut<[u8]> + Default, const N: usize>(
        prk: &<E::Kdf as Kdf>::Prk,
        label: &[u8; N],
        info: &[u8],
    ) -> Result<T, KdfError> {
        let mut out = T::default();
        // We know all possible enumerations of `T` and they all
        // must have a length <= 2^16 - 1.
        assert!(out.borrow().len() <= (u16::MAX as usize));
        let labeled_info = [
            &(out.borrow().len() as u16).to_be_bytes(),
            "kdf-exp-v1".as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            label,
            info,
        ];
        E::Kdf::expand_multi(out.borrow_mut(), prk, &labeled_info)?;
        Ok(out)
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

    /// Tries to create itself from bytes.
    ///
    /// NB: `GroupKey` does not implement `Import<[u8]>` or
    /// `TryFrom` or `Try` because we do not want to expose this
    /// functionality to users.
    pub(crate) fn try_from(data: &[u8]) -> Result<Self, ImportError> {
        Ok(Self {
            seed: try_import(data)?,
            _cs: PhantomData,
        })
    }
}

impl<E: Engine + ?Sized> ConstantTimeEq for GroupKey<E> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.seed.ct_eq(&other.seed)
    }
}

/// Contextual binding for [`GroupKey::seal`] and
/// [`GroupKey::open`].
pub struct Context<'a, E: Engine + ?Sized> {
    /// Describes what is being encrypted.
    ///
    /// For example, it could be an event name.
    pub label: &'static str,
    /// The stable ID of the parent event.
    pub parent: Id,
    /// The public key of the author of the encrypted data.
    pub author: &'a VerifyingKey<E>,
}

impl<E: Engine + ?Sized> Context<'_, E> {
    /// Converts the [`Context`] to its byte representation.
    fn to_bytes(&self) -> <E::Hash as Hash>::Digest {
        // Ideally, this would simple be the actual concatenation
        // of `Context`'s fields. However, we need to be
        // `no_alloc` and without `const_generic_exprs` it's
        // quite difficult to concatenate the fields into
        // a fixed-size buffer.
        //
        // So, we instead hash the fields into a fixed-size
        // buffer. We use `tuple_hash` out of paranoia, but
        // a regular hash should also suffice.
        tuple_hash::<E::Hash, _>([
            self.label.as_bytes(),
            self.parent.as_ref(),
            self.author.id().as_bytes(),
        ])
    }
}

/// Uniquely identifies a [`GroupKey`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct GroupKeyId(Id);

impl AsRef<[u8]> for GroupKeyId {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Id> for GroupKeyId {
    #[inline]
    fn from(id: Id) -> Self {
        Self(id)
    }
}

impl From<GroupKeyId> for Id {
    #[inline]
    fn from(id: GroupKeyId) -> Self {
        id.0
    }
}

impl fmt::Display for GroupKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
