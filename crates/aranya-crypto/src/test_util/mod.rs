//! Utilities for testing [`Engine`][crate::Engine],
//! [`CipherSuite`], and cryptography implementations.
//!
//! If you implement any traits in this crate it is **very
//! highly** recommended that you use these tests.

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::panic)]
#![cfg(any(test, feature = "test_util"))]
#![cfg_attr(docsrs, doc(cfg(feature = "test_util")))]
#![forbid(unsafe_code)]

pub mod ciphersuite;
pub mod engine;

use core::{
    fmt::{self, Debug},
    marker::PhantomData,
};

pub use aranya_crypto_core::test_util::{
    aead::{self, test_aead},
    hash::{self, test_hash},
    hpke::{self, test_hpke},
    kdf::{self, test_kdf},
    mac::{self, test_mac},
    signer::{self, test_signer},
    vectors,
};
pub use ciphersuite::test_ciphersuite;
pub use engine::test_engine;

use crate::{
    aead::{Aead, AeadId, IndCca2, Lifetime, OpenError, SealError},
    ciphersuite::CipherSuite,
    csprng::Csprng,
    hash::Hash,
    import::{ExportError, Import, ImportError},
    kdf::{Kdf, KdfError, KdfId, Prk},
    kem::Kem,
    keys::{PublicKey, SecretKey, SecretKeyBytes},
    mac::{Mac, MacId},
    signer::{Signature, Signer, SignerError, SignerId, SigningKey, VerifyingKey},
    subtle::{Choice, ConstantTimeEq},
    typenum::U64,
    zeroize::ZeroizeOnDrop,
    Id,
};

#[macro_export]
#[doc(hidden)]
macro_rules! __apply {
    ($callback:ident, $($tt:tt),* $(,)?) => {
        $(
            $callback!($tt);
        )*
    };
}
pub use __apply;

/// Like [`assert_eq!`], but for [`Choice`].
#[macro_export]
macro_rules! assert_ct_eq {
    ($lhs:expr, $rhs:expr) => {
        assert!(bool::from($crate::subtle::ConstantTimeEq::ct_eq(&$lhs, &$rhs)))
    };
    ($lhs:expr, $rhs:expr, ) => {
        $crate::assert_ct_eq!($lhs, $rhs)
    };
    ($lhs:expr, $rhs:expr, $($args:tt)+) => {
        assert!(bool::from($crate::subtle::ConstantTimeEq::ct_eq(&$lhs, &$rhs)), $($args)+)
    };
}
pub(super) use assert_ct_eq;

/// Like [`assert_ne!`], but for [`Choice`].
#[macro_export]
macro_rules! assert_ct_ne {
    ($lhs:expr, $rhs:expr) => {
        assert!(bool::from($crate::subtle::ConstantTimeEq::ct_ne(&$lhs, &$rhs)))
    };
    ($lhs:expr, $rhs:expr, ) => {
        $crate::assert_ct_ne!($lhs, $rhs)
    };
    ($lhs:expr, $rhs:expr, $($args:tt)+) => {
        assert!(bool::from($crate::subtle::ConstantTimeEq::ct_ne(&$lhs, &$rhs)), $($args)+)
    };
}
pub(super) use assert_ct_ne;

/// A shim that declares `OS_hardware_rand` for doctests.
#[macro_export]
#[doc(hidden)]
macro_rules! __doctest_os_hardware_rand {
    () => {
        #[cfg(feature = "trng")]
        #[no_mangle]
        extern "C" fn OS_hardware_rand() -> u32 {
            use rand::RngCore;
            rand::rngs::OsRng.next_u32()
        }
    };
}

/// An [`Aead`] that that uses the default trait methods.
pub struct AeadWithDefaults<T>(T);

impl<T: Aead> Aead for AeadWithDefaults<T> {
    const ID: AeadId = T::ID;

    const LIFETIME: Lifetime = T::LIFETIME;

    type KeySize = T::KeySize;
    const KEY_SIZE: usize = T::KEY_SIZE;

    type NonceSize = T::NonceSize;
    const NONCE_SIZE: usize = T::NONCE_SIZE;

    type Overhead = T::Overhead;
    const OVERHEAD: usize = T::OVERHEAD;

    const MAX_PLAINTEXT_SIZE: u64 = T::MAX_PLAINTEXT_SIZE;
    const MAX_ADDITIONAL_DATA_SIZE: u64 = T::MAX_ADDITIONAL_DATA_SIZE;
    const MAX_CIPHERTEXT_SIZE: u64 = T::MAX_CIPHERTEXT_SIZE;

    type Key = T::Key;

    fn new(key: &Self::Key) -> Self {
        Self(T::new(key))
    }

    fn seal_in_place(
        &self,
        nonce: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
        additional_data: &[u8],
    ) -> Result<(), SealError> {
        self.0.seal_in_place(nonce, data, tag, additional_data)
    }

    fn open_in_place(
        &self,
        nonce: &[u8],
        data: &mut [u8],
        tag: &[u8],
        additional_data: &[u8],
    ) -> Result<(), OpenError> {
        self.0.open_in_place(nonce, data, tag, additional_data)
    }
}

/// A [`Kdf`] that that uses the default trait methods.
pub struct KdfWithDefaults<T>(PhantomData<T>);

impl<T: Kdf> Kdf for KdfWithDefaults<T> {
    const ID: KdfId = T::ID;

    type MaxOutput = T::MaxOutput;

    type PrkSize = T::PrkSize;

    fn extract_multi<I>(ikm: I, salt: &[u8]) -> Prk<Self::PrkSize>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        T::extract_multi(ikm, salt)
    }

    fn expand_multi<I>(out: &mut [u8], prk: &Prk<Self::PrkSize>, info: I) -> Result<(), KdfError>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
        I::IntoIter: Clone,
    {
        T::expand_multi(out, prk, info)
    }
}

/// A [`Mac`] that that uses the default trait methods.
#[derive(Clone)]
pub struct MacWithDefaults<T>(T);

impl<T: Mac> Mac for MacWithDefaults<T> {
    const ID: MacId = T::ID;

    type Tag = T::Tag;
    type TagSize = T::TagSize;

    type Key = T::Key;
    type KeySize = T::KeySize;

    fn new(key: &Self::Key) -> Self {
        Self(T::new(key))
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }

    fn tag(self) -> Self::Tag {
        self.0.tag()
    }
}

/// A [`Signer`] that that uses the default trait methods.
pub struct SignerWithDefaults<T: ?Sized>(T);

impl<T: Signer + ?Sized> Signer for SignerWithDefaults<T> {
    const ID: SignerId = T::ID;

    type SigningKey = SigningKeyWithDefaults<T>;
    type VerifyingKey = VerifyingKeyWithDefaults<T>;
    type Signature = SignatureWithDefaults<T>;
}

/// A [`SigningKey`] that uses the default trait methods.
pub struct SigningKeyWithDefaults<T: Signer + ?Sized>(T::SigningKey);

impl<T: Signer + ?Sized> SigningKey<SignerWithDefaults<T>> for SigningKeyWithDefaults<T> {
    fn sign(&self, msg: &[u8]) -> Result<SignatureWithDefaults<T>, SignerError> {
        Ok(SignatureWithDefaults(self.0.sign(msg)?))
    }

    fn public(&self) -> Result<VerifyingKeyWithDefaults<T>, crate::signer::PkError> {
        Ok(VerifyingKeyWithDefaults(self.0.public()?))
    }
}

impl<T: Signer + ?Sized> SecretKey for SigningKeyWithDefaults<T> {
    type Size = <T::SigningKey as SecretKey>::Size;

    fn new<R: Csprng>(rng: &mut R) -> Self {
        Self(T::SigningKey::new(rng))
    }

    fn try_export_secret(&self) -> Result<SecretKeyBytes<Self::Size>, ExportError> {
        self.0.try_export_secret()
    }
}

impl<T: Signer + ?Sized> ConstantTimeEq for SigningKeyWithDefaults<T> {
    fn ct_eq(&self, other: &Self) -> Choice {
        ConstantTimeEq::ct_eq(&self.0, &other.0)
    }
}

impl<'a, T: Signer + ?Sized> Import<&'a [u8]> for SigningKeyWithDefaults<T> {
    fn import(data: &'a [u8]) -> Result<Self, ImportError> {
        Ok(Self(T::SigningKey::import(data)?))
    }
}

impl<T: Signer + ?Sized> Clone for SigningKeyWithDefaults<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Signer + ?Sized> ZeroizeOnDrop for SigningKeyWithDefaults<T> {}

/// A [`VerifyingKey`] that uses the default trait methods.
pub struct VerifyingKeyWithDefaults<T: Signer + ?Sized>(T::VerifyingKey);

impl<T: Signer + ?Sized> VerifyingKey<SignerWithDefaults<T>> for VerifyingKeyWithDefaults<T> {
    fn verify(&self, msg: &[u8], sig: &SignatureWithDefaults<T>) -> Result<(), SignerError> {
        self.0.verify(msg, &sig.0)
    }
}

impl<T: Signer + ?Sized> PublicKey for VerifyingKeyWithDefaults<T> {
    type Data = <T::VerifyingKey as PublicKey>::Data;

    fn export(&self) -> Self::Data {
        self.0.export()
    }
}

impl<'a, T: Signer + ?Sized> Import<&'a [u8]> for VerifyingKeyWithDefaults<T> {
    fn import(data: &'a [u8]) -> Result<Self, ImportError> {
        Ok(Self(T::VerifyingKey::import(data)?))
    }
}

impl<T: Signer + ?Sized> Clone for VerifyingKeyWithDefaults<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Signer + ?Sized> Debug for VerifyingKeyWithDefaults<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl<T: Signer + ?Sized> Eq for VerifyingKeyWithDefaults<T> {}
impl<T: Signer + ?Sized> PartialEq for VerifyingKeyWithDefaults<T> {
    fn eq(&self, other: &Self) -> bool {
        PartialEq::eq(&self.0, &other.0)
    }
}

/// [`Signer::Signature`] that uses the default trait methods.
pub struct SignatureWithDefaults<T: Signer + ?Sized>(T::Signature);

impl<T: Signer + ?Sized> Signature<SignerWithDefaults<T>> for SignatureWithDefaults<T> {
    type Data = <T::Signature as Signature<T>>::Data;

    fn export(&self) -> Self::Data {
        self.0.export()
    }
}

impl<T: Signer + ?Sized> Clone for SignatureWithDefaults<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Signer + ?Sized> Debug for SignatureWithDefaults<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl<'a, T: Signer + ?Sized> Import<&'a [u8]> for SignatureWithDefaults<T> {
    fn import(data: &'a [u8]) -> Result<Self, ImportError> {
        Ok(Self(T::Signature::import(data)?))
    }
}

/// A test [`CipherSuite`].
pub struct TestCs<
    A: Aead + IndCca2,
    H: Hash<DigestSize = U64>,
    F: Kdf,
    K: Kem,
    M: Mac<KeySize = U64, TagSize = U64>,
    S: Signer,
>(PhantomData<(A, H, F, K, M, S)>);

impl<A, H, F, K, M, S> CipherSuite for TestCs<A, H, F, K, M, S>
where
    A: Aead + IndCca2,
    H: Hash<DigestSize = U64>,
    F: Kdf,
    K: Kem,
    M: Mac<KeySize = U64, TagSize = U64>,
    S: Signer,
{
    const ID: Id = Id::default();
    type Aead = A;
    type Hash = H;
    type Kdf = F;
    type Kem = K;
    type Mac = M;
    type Signer = S;
}
