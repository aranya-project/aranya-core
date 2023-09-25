//! Utilities for testing [`Engine`][crate::Engine],
//! [`CipherSuite`], and cryptography implementations.
//!
//! If you implement any traits in this crate it is **very
//! highly** recommended that you use these tests.

#![allow(clippy::panic)]
#![cfg(any(test, docs, feature = "test_util"))]
#![cfg_attr(docs, doc(cfg(feature = "test_util")))]
#![forbid(unsafe_code)]

use {
    crate::{
        aead::{Aead, AeadError, AeadId, Lifetime},
        ciphersuite::CipherSuite,
        csprng::Csprng,
        hash::Hash,
        import::{ExportError, Import, ImportError},
        kdf::{Kdf, KdfError, KdfId},
        kem::Kem,
        keys::{PublicKey, SecretKey},
        mac::{Mac, MacId, MacKey, Tag},
        signer::{Signature, Signer, SignerError, SignerId, SigningKey, VerifyingKey},
    },
    core::{
        fmt::{self, Debug},
        marker::PhantomData,
    },
    subtle::{Choice, ConstantTimeEq},
    zeroize::ZeroizeOnDrop,
};

macro_rules! msg {
    ($id:expr) => {
        &$id.to_string()
    };
    ($($arg:tt)*) => {
        &format!($($arg)*)
    };
}

/// Like `assert_eq`, but for `Choice`.
#[macro_export]
macro_rules! assert_ct_eq {
    ($lhs:expr, $rhs:expr) => {
        assert!(bool::from(::subtle::ConstantTimeEq::ct_eq(&$lhs, &$rhs)))
    };
    ($lhs:expr, $rhs:expr, ) => {
        $crate::assert_ct_eq!($lhs, $rhs)
    };
    ($lhs:expr, $rhs:expr, $($args:tt)+) => {
        assert!(bool::from(::subtle::ConstantTimeEq::ct_eq(&$lhs, &$rhs)), $($args)+)
    };
}

/// Like `assert_ne`, but for `Choice`.
#[macro_export]
macro_rules! assert_ct_ne {
    ($lhs:expr, $rhs:expr) => {
        assert!(bool::from(::subtle::ConstantTimeEq::ct_ne(&$lhs, &$rhs)))
    };
    ($lhs:expr, $rhs:expr, ) => {
        $crate::assert_ct_ne!($lhs, $rhs)
    };
    ($lhs:expr, $rhs:expr, $($args:tt)+) => {
        assert!(bool::from(::subtle::ConstantTimeEq::ct_ne(&$lhs, &$rhs)), $($args)+)
    };
}

/// Checks that each byte in `data` is zero.
macro_rules! assert_all_zero {
    ($data:expr) => {
        for c in $data.borrow() {
            assert_eq!(*c, 0, "Default must return all zeros");
        }
    };
}

/// A [`Aead`] that that uses the default trait methods.
pub struct AeadWithDefaults<T: Aead>(T);

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
    type Nonce = T::Nonce;

    fn new(key: &Self::Key) -> Self {
        Self(T::new(key))
    }

    fn seal_in_place(
        &self,
        nonce: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
        additional_data: &[u8],
    ) -> Result<(), AeadError> {
        self.0.seal_in_place(nonce, data, tag, additional_data)
    }

    fn open_in_place(
        &self,
        nonce: &[u8],
        data: &mut [u8],
        tag: &[u8],
        additional_data: &[u8],
    ) -> Result<(), AeadError> {
        self.0.open_in_place(nonce, data, tag, additional_data)
    }
}

/// A [`Kdf`] that that uses the default trait methods.
pub struct KdfWithDefaults<T: Kdf>(PhantomData<T>);

impl<T: Kdf> Kdf for KdfWithDefaults<T> {
    const ID: KdfId = T::ID;

    const MAX_OUTPUT: usize = T::MAX_OUTPUT;

    const PRK_SIZE: usize = T::PRK_SIZE;

    type Prk = T::Prk;

    fn extract_multi(ikm: &[&[u8]], salt: &[u8]) -> Self::Prk {
        T::extract_multi(ikm, salt)
    }

    fn expand_multi(out: &mut [u8], prk: &Self::Prk, info: &[&[u8]]) -> Result<(), KdfError> {
        T::expand_multi(out, prk, info)
    }
}

/// A [`Mac`] that that uses the default trait methods.
#[derive(Clone)]
pub struct MacWithDefaults<T: Mac>(T);

impl<T: Mac> Mac for MacWithDefaults<T> {
    const ID: MacId = T::ID;

    type Key = T::Key;
    type Tag = T::Tag;

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
pub struct SignerWithDefaults<T: Signer + ?Sized>(T);

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

    fn public(&self) -> VerifyingKeyWithDefaults<T> {
        VerifyingKeyWithDefaults(self.0.public())
    }
}

impl<T: Signer + ?Sized> SecretKey for SigningKeyWithDefaults<T> {
    fn new<R: Csprng>(rng: &mut R) -> Self {
        Self(T::SigningKey::new(rng))
    }

    type Data = <T::SigningKey as SecretKey>::Data;

    fn try_export_secret(&self) -> Result<Self::Data, ExportError> {
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
    A: Aead,
    H: Hash<Digest = [u8; 64]>,
    F: Kdf,
    K: Kem,
    M: Mac<Key = MacKey<64>, Tag = Tag<64>>,
    S: Signer,
>(PhantomData<(A, H, F, K, M, S)>);

impl<A, H, F, K, M, S> CipherSuite for TestCs<A, H, F, K, M, S>
where
    A: Aead,
    H: Hash<Digest = [u8; 64]>,
    F: Kdf,
    K: Kem,
    M: Mac<Key = MacKey<64>, Tag = Tag<64>>,
    S: Signer,
{
    type Aead = A;
    type Hash = H;
    type Kdf = F;
    type Kem = K;
    type Mac = M;
    type Signer = S;
}

/// Performs all of the tests inside the `engine` module.
///
/// This macro expands into a bunch of individual `#[test]`
/// functions.
///
/// It also performs [`test_ciphersuite`].
///
/// # Example
///
/// ```
/// use crypto::{test_engine, DefaultCipherSuite, DefaultEngine, Rng};
///
/// test_engine!(default_engine, || -> DefaultEngine<_, _> {
///     let (eng, _) = DefaultEngine::<_, DefaultCipherSuite>::from_entropy(Rng);
///     eng
/// });
/// ```
#[macro_export]
macro_rules! test_engine {
    ($name:ident, || -> $engine:ty { $($args:tt)+ }) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            $crate::test_util::test_ciphersuite!(ciphersuite, $engine);

            macro_rules! test {
                ($test:ident) => {
                    #[test]
                    fn $test() {
                        $crate::test_util::engine::$test(&mut { $($args)+ });
                    }
                };
            }

            mod aranya {
                #[allow(unused_imports)]
                use super::*;

                test!(test_simple_user_signing_key_sign);

                test!(test_simple_seal_group_key);
                test!(test_simple_wrap_group_key);
                test!(test_simple_wrap_user_identity_key);
                test!(test_simple_export_user_identity_key);
                test!(test_simple_identity_key_sign);
                test!(test_simple_wrap_user_signing_key);
                test!(test_simple_export_user_signing_key);
                test!(test_simple_wrap_user_encryption_key);
                test!(test_simple_export_user_encryption_key);

                test!(test_group_key_seal);
                test!(test_group_key_open_wrong_key);
                test!(test_group_key_open_wrong_context);
                test!(test_group_key_open_bad_ciphertext);

                test!(test_encrypted_group_key_encode);
            }
            pub use aranya::*;

            mod apq {
                #[allow(unused_imports)]
                use super::*;

                test!(test_simple_sender_signing_key_sign);

                test!(test_simple_seal_topic_key);
                test!(test_simple_wrap_user_sender_secret_key);
                test!(test_simple_wrap_user_sender_signing_key);
                test!(test_simple_wrap_user_receiver_secret_key);

                test!(test_topic_key_seal);
                test!(test_topic_key_open_wrong_key);
                test!(test_topic_key_open_wrong_context);
                test!(test_topic_key_open_bad_ciphertext);
            }
            pub use apq::*;

            mod aps {
                #[allow(unused_imports)]
                use super::*;

                test!(test_derive_channel_keys);
                test!(test_derive_channel_keys_different_labels);
                test!(test_derive_channel_keys_different_user_ids);
                test!(test_derive_channel_keys_different_cmd_ids);
                test!(test_derive_channel_keys_different_seeds);
                test!(test_derive_channel_keys_same_user_id);
                test!(test_simple_seal_channel_seed);
                test!(test_simple_wrap_channel_seed);
                test!(test_encrypted_channel_seed_encode);
            }
            pub use aps::*;
        }
    };
}
pub use test_engine;

/// [`Engine`][crate::Engine] tests.
pub mod engine {
    extern crate alloc;

    use {
        crate::{
            aead::{Aead, AeadError},
            apq::{
                EncryptedTopicKey, ReceiverSecretKey, Sender, SenderSecretKey, SenderSigningKey,
                Topic, TopicKey, Version,
            },
            aps::{ChannelSeed, EncryptedChannelSeed},
            aranya::{
                Encap, EncryptedGroupKey, EncryptionKey, IdentityKey, SigningKey as UserSigningKey,
            },
            engine::{Engine, WrappedKey},
            error::Error,
            groupkey::{Context, GroupKey},
            id::Id,
        },
        alloc::vec,
        core::{borrow::Borrow, ops::Add},
        generic_array::ArrayLength,
        typenum::{Sum, U64},
    };

    /// Simple test for [`UserSigningKey`].
    pub fn test_simple_user_signing_key_sign<E: Engine + ?Sized>(eng: &mut E) {
        const MSG: &[u8] = b"hello, world!";
        const CONTEXT: &str = "test_simple_user_signing_key_sign";

        let sign_key = UserSigningKey::<E>::new(eng);

        let sig = sign_key
            .sign(MSG, CONTEXT)
            .expect("unable to create signature");

        sign_key
            .public()
            .verify(MSG, CONTEXT, &sig)
            .expect("the signature should be valid");

        sign_key
            .public()
            .verify(MSG, "wrong context", &sig)
            .expect_err("should fail with wrong context");

        let wrong_sig = sign_key
            .sign(b"different", "signature")
            .expect("should not fail to create signature");

        sign_key
            .public()
            .verify(MSG, CONTEXT, &wrong_sig)
            .expect_err("should fail with wrong signature");
    }

    /// Simple positive test for encrypting/decrypting
    /// [`GroupKey`]s.
    pub fn test_simple_seal_group_key<E: Engine + ?Sized>(eng: &mut E)
    where
        <E::Aead as Aead>::Overhead: Add<U64>,
        Sum<<E::Aead as Aead>::Overhead, U64>: ArrayLength,
    {
        let enc_key = EncryptionKey::<E>::new(eng);

        let group = Id::default();
        let want = GroupKey::new(eng);
        let (enc, ciphertext) = enc_key
            .public()
            .seal_group_key(eng, &want, group)
            .expect("unable to encrypt `GroupKey`");
        let got = enc_key
            .open_group_key(&enc, &ciphertext, group)
            .expect("unable to decrypt `GroupKey`");
        assert_eq!(want.id(), got.id());
    }

    /// Simple positive test for wrapping [`GroupKey`]s.
    pub fn test_simple_wrap_group_key<E: Engine + ?Sized>(eng: &mut E) {
        let want = GroupKey::new(eng);
        let bytes = eng
            .wrap(&want)
            .expect("should be able to wrap `GroupKey`")
            .encode()
            .expect("should be able to encode wrapped `GroupKey`");
        let wrapped = E::WrappedKey::decode(bytes.borrow())
            .expect("should be able to decode encoded wrapped `GroupKey`");
        let got: GroupKey<E> = eng
            .unwrap(&wrapped)
            .expect("should be able to unwrap `GroupKey`")
            .try_into()
            .expect("should be a `GroupKey`");
        assert_eq!(want.id(), got.id());
    }

    /// Simple positive test for wrapping [`IdentityKey`]s.
    pub fn test_simple_wrap_user_identity_key<E: Engine + ?Sized>(eng: &mut E) {
        let want = IdentityKey::new(eng);
        let bytes = eng
            .wrap(&want)
            .expect("should be able to wrap `IdentityKey`")
            .encode()
            .expect("should be able to encode wrapped `IdentityKey`");
        let wrapped = E::WrappedKey::decode(bytes.borrow())
            .expect("should be able to decode encoded wrapped `IdentityKey`");
        let got: IdentityKey<E> = eng
            .unwrap(&wrapped)
            .expect("should be able to unwrap `IdentityKey`")
            .try_into()
            .expect("should be a `IdentityKey`");
        assert_eq!(want.id(), got.id());
    }

    /// Simple positive test for exporting the public half of
    /// [`IdentityKey`]s.
    pub fn test_simple_export_user_identity_key<E: Engine + ?Sized>(eng: &mut E) {
        let want = IdentityKey::<E>::new(eng).public();
        let bytes = postcard::to_allocvec(&want)
            .expect("should be able to encode an `IdentityVerifyingKey`");
        let got = postcard::from_bytes(&bytes)
            .expect("should be able to decode an `IdentityVerifyingKey`");
        assert_eq!(want, got);
    }

    /// Simple test for [`IdentityKey`].
    /// Creates a signature over `msg` bound to some `context`.
    /// `msg` must NOT be pre-hashed.
    pub fn test_simple_identity_key_sign<E: Engine + ?Sized>(eng: &mut E) {
        let sign_key = IdentityKey::<E>::new(eng);

        const MESSAGE: &[u8] = b"hello, world!";
        const CONTEXT: &str = "test_simple_identity_key_sign";

        let sig = sign_key
            .sign(MESSAGE, CONTEXT)
            .expect("should not fail to create signature");

        sign_key
            .public()
            .verify(MESSAGE, CONTEXT, &sig)
            .expect("should not fail with correct signature");

        sign_key
            .public()
            .verify(MESSAGE, "wrong context", &sig)
            .expect_err("should fail with wrong context");

        let wrong_sig = sign_key
            .sign(b"different", "signature")
            .expect("should not fail to create signature");

        sign_key
            .public()
            .verify(MESSAGE, CONTEXT, &wrong_sig)
            .expect_err("should fail with wrong signature");
    }

    /// Simple positive test for wrapping [`UserSigningKey`]s.
    pub fn test_simple_wrap_user_signing_key<E: Engine + ?Sized>(eng: &mut E) {
        let want = UserSigningKey::new(eng);
        let bytes = eng
            .wrap(&want)
            .expect("should be able to wrap `UserSigningKey`")
            .encode()
            .expect("should be able to encode wrapped `UserSigningKey`");
        let wrapped = E::WrappedKey::decode(bytes.borrow())
            .expect("should be able to decode encoded wrapped `UserSigningKey`");
        let got: UserSigningKey<E> = eng
            .unwrap(&wrapped)
            .expect("should be able to unwrap `UserSigningKey`")
            .try_into()
            .expect("should be a `UserSigningKey`");
        assert_eq!(want.id(), got.id());
    }

    /// Simple positive test for exporting the public half of
    /// [`UserSigningKey`]s.
    pub fn test_simple_export_user_signing_key<E: Engine + ?Sized>(eng: &mut E) {
        let want = UserSigningKey::<E>::new(eng).public();
        let bytes =
            postcard::to_allocvec(&want).expect("should be able to encode an `VerifyingKey`");
        let got = postcard::from_bytes(&bytes).expect("should be able to decode an `VerifyingKey`");
        assert_eq!(want, got);
    }

    /// Simple positive test for wrapping [`EncryptionKey`]s.
    pub fn test_simple_wrap_user_encryption_key<E: Engine + ?Sized>(eng: &mut E) {
        let want = EncryptionKey::new(eng);
        let bytes = eng
            .wrap(&want)
            .expect("should be able to wrap `EncryptionKey`")
            .encode()
            .expect("should be able to encode wrapped `EncryptionKey`");
        let wrapped = E::WrappedKey::decode(bytes.borrow())
            .expect("should be able to decode encoded wrapped `EncryptionKey`");
        let got: EncryptionKey<E> = eng
            .unwrap(&wrapped)
            .expect("should be able to unwrap `EncryptionKey`")
            .try_into()
            .expect("should be a `EncryptionKey`");
        assert_eq!(want.id(), got.id());
    }

    /// Simple positive test for exporting the public half of
    /// [`EncryptionKey`]s.
    pub fn test_simple_export_user_encryption_key<E: Engine + ?Sized>(eng: &mut E) {
        let want = EncryptionKey::<E>::new(eng).public();
        let bytes = postcard::to_allocvec(&want)
            .expect("should be able to encode an `EncryptionPublicKey`");
        let got = postcard::from_bytes(&bytes)
            .expect("should be able to decode an `EncryptionPublicKey`");
        assert_eq!(want, got);
    }

    /// Simple positive test for encryption using a [`GroupKey`].
    pub fn test_group_key_seal<E: Engine + ?Sized>(eng: &mut E) {
        const INPUT: &[u8] = b"hello, world!";

        let author = UserSigningKey::<E>::new(eng).public();

        let gk = GroupKey::new(eng);
        let ciphertext = {
            let mut dst = vec![0u8; INPUT.len() + gk.overhead()];
            gk.seal(
                eng,
                &mut dst,
                INPUT,
                Context {
                    label: "test_group_key_seal",
                    parent: Id::default(),
                    author: &author,
                },
            )
            .expect("should succeed");
            dst
        };
        let plaintext = {
            let mut dst = vec![0u8; ciphertext.len() - gk.overhead()];
            gk.open(
                &mut dst,
                &ciphertext,
                Context {
                    label: "test_group_key_seal",
                    parent: Id::default(),
                    author: &author,
                },
            )
            .expect("should succeed");
            dst
        };
        assert_eq!(&plaintext, INPUT);
    }

    /// Negative test for the wrong [`GroupKey`].
    pub fn test_group_key_open_wrong_key<E: Engine + ?Sized>(eng: &mut E) {
        const INPUT: &[u8] = b"hello, world!";

        let author = UserSigningKey::<E>::new(eng).public();

        let gk1 = GroupKey::new(eng);
        let gk2 = GroupKey::new(eng);

        let ciphertext = {
            let mut dst = vec![0u8; INPUT.len() + gk1.overhead()];
            gk1.seal(
                eng,
                &mut dst,
                INPUT,
                Context {
                    label: "some label",
                    parent: Id::default(),
                    author: &author,
                },
            )
            .expect("should succeed");
            dst
        };
        let mut dst = vec![0u8; ciphertext.len() - gk2.overhead()];
        let err = gk2
            .open(
                &mut dst,
                &ciphertext,
                Context {
                    label: "some label",
                    parent: Id::default(),
                    author: &author,
                },
            )
            .expect_err("should have failed");
        assert_eq!(err, Error::Aead(AeadError::Authentication));
    }

    /// Negative test for the wrong [`Context`].
    pub fn test_group_key_open_wrong_context<E: Engine + ?Sized>(eng: &mut E) {
        const INPUT: &[u8] = b"hello, world!";

        let author1 = UserSigningKey::<E>::new(eng).public();
        let author2 = UserSigningKey::<E>::new(eng).public();

        let gk = GroupKey::new(eng);
        let ciphertext = {
            let mut dst = vec![0u8; INPUT.len() + gk.overhead()];
            gk.seal(
                eng,
                &mut dst,
                INPUT,
                Context {
                    label: "some label",
                    parent: Id::default(),
                    author: &author1,
                },
            )
            .expect("should succeed");
            dst
        };

        macro_rules! should_fail {
            ($msg:expr, $ctx:expr) => {
                let mut dst = vec![0u8; ciphertext.len() - gk.overhead()];
                let err = gk
                    .open(&mut dst, &ciphertext, $ctx)
                    .expect_err("should have failed");
                assert_eq!(err, Error::Aead(AeadError::Authentication), $msg);
            };
        }
        should_fail!(
            "wrong label",
            Context {
                label: "wrong label",
                parent: Id::default(),
                author: &author1,
            }
        );
        should_fail!(
            "wrong `parent`",
            Context {
                label: "some label",
                parent: [1u8; 64].into(),
                author: &author1,
            }
        );
        should_fail!(
            "wrong `author`",
            Context {
                label: "some label",
                parent: Id::default(),
                author: &author2,
            }
        );
    }

    /// Negative test for a modified ciphertext.
    pub fn test_group_key_open_bad_ciphertext<E: Engine + ?Sized>(eng: &mut E) {
        const INPUT: &[u8] = b"hello, world!";

        let author = UserSigningKey::<E>::new(eng).public();

        let gk = GroupKey::new(eng);
        let mut ciphertext = {
            let mut dst = vec![0u8; INPUT.len() + gk.overhead()];
            gk.seal(
                eng,
                &mut dst,
                INPUT,
                Context {
                    label: "some label",
                    parent: Id::default(),
                    author: &author,
                },
            )
            .expect("should succeed");
            dst
        };

        ciphertext[0] = ciphertext[0].wrapping_add(1);

        let mut dst = vec![0u8; ciphertext.len() - gk.overhead()];
        let err = gk
            .open(
                &mut dst,
                &ciphertext,
                Context {
                    label: "some label",
                    parent: Id::default(),
                    author: &author,
                },
            )
            .expect_err("should have failed");
        assert_eq!(err, Error::Aead(AeadError::Authentication));
    }

    /// Test encoding/decoding [`EncryptedGroupKey`].
    pub fn test_encrypted_group_key_encode<E: Engine + ?Sized>(eng: &mut E)
    where
        <E::Aead as Aead>::Overhead: Add<U64>,
        Sum<<E::Aead as Aead>::Overhead, U64>: ArrayLength,
    {
        let enc_key = EncryptionKey::<E>::new(eng);

        let group = Id::default();
        let want = GroupKey::new(eng);
        let (enc, ciphertext) = enc_key
            .public()
            .seal_group_key(eng, &want, group)
            .expect("unable to encrypt `GroupKey`");
        let enc = Encap::<E>::from_bytes(enc.as_bytes()).expect("should be able to decode `Encap`");
        let ciphertext = EncryptedGroupKey::<E>::from_bytes(ciphertext.as_bytes())
            .expect("should be able to decode `EncryptedGroupKey`");
        let got = enc_key
            .open_group_key(&enc, &ciphertext, group)
            .expect("unable to decrypt `GroupKey`");
        assert_eq!(want.id(), got.id());
    }

    /// Simple test for [`SenderSigningKey`].
    /// Creates a signature over an encoded record.
    pub fn test_simple_sender_signing_key_sign<E: Engine + ?Sized>(eng: &mut E)
    where
        <E::Aead as Aead>::Overhead: Add<U64>,
        Sum<<E::Aead as Aead>::Overhead, U64>: ArrayLength,
    {
        const RECORD: &[u8] = b"some encoded record";

        const VERSION: Version = Version::new(1);
        let topic = Topic::new("SomeTopic");

        let sign_key = SenderSigningKey::<E>::new(eng);
        let sig = sign_key
            .sign(VERSION, &topic, RECORD)
            .expect("unable to create signature");

        sign_key
            .public()
            .verify(VERSION, &topic, RECORD, &sig)
            .expect("the signature should be valid");

        sign_key
            .public()
            .verify(Version::new(VERSION.as_u32() + 1), &topic, RECORD, &sig)
            .expect_err("should fail: wrong version");

        sign_key
            .public()
            .verify(VERSION, &Topic::new("WrongTopic"), RECORD, &sig)
            .expect_err("should fail: wrong topic");

        sign_key
            .public()
            .verify(VERSION, &topic, b"wrong", &sig)
            .expect_err("should fail: wrong record");

        let wrong_sig = sign_key
            .sign(
                Version::new(VERSION.as_u32() + 1),
                &Topic::new("AnotherTopic"),
                b"encoded record",
            )
            .expect("should not fail to create signature");

        sign_key
            .public()
            .verify(VERSION, &topic, RECORD, &wrong_sig)
            .expect_err("should fail: wrong signature");
    }

    /// Simple positive test for encrypting/decrypting
    /// [`TopicKey`]s.
    pub fn test_simple_seal_topic_key<E: Engine + ?Sized>(eng: &mut E)
    where
        <E::Aead as Aead>::Overhead: Add<U64>,
        Sum<<E::Aead as Aead>::Overhead, U64>: ArrayLength,
    {
        let send_sk = SenderSecretKey::<E>::new(eng);
        let send_pk = send_sk.public();
        let recv_sk = ReceiverSecretKey::<E>::new(eng);
        let recv_pk = recv_sk.public();

        const VERSION: Version = Version::new(1);
        let topic = Topic::new("SomeTopic");

        let want = TopicKey::new(eng, VERSION, &topic).expect("unable to create new `TopicKey`");
        let (enc, ciphertext) = recv_pk
            .seal_topic_key(eng, VERSION, &topic, &send_sk, &want)
            .expect("unable to encrypt `TopicKey`");
        let enc = Encap::<E>::from_bytes(enc.as_bytes()).expect("should be able to decode `Encap`");
        let ciphertext = EncryptedTopicKey::<E>::from_bytes(ciphertext.as_bytes())
            .expect("should be able to decode `EncryptedTopicKey`");
        let got = recv_sk
            .open_topic_key(VERSION, &topic, &send_pk, &enc, &ciphertext)
            .expect("unable to decrypt `TopicKey`");
        assert_eq!(want.id(), got.id());
    }

    /// Simple positive test for wrapping [`SenderSecretKey`]s.
    pub fn test_simple_wrap_user_sender_secret_key<E: Engine + ?Sized>(eng: &mut E) {
        let want = SenderSecretKey::new(eng);
        let bytes = eng
            .wrap(&want)
            .expect("should be able to wrap `SenderSecretKey`")
            .encode()
            .expect("should be able to encode wrapped `SenderSecretKey`");
        let wrapped = E::WrappedKey::decode(bytes.borrow())
            .expect("should be able to decode encoded wrapped `SenderSecretKey`");
        let got: SenderSecretKey<E> = eng
            .unwrap(&wrapped)
            .expect("should be able to unwrap `SenderSecretKey`")
            .try_into()
            .expect("should be a `SenderSecretKey`");
        assert_eq!(want.id(), got.id());
    }

    /// Simple positive test for wrapping [`SenderSigningKey`]s.
    pub fn test_simple_wrap_user_sender_signing_key<E: Engine + ?Sized>(eng: &mut E) {
        let want = SenderSigningKey::new(eng);
        let bytes = eng
            .wrap(&want)
            .expect("should be able to wrap `SenderSigningKey`")
            .encode()
            .expect("should be able to encode wrapped `SenderSigningKey`");
        let wrapped = E::WrappedKey::decode(bytes.borrow())
            .expect("should be able to decode encoded wrapped `SenderSigningKey`");
        let got: SenderSigningKey<E> = eng
            .unwrap(&wrapped)
            .expect("should be able to unwrap `SenderSigningKey`")
            .try_into()
            .expect("should be a `SenderSigningKey`");
        assert_eq!(want.id(), got.id());
    }

    /// Simple positive test for wrapping [`ReceiverSecretKey`]s.
    pub fn test_simple_wrap_user_receiver_secret_key<E: Engine + ?Sized>(eng: &mut E) {
        let want = ReceiverSecretKey::new(eng);
        let bytes = eng
            .wrap(&want)
            .expect("should be able to wrap `ReceiverSecretKey`")
            .encode()
            .expect("should be able to encode wrapped `ReceiverSecretKey`");
        let wrapped = E::WrappedKey::decode(bytes.borrow())
            .expect("should be able to decode encoded wrapped `ReceiverSecretKey`");
        let got: ReceiverSecretKey<E> = eng
            .unwrap(&wrapped)
            .expect("should be able to unwrap `ReceiverSecretKey`")
            .try_into()
            .expect("should be a `ReceiverSecretKey`");
        assert_eq!(want.id(), got.id());
    }

    /// Simple positive test for encryption using a [`TopicKey`].
    pub fn test_topic_key_seal<E: Engine + ?Sized>(eng: &mut E) {
        const INPUT: &[u8] = b"hello, world!";

        let ident = Sender {
            enc_key: &SenderSecretKey::<E>::new(eng).public(),
            sign_key: &SenderSigningKey::<E>::new(eng).public(),
        };

        const VERSION: Version = Version::new(1);
        let topic = Topic::new("SomeTopic");

        let tk = TopicKey::new(eng, VERSION, &topic).expect("unable to create new `TopicKey`");
        let ciphertext = {
            let mut dst = vec![0u8; INPUT.len() + tk.overhead()];
            tk.seal_message(eng, &mut dst, INPUT, VERSION, &topic, &ident)
                .expect("should succeed");
            dst
        };
        let plaintext = {
            let mut dst = vec![0u8; ciphertext.len() - tk.overhead()];
            tk.open_message(&mut dst, &ciphertext, VERSION, &topic, &ident)
                .expect("should succeed");
            dst
        };
        assert_eq!(&plaintext, INPUT);
    }

    /// Negative test for the wrong [`TopicKey`].
    pub fn test_topic_key_open_wrong_key<E: Engine + ?Sized>(eng: &mut E) {
        const INPUT: &[u8] = b"hello, world!";

        let ident = Sender {
            enc_key: &SenderSecretKey::<E>::new(eng).public(),
            sign_key: &SenderSigningKey::<E>::new(eng).public(),
        };

        const VERSION: Version = Version::new(1);
        let topic = Topic::new("SomeTopic");

        let tk1 = TopicKey::new(eng, VERSION, &topic).expect("unable to create new `TopicKey`");
        let tk2 = TopicKey::new(eng, VERSION, &topic).expect("unable to create new `TopicKey`");

        let ciphertext = {
            let mut dst = vec![0u8; INPUT.len() + tk1.overhead()];
            tk1.seal_message(eng, &mut dst, INPUT, VERSION, &topic, &ident)
                .expect("should succeed");
            dst
        };
        let mut dst = vec![0u8; ciphertext.len() - tk2.overhead()];
        let err = tk2
            .open_message(&mut dst, &ciphertext, VERSION, &topic, &ident)
            .expect_err("should have failed");
        assert_eq!(err, Error::Aead(AeadError::Authentication));
    }

    /// Negative test for the wrong [`Context`].
    pub fn test_topic_key_open_wrong_context<E: Engine + ?Sized>(eng: &mut E) {
        const INPUT: &[u8] = b"hello, world!";

        let ident = Sender {
            enc_key: &SenderSecretKey::<E>::new(eng).public(),
            sign_key: &SenderSigningKey::<E>::new(eng).public(),
        };
        let wrong_ident = Sender {
            enc_key: &SenderSecretKey::<E>::new(eng).public(),
            sign_key: &SenderSigningKey::<E>::new(eng).public(),
        };

        const VERSION: Version = Version::new(1);
        let topic = Topic::new("SomeTopic");

        let tk = TopicKey::new(eng, VERSION, &topic).expect("unable to create `TopicKey`");
        let ciphertext = {
            let mut dst = vec![0u8; INPUT.len() + tk.overhead()];
            tk.seal_message(eng, &mut dst, INPUT, VERSION, &topic, &ident)
                .expect("should succeed");
            dst
        };

        macro_rules! should_fail {
            ($msg:expr, $version:expr, $topic:expr, $ident:expr) => {
                let mut dst = vec![0u8; ciphertext.len() - tk.overhead()];
                let err = tk
                    .open_message(&mut dst, &ciphertext, $version, $topic, $ident)
                    .expect_err("should have failed");
                assert_eq!(err, Error::Aead(AeadError::Authentication), $msg);
            };
        }
        should_fail!(
            "wrong version",
            Version::new(VERSION.as_u32() + 1),
            &topic,
            &ident
        );
        should_fail!("wrong topic", VERSION, &Topic::new("WrongTopic"), &ident);
        should_fail!("wrong ident", VERSION, &topic, &wrong_ident);
    }

    /// Negative test for a modified ciphertext.
    pub fn test_topic_key_open_bad_ciphertext<E: Engine + ?Sized>(eng: &mut E) {
        const INPUT: &[u8] = b"hello, world!";

        let ident = Sender {
            enc_key: &SenderSecretKey::<E>::new(eng).public(),
            sign_key: &SenderSigningKey::<E>::new(eng).public(),
        };

        const VERSION: Version = Version::new(1);
        let topic = Topic::new("SomeTopic");

        let tk = TopicKey::new(eng, VERSION, &topic).expect("unable to create `TopicKey`");
        let mut ciphertext = {
            let mut dst = vec![0u8; INPUT.len() + tk.overhead()];
            tk.seal_message(eng, &mut dst, INPUT, VERSION, &topic, &ident)
                .expect("should succeed");
            dst
        };

        ciphertext[0] = ciphertext[0].wrapping_add(1);

        let mut dst = vec![0u8; ciphertext.len() - tk.overhead()];
        let err = tk
            .open_message(&mut dst, &ciphertext, VERSION, &topic, &ident)
            .expect_err("should have failed");
        assert_eq!(err, Error::Aead(AeadError::Authentication));
    }

    /// A simple positive test for deriving
    /// [`ChannelKeys`][crate::aps::ChannelKeys].
    pub fn test_derive_channel_keys<E: Engine + ?Sized>(eng: &mut E) {
        let user1 = IdentityKey::<E>::new(eng).id();
        let user2 = IdentityKey::<E>::new(eng).id();
        let cmd_id = Id::random(eng);

        let label = 123;
        let seed = ChannelSeed::new(eng);
        let ck1 = seed
            .derive_keys(label, &user1, &user2, &cmd_id)
            .expect("unable to derive `ChannelKeys`");
        let ck2 = seed
            .derive_keys(label, &user2, &user1, &cmd_id)
            .expect("unable to derive `ChannelKeys`");

        // `ck1` and `ck2` should be the reverse of each other.
        assert_eq!(ck1.seal_key(), ck2.open_key());
        assert_eq!(ck1.open_key(), ck2.seal_key());

        // We should not generate duplicate keys.
        assert_ne!(ck1.seal_key(), ck2.seal_key());
        assert_ne!(ck1.open_key(), ck2.open_key());
    }

    /// Different labels should create different
    /// [`ChannelKeys`][crate::aps::ChannelKeys].
    pub fn test_derive_channel_keys_different_labels<E: Engine + ?Sized>(eng: &mut E) {
        let user1 = IdentityKey::<E>::new(eng).id();
        let user2 = IdentityKey::<E>::new(eng).id();
        let cmd_id = Id::random(eng);

        let label1 = 123;
        let label2 = 456;

        let seed = ChannelSeed::new(eng);
        let ck1 = seed
            .derive_keys(label1, &user1, &user2, &cmd_id)
            .expect("unable to derive `ChannelKeys`");
        let ck2 = seed
            .derive_keys(label2, &user1, &user2, &cmd_id)
            .expect("unable to derive `ChannelKeys`");

        // The labels are different, so the keys should also be
        // different.
        assert_ne!(ck1.seal_key(), ck2.open_key());
        assert_ne!(ck1.open_key(), ck2.seal_key());
        assert_ne!(ck1.seal_key(), ck2.seal_key());
        assert_ne!(ck1.open_key(), ck2.open_key());

        // Also check the case where user2 derives the keys.
        let ck2 = seed
            .derive_keys(label2, &user2, &user1, &cmd_id)
            .expect("unable to derive `ChannelKeys`");

        assert_ne!(ck1.seal_key(), ck2.open_key());
        assert_ne!(ck1.open_key(), ck2.seal_key());
        assert_ne!(ck1.seal_key(), ck2.seal_key());
        assert_ne!(ck1.open_key(), ck2.open_key());
    }

    /// Different UserIDs should create different
    /// [`ChannelKeys`][crate::aps::ChannelKeys].
    ///
    /// E.g., derive(label, u1, u2, c1) != derive(label, u2, u3, c1).
    pub fn test_derive_channel_keys_different_user_ids<E: Engine + ?Sized>(eng: &mut E) {
        let user1 = IdentityKey::<E>::new(eng).id();
        let user2 = IdentityKey::<E>::new(eng).id();
        let user3 = IdentityKey::<E>::new(eng).id();
        let cmd_id = Id::random(eng);

        let label = 123;
        let seed = ChannelSeed::new(eng);
        let ck1 = seed
            .derive_keys(label, &user1, &user2, &cmd_id)
            .expect("unable to derive `ChannelKeys`");
        let ck2 = seed
            .derive_keys(label, &user2, &user3, &cmd_id)
            .expect("unable to derive `ChannelKeys`");

        // User2 used a different peer ID, so the keys should be
        // different.
        assert_ne!(ck1.seal_key(), ck2.open_key());
        assert_ne!(ck1.open_key(), ck2.seal_key());
        assert_ne!(ck1.seal_key(), ck2.seal_key());
        assert_ne!(ck1.open_key(), ck2.open_key());

        // Check both (u2, u3) and (u3, u2).
        let ck2 = seed
            .derive_keys(label, &user3, &user2, &cmd_id)
            .expect("unable to derive `ChannelKeys`");

        assert_ne!(ck1.seal_key(), ck2.open_key());
        assert_ne!(ck1.open_key(), ck2.seal_key());
        assert_ne!(ck1.seal_key(), ck2.seal_key());
        assert_ne!(ck1.open_key(), ck2.open_key());
    }

    /// Different command IDs should create different
    /// [`ChannelKeys`][crate::aps::ChannelKeys].
    ///
    /// E.g., derive(label, u1, u2, c1) != derive(label, u2, u1, c2).
    pub fn test_derive_channel_keys_different_cmd_ids<E: Engine + ?Sized>(eng: &mut E) {
        let user1 = IdentityKey::<E>::new(eng).id();
        let user2 = IdentityKey::<E>::new(eng).id();
        let cmd_id1 = Id::random(eng);
        let cmd_id2 = Id::random(eng);

        let label = 123;
        let seed = ChannelSeed::new(eng);
        let ck1 = seed
            .derive_keys(label, &user1, &user2, &cmd_id1)
            .expect("unable to derive `ChannelKeys`");
        let ck2 = seed
            .derive_keys(label, &user2, &user1, &cmd_id2)
            .expect("unable to derive `ChannelKeys`");

        // The command IDs are different, so the keys should also
        // be different.
        assert_ne!(ck1.seal_key(), ck2.open_key());
        assert_ne!(ck1.open_key(), ck2.seal_key());
        assert_ne!(ck1.seal_key(), ck2.seal_key());
        assert_ne!(ck1.open_key(), ck2.open_key());
    }

    /// Different seeds should create different
    /// [`ChannelKeys`][crate::aps::ChannelKeys].
    ///
    /// E.g., derive(label, u1, u2, c1) != derive(label, u2, u1, c2).
    pub fn test_derive_channel_keys_different_seeds<E: Engine + ?Sized>(eng: &mut E) {
        let user1 = IdentityKey::<E>::new(eng).id();
        let user2 = IdentityKey::<E>::new(eng).id();
        let cmd_id = Id::random(eng);

        let label = 123;
        let seed1 = ChannelSeed::new(eng);
        let seed2 = ChannelSeed::new(eng);
        assert_ct_ne!(seed1, seed2);

        let ck1 = seed1
            .derive_keys(label, &user1, &user2, &cmd_id)
            .expect("unable to derive `ChannelKeys`");
        let ck2 = seed2
            .derive_keys(label, &user2, &user1, &cmd_id)
            .expect("unable to derive `ChannelKeys`");

        // The seeds are different, so the keys should also
        // be different.
        assert_ne!(ck1.seal_key(), ck2.open_key());
        assert_ne!(ck1.open_key(), ck2.seal_key());
        assert_ne!(ck1.seal_key(), ck2.seal_key());
        assert_ne!(ck1.open_key(), ck2.open_key());
    }

    /// It is an error to use the same `UserId` when deriving
    /// [`ChannelKeys`][crate::aps::ChannelKeys].
    pub fn test_derive_channel_keys_same_user_id<E: Engine + ?Sized>(eng: &mut E) {
        let user = IdentityKey::<E>::new(eng).id();
        let cmd_id = Id::random(eng);
        let err = ChannelSeed::new(eng)
            .derive_keys(123, &user, &user, &cmd_id)
            .err()
            .expect("unable to derive `ChannelKeys`");
        assert_eq!(err, Error::InvalidArgument("same `UserId`"))
    }

    /// Simple positive test for encrypting/decrypting
    /// [`ChannelSeed`]s.
    pub fn test_simple_seal_channel_seed<E: Engine + ?Sized>(eng: &mut E)
    where
        <E::Aead as Aead>::Overhead: Add<U64>,
        Sum<<E::Aead as Aead>::Overhead, U64>: ArrayLength,
    {
        let enc_key = EncryptionKey::<E>::new(eng);

        let label = 33;
        let want = ChannelSeed::new(eng);
        let (enc, ciphertext) = enc_key
            .public()
            .seal_channel_seed(eng, &want, label)
            .expect("unable to encrypt `ChannelSeed`");
        let got = enc_key
            .open_channel_seed(&enc, &ciphertext, label)
            .expect("unable to decrypt `ChannelSeed`");
        assert_eq!(want.id(), got.id());
    }

    /// Simple positive test for wrapping [`ChannelSeed`]s.
    pub fn test_simple_wrap_channel_seed<E: Engine + ?Sized>(eng: &mut E) {
        let want = ChannelSeed::new(eng);
        let bytes = eng
            .wrap(&want)
            .expect("should be able to wrap `ChannelSeed`")
            .encode()
            .expect("should be able to encode wrapped `ChannelSeed`");
        let wrapped = E::WrappedKey::decode(bytes.borrow())
            .expect("should be able to decode encoded wrapped `ChannelSeed`");
        let got: ChannelSeed<E> = eng
            .unwrap(&wrapped)
            .expect("should be able to unwrap `ChannelSeed`")
            .try_into()
            .expect("should be a `ChannelSeed`");
        assert_eq!(want.id(), got.id());
    }

    /// Test encoding/decoding [`EncryptedChannelSeed`].
    pub fn test_encrypted_channel_seed_encode<E: Engine + ?Sized>(eng: &mut E)
    where
        <E::Aead as Aead>::Overhead: Add<U64>,
        Sum<<E::Aead as Aead>::Overhead, U64>: ArrayLength,
    {
        let enc_key = EncryptionKey::<E>::new(eng);

        let label = 42;
        let want = ChannelSeed::new(eng);
        let (enc, ciphertext) = enc_key
            .public()
            .seal_channel_seed(eng, &want, label)
            .expect("unable to encrypt `ChannelSeed`");
        let enc = Encap::<E>::from_bytes(enc.as_bytes()).expect("should be able to decode `Encap`");
        let ciphertext = EncryptedChannelSeed::<E>::from_bytes(ciphertext.as_bytes())
            .expect("should be able to decode `EncryptedChannelSeed`");
        let got = enc_key
            .open_channel_seed(&enc, &ciphertext, label)
            .expect("unable to decrypt `ChannelSeed`");
        assert_eq!(want.id(), got.id());
    }
}

/// Tests a [`CipherSuite`].
///
/// It also performs all of the tests inside the `aead`, `hash`,
/// `hpke`, `kdf`, `mac`, and `signer` modules.
///
/// # Example
///
/// ```
/// use crypto::{test_ciphersuite, DefaultCipherSuite};
///
/// test_ciphersuite!(default_ciphersuite, DefaultCipherSuite);
/// ```
#[macro_export]
macro_rules! test_ciphersuite {
    ($name:ident, $cs:ty) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            $crate::test_aead!(aead, <$cs as $crate::CipherSuite>::Aead);
            $crate::test_aead!(
                aead_with_defaults,
                $crate::test_util::AeadWithDefaults<
                    <$cs as $crate::CipherSuite>::Aead,
                >
            );


            $crate::test_hash!(hash, <$cs as $crate::CipherSuite>::Hash);

            $crate::test_hpke!(hpke,
                <$cs as $crate::CipherSuite>::Kem,
                <$cs as $crate::CipherSuite>::Kdf,
                <$cs as $crate::CipherSuite>::Aead,
            );

            $crate::test_kdf!(kdf, <$cs as $crate::CipherSuite>::Kdf);
            $crate::test_kdf!(
                kdf_with_defaults,
                $crate::test_util::KdfWithDefaults<<$cs as $crate::CipherSuite>::Kdf>
            );

            $crate::test_mac!(mac, <$cs as $crate::CipherSuite>::Mac);
            $crate::test_mac!(
                mac_with_defaults,
                $crate::test_util::MacWithDefaults<<$cs as $crate::CipherSuite>::Mac>
            );

            $crate::test_signer!(signer, <$cs as $crate::CipherSuite>::Signer);
            $crate::test_signer!(
                signer_with_defaults,
                $crate::test_util::SignerWithDefaults<<$cs as $crate::CipherSuite>::Signer>
            );
        }
    };
}
pub use test_ciphersuite;

/// Performs all of the tests inside the `aead` module.
///
/// This macro expands into a bunch of individual `#[test]`
/// functions.
///
/// This is used by [`test_ciphersuite`], but can also be used
/// manually.
///
/// # Example
///
/// ```
/// use crypto::{test_aead, rust::Aes256Gcm};
///
/// // Without test vectors.
/// test_aead!(aes256gcm, Aes256Gcm);
///
/// // With test vectors.
/// test_aead!(aes256gcm_with_vecs, Aes256Gcm, AeadTest::AesGcm);
/// ```
#[macro_export]
macro_rules! test_aead {
    ($name:ident, $aead:ty $(, AeadTest::$vectors:ident)?) => {
        macro_rules! test {
            ($test:ident) => {
                #[test]
                fn $test() {
                    $crate::test_util::aead::$test::<$aead, _>(&mut $crate::Rng)
                }
            };
        }

        mod $name {
            #[allow(unused_imports)]
            use super::*;

            test!(test_basic);
            test!(test_new_key);
            test!(test_round_trip);
            test!(test_in_place_round_trip);
            test!(test_bad_key);
            test!(test_bad_nonce);
            test!(test_bad_ciphertext);
            test!(test_bad_ad);
            test!(test_bad_tag);

            // TODO(eric): add tests for boundaries. E.g., nonce is
            // too long, tag is too short, etc.

            $(
                #[test]
                fn vectors() {
                    $crate::test_util::vectors::test_aead::<$aead>(
                        $crate::test_util::vectors::AeadTest::$vectors,
                    );
                }
            )?
        }
    };
}
pub use test_aead;

/// [`Aead`] tests.
pub mod aead {
    extern crate alloc;

    use {
        crate::{
            aead::{Aead, AeadError},
            csprng::Csprng,
            keys::SecretKey,
        },
        alloc::vec,
        core::borrow::{Borrow, BorrowMut},
        more_asserts::assert_ge,
    };

    const GOLDEN: &[u8] = b"hello, world!";
    const AD: &[u8] = b"some additional data";

    /// Tests basic
    pub fn test_basic<A: Aead, R: Csprng>(_rng: &mut R) {
        // The minimum key size is 128 bits.
        assert_ge!(A::KEY_SIZE, 16);
        // Must be at least 2^32-1.
        assert_ge!(A::MAX_PLAINTEXT_SIZE, u64::from(u32::MAX));
        // Must be `OVERHEAD` bytes larger than the plaintext.
        assert_eq!(
            A::MAX_CIPHERTEXT_SIZE,
            A::MAX_PLAINTEXT_SIZE + A::OVERHEAD as u64
        );
        // Must be at least 2^32-1.
        assert_ge!(A::MAX_ADDITIONAL_DATA_SIZE, u64::from(u32::MAX));

        // The symmetric key data must be the same size as
        // specified by the `Aead`.
        let data = <A::Key as SecretKey>::Data::default();
        assert_eq!(
            A::KEY_SIZE,
            data.borrow().len(),
            "KEY_SIZE does not match Key::Data size"
        );
        assert_all_zero!(data);
    }

    /// Tests that `Aead::Key::new` returns unique keys.
    pub fn test_new_key<A: Aead, R: Csprng>(rng: &mut R) {
        let k1 = A::Key::new(rng);
        let k2 = A::Key::new(rng);
        assert_ct_ne!(k1, k2);
    }

    /// A round-trip positive test.
    pub fn test_round_trip<A: Aead, R: Csprng>(rng: &mut R) {
        let key = A::Key::new(rng);
        let nonce = A::Nonce::default();
        assert_all_zero!(nonce);

        let ciphertext = {
            let mut dst = vec![0u8; GOLDEN.len() + A::OVERHEAD];
            A::new(&key)
                .seal(&mut dst[..], nonce.borrow(), GOLDEN, AD)
                .expect("unable to encrypt data");
            dst
        };

        let plaintext = {
            let mut dst = vec![0u8; ciphertext.len() - A::OVERHEAD];
            A::new(&key)
                .open(&mut dst[..], nonce.borrow(), &ciphertext, AD)
                .expect("unable to decrypt data");
            dst
        };
        assert_eq!(&plaintext, GOLDEN, "round trip test failed");
    }

    /// An in-place round-trip positive test.
    pub fn test_in_place_round_trip<A: Aead, R: Csprng>(rng: &mut R) {
        let key = A::Key::new(rng);
        let nonce = A::Nonce::default();
        assert_all_zero!(nonce);

        let ciphertext = {
            let mut data = vec![0u8; GOLDEN.len() + A::OVERHEAD];
            let (out, tag) = data.split_at_mut(GOLDEN.len());
            out.clone_from_slice(GOLDEN);
            A::new(&key)
                .seal_in_place(nonce.borrow(), out, tag, AD)
                .expect("unable to encrypt data in-place");
            data
        };

        let plaintext = {
            let mut data = ciphertext.to_vec();
            let (out, tag) = data.split_at_mut(GOLDEN.len());
            A::new(&key)
                .open_in_place(nonce.borrow(), out, tag, AD)
                .expect("unable to decrypt data in-place");
            out.to_vec()
        };
        assert_eq!(&plaintext, GOLDEN, "in-place round trip test failed");
    }

    /// Decryption should fail with an incorrect key.
    pub fn test_bad_key<A: Aead, R: Csprng>(rng: &mut R) {
        let nonce = A::Nonce::default();
        assert_all_zero!(nonce);

        let ciphertext = {
            let key = A::Key::new(rng);

            let mut dst = vec![0u8; GOLDEN.len() + A::OVERHEAD];
            A::new(&key)
                .seal(&mut dst[..], nonce.borrow(), GOLDEN, AD)
                .expect("unable to encrypt data");
            dst
        };

        let key = A::Key::new(rng);
        let mut dst = vec![0u8; ciphertext.len() - A::OVERHEAD];
        let err = A::new(&key)
            .open(&mut dst[..], nonce.borrow(), &ciphertext, AD)
            .expect_err("decryption should have failed due to a different key");
        assert_eq!(err, AeadError::Authentication);
    }

    /// Decryption should fail with an incorrect nonce.
    pub fn test_bad_nonce<A: Aead, R: Csprng>(rng: &mut R) {
        let key = A::Key::new(rng);

        let ciphertext = {
            let mut nonce = A::Nonce::default();
            assert_all_zero!(nonce);
            nonce.borrow_mut().fill(b'A');

            let mut dst = vec![0u8; GOLDEN.len() + A::OVERHEAD];
            A::new(&key)
                .seal(&mut dst[..], nonce.borrow(), GOLDEN, AD)
                .expect("unable to encrypt data");
            dst
        };

        let mut nonce = A::Nonce::default();
        assert_all_zero!(nonce);
        nonce.borrow_mut().fill(b'B');

        let mut dst = vec![0u8; ciphertext.len() - A::OVERHEAD];
        let err = A::new(&key)
            .open(&mut dst[..], nonce.borrow(), &ciphertext, AD)
            .expect_err("decryption should have failed due to a modified nonce");
        assert_eq!(err, AeadError::Authentication);
    }

    /// Decryption should fail with a modified AD.
    pub fn test_bad_ad<A: Aead, R: Csprng>(rng: &mut R) {
        let key = A::Key::new(rng);
        let nonce = A::Nonce::default();
        assert_all_zero!(nonce);

        let ciphertext = {
            let mut dst = vec![0u8; GOLDEN.len() + A::OVERHEAD];
            A::new(&key)
                .seal(&mut dst[..], nonce.borrow(), GOLDEN, AD)
                .expect("unable to encrypt data");
            dst
        };

        let mut dst = vec![0u8; ciphertext.len() - A::OVERHEAD];
        let err = A::new(&key)
            .open(&mut dst[..], nonce.borrow(), &ciphertext, b"some bad AD")
            .expect_err("decryption should have failed due to a modified AD");
        assert_eq!(err, AeadError::Authentication);
    }

    /// Decryption should fail with a modified ciphertext.
    pub fn test_bad_ciphertext<A: Aead, R: Csprng>(rng: &mut R) {
        let key = A::Key::new(rng);
        let nonce = A::Nonce::default();
        assert_all_zero!(nonce);

        let mut ciphertext = {
            let mut dst = vec![0u8; GOLDEN.len() + A::OVERHEAD];
            A::new(&key)
                .seal(&mut dst[..], nonce.borrow(), GOLDEN, AD)
                .expect("unable to encrypt data");
            dst
        };

        ciphertext[0] = ciphertext[0].wrapping_add(1);

        let mut dst = vec![0u8; ciphertext.len() - A::OVERHEAD];
        let err = A::new(&key)
            .open(&mut dst[..], nonce.borrow(), &ciphertext, AD)
            .expect_err("decryption should have failed due to a modified ciphertext");
        assert_eq!(err, AeadError::Authentication);
    }

    /// Decryption should fail with a modified authentication
    /// tag.
    pub fn test_bad_tag<A: Aead, R: Csprng>(rng: &mut R) {
        let key = A::Key::new(rng);
        let nonce = A::Nonce::default();
        assert_all_zero!(nonce);

        let mut ciphertext = {
            let mut dst = vec![0u8; GOLDEN.len() + A::OVERHEAD];
            A::new(&key)
                .seal(&mut dst[..], nonce.borrow(), GOLDEN, AD)
                .expect("unable to encrypt data");
            dst
        };

        // It's possible that the tag isn't at the end, but for
        // most AEADs it will be.
        let n = ciphertext.len() - 1;
        ciphertext[n] = ciphertext[n].wrapping_add(1);

        let mut dst = vec![0u8; ciphertext.len() - A::OVERHEAD];
        let err = A::new(&key)
            .open(&mut dst[..], nonce.borrow(), &ciphertext, AD)
            .expect_err("decryption should have failed due to a modified auth tag");
        assert_eq!(err, AeadError::Authentication);
    }
}

/// Performs all of the tests inside the `hash` module.
///
/// This macro expands into a bunch of individual `#[test]`
/// functions.
///
/// This is used by [`test_ciphersuite`], but can also be used
/// manually.
///
/// # Example
///
/// ```
/// use crypto::{test_hash, rust::Sha256};
///
/// test_hash!(sha256, Sha256);
/// ```
#[macro_export]
macro_rules! test_hash {
    ($name:ident, $hash:ty) => {
        macro_rules! test {
            ($test:ident) => {
                #[test]
                fn $test() {
                    $crate::test_util::hash::$test::<$hash>()
                }
            };
        }

        mod $name {
            #[allow(unused_imports)]
            use super::*;

            test!(test_basic);
        }
    };
}
pub use test_hash;

/// [`Hash`] tests.
pub mod hash {
    use crate::hash::Hash;

    /// A basic test for a `Hash`.
    pub fn test_basic<T: Hash>() {
        const INPUT: &[u8] = r#"
Sir, in my heart there was a kind of fighting
That would not let me sleep. Methought I lay
Worse than the mutines in the bilboes. Rashly—
And prais'd be rashness for it—let us know
Our indiscretion sometimes serves us well ...
"#
        .as_bytes();

        let want = T::hash(INPUT);

        let got = {
            // Repeated calls to `update` should be the same as
            // calling `hash` directly.
            let mut h = T::new();
            for c in INPUT {
                h.update(&[*c]);
            }
            h.digest()
        };
        assert_eq!(want, got);

        // Hashing the same input should result in the same
        // output.
        assert_eq!(want, T::hash(INPUT));

        // A modified input should have a different hash, though.
        let mut modified = INPUT.to_vec();
        modified[0] += 1;
        assert_ne!(want, T::hash(&modified[..]));
    }
}

/// Performs all of the tests inside the `hpke` module.
///
/// This macro expands into a bunch of individual `#[test]`
/// functions.
///
/// This is used by [`test_ciphersuite`], but can also be used
/// manually.
///
/// # Example
///
/// ```
/// use crypto::{
///     rust::{
///         Aes256Gcm,
///         DhKemP256HkdfSha256,
///         HkdfSha256,
///     },
///     test_hpke,
/// };
///
/// // Without test vectors.
/// test_hpke!(dhkemp256hkdfsha256_hkdfsha256_aes256gcm,
///     DhKemP256HkdfSha256,
///     HkdfSha256,
///     Aes256Gcm,
/// );
///
/// // With test vectors.
/// test_hpke!(dhkemp256hkdfsha256_hkdfsha256_aes256gcm_with_vecs,
///     DhKemP256HkdfSha256,
///     HkdfSha256,
///     Aes256Gcm,
///     HpkeTest::HpkeDhKemP256HkdfSha256HkdfSha256Aes256Gcm,
/// );
/// ```
#[macro_export]
macro_rules! test_hpke {
    ($name:ident, $kem:ty, $kdf:ty, $aead:ty $(, HpkeTest::$vectors:ident)? $(,)?) => {
        macro_rules! test {
            ($test:ident) => {
                #[test]
                fn $test() {
                    $crate::test_util::hpke::$test::<$kem, $kdf, $aead, _>(
                        &mut $crate::Rng,
                    )
                }
            };
        }

        mod $name {
            #[allow(unused_imports)]
            use super::*;

            test!(test_round_trip);

            $(
                #[test]
                fn vectors() {
                    $crate::test_util::vectors::test_hpke::<$kem, $kdf, $aead>(
                        $crate::test_util::vectors::HpkeTest::$vectors,
                    );
                }
            )?
        }
    };
}
pub use test_hpke;

/// [`Hpke`][crate::hpke::Hpke] tests.
pub mod hpke {
    extern crate alloc;

    use {
        crate::{
            aead::Aead,
            csprng::Csprng,
            hpke::{Hpke, Mode, RecvCtx, SendCtx},
            kdf::Kdf,
            kem::{DecapKey, Kem},
            keys::SecretKey,
        },
        alloc::vec,
    };

    /// Tests the full encryption-decryption cycle.
    #[allow(non_snake_case)]
    pub fn test_round_trip<K: Kem, F: Kdf, A: Aead, R: Csprng>(rng: &mut R) {
        const GOLDEN: &[u8] = b"some plaintext";
        const AD: &[u8] = b"some additional data";
        const INFO: &[u8] = b"some contextual binding";

        let skR = K::DecapKey::new(rng);
        let pkR = skR.public();

        let (enc, mut send) = Hpke::<K, F, A>::setup_send(rng, Mode::Base, &pkR, INFO)
            .expect("unable to create send context");
        let mut recv = Hpke::<K, F, A>::setup_recv(Mode::Base, &enc, &skR, INFO)
            .expect("unable to create recv context");

        let ciphertext = {
            let mut dst = vec![0u8; GOLDEN.len() + SendCtx::<K, F, A>::OVERHEAD];
            send.seal(&mut dst, GOLDEN, AD).expect("encryption failed");
            dst
        };
        let plaintext = {
            let mut dst = vec![0u8; ciphertext.len() - RecvCtx::<K, F, A>::OVERHEAD];
            recv.open(&mut dst, &ciphertext, AD)
                .expect("decryption failed");
            dst
        };
        assert_eq!(plaintext, GOLDEN);
    }
}

/// Performs all of the tests inside the `kdf` module.
///
/// This macro expands into a bunch of individual `#[test]`
/// functions.
///
/// This is used by [`test_ciphersuite`], but can also be used
/// manually.
///
/// # Example
///
/// ```
/// use crypto::{test_kdf, rust::HkdfSha256};
///
/// // Without test vectors.
/// test_kdf!(hkdf_sha256, HkdfSha256);
///
/// // With test vectors.
/// test_kdf!(hkdf_sha256_with_vecs, HkdfSha256, HkdfTest::HkdfSha256);
/// ```
#[macro_export]
macro_rules! test_kdf {
    ($name:ident, $kdf:ty $(, HkdfTest::$vectors:ident)?) => {
        macro_rules! test {
            ($test:ident) => {
                #[test]
                fn $test() {
                    $crate::test_util::kdf::$test::<$kdf>()
                }
            };
        }

        mod $name {
            #[allow(unused_imports)]
            use super::*;

            test!(test_arbitrary_len);
            test!(test_max_output);

            $(
                #[test]
                fn vectors() {
                    $crate::test_util::vectors::test_hkdf::<$kdf>(
                        $crate::test_util::vectors::HkdfTest::$vectors,
                    );
                }
            )?
        }
    };
}
pub use test_kdf;

/// [`Kdf`] tests.
pub mod kdf {
    extern crate alloc;

    use {
        crate::kdf::{Kdf, KdfError},
        alloc::vec,
        core::borrow::Borrow,
        more_asserts::assert_ge,
    };

    /// Asserts the following:
    ///
    /// - invoking [`Kdf::extract`] twice results in the same PRK
    /// - invoking [`Kdf::expand`] twice results in the same key
    /// - [`Kdf::extract_and_expand`] is the same as invoking
    /// both [`Kdf::extract`] and [`Kdf::expand`].
    fn check<T: Kdf>(out1: &mut [u8], out2: &mut [u8], ikm: &[u8], salt: &[u8], info: &[u8]) {
        // extract should return the same output
        assert_eq!(
            T::extract(ikm, salt).borrow(),
            T::extract(ikm, salt).borrow(),
            "extract returned different outputs"
        );

        // expand should also return the same ouput
        let prk = T::extract(ikm, salt);
        T::expand(out1, &prk, info).expect("expand failed");
        T::expand(out2, &prk, info).expect("expand failed");
        assert_eq!(out1, out2, "expand returned different outputs");

        let tmp = out1.to_vec();

        // and so should extract_and_expand
        T::extract_and_expand(out1, ikm, salt, info).expect("extract_and_expand failed");
        T::extract_and_expand(out2, ikm, salt, info).expect("extract_and_expand failed");
        assert_eq!(out1, out2, "extract_and_expand returned different outputs");

        assert_eq!(
            out1,
            &tmp[..],
            "extract_and_expand differs from extract+expand"
        );
    }

    /// Tests that we can use arbitrary length IKM, salts, and
    /// infos.
    pub fn test_arbitrary_len<T: Kdf>() {
        const N: usize = 255 * 64;

        let mut out1 = [0u8; 517];
        let mut out2 = [0u8; 517];

        // Must support arbitrary length IKMs, salts, and infos.
        let ikm = [0u8; N];
        let salt = [0u8; N];
        let info = [0u8; N];
        for i in (0..ikm.len()).step_by(77) {
            check::<T>(&mut out1, &mut out2, &ikm[..i], &salt[..i], &info[..i]);
        }
    }

    /// Tests that we can't exceed [`Kdf::MAX_OUTPUT`].
    pub fn test_max_output<T: Kdf>() {
        // Must support at least 512 bits of output.
        assert_ge!(T::MAX_OUTPUT, 64);

        // It's possible that `MAX_OUTPUT` is something silly,
        // like 2 GiB. If this is the case, we have to assume it
        // does the Right Thing.
        const TOO_LARGE: usize = 500 * 1024 * 1024;
        if T::MAX_OUTPUT > TOO_LARGE {
            #[cfg(any(test, feature = "std"))]
            eprintln!(
                "skipping 'test_max_output': MAX_OUTPUT too large: {}",
                T::MAX_OUTPUT
            );
            return;
        }
        let mut out = vec![0u8; T::MAX_OUTPUT + 1];
        let err = T::extract_and_expand(&mut out[..], &[], &[], &[])
            .expect_err("output larger than MAX_OUTPUT, but no error");
        assert_eq!(err, KdfError::OutputTooLong);
    }
}

/// Performs all of the tests inside the `mac` module.
///
/// This macro expands into a bunch of individual `#[test]`
/// functions.
///
/// This is used by [`test_ciphersuite`], but can also be used
/// manually.
///
/// # Example
///
/// ```
/// use crypto::{test_mac, rust::HmacSha256};
///
/// // Without test vectors.
/// test_mac!(hmac_sha256, HmacSha256);
///
/// // With test vectors.
/// test_mac!(hmac_sha256_with_vecs, HmacSha256, MacTest::HmacSha256);
/// ```
#[macro_export]
macro_rules! test_mac {
    ($name:ident, $mac:ty $(, MacTest::$vectors:ident)?) => {
        macro_rules! test {
            ($test:ident) => {
                #[test]
                fn $test() {
                    $crate::test_util::mac::$test::<$mac, _>(&mut $crate::Rng)
                }
            };
        }

        mod $name {
            #[allow(unused_imports)]
            use super::*;

            test!(test_default);
            test!(test_update);
            test!(test_verify);
            test!(test_different_keys);
            test!(test_different_data);

            $(
                #[test]
                fn vectors() {
                    $crate::test_util::vectors::test_mac::<$mac>(
                        $crate::test_util::vectors::MacTest::$vectors,
                    );
                }
            )?
        }
    };
}
pub use test_mac;

/// [`Mac`] tests.
pub mod mac {
    use crate::{csprng::Csprng, keys::SecretKey, mac::Mac};

    const DATA: &[u8] = b"hello, world!";

    /// Basic positive test.
    pub fn test_default<T: Mac, R: Csprng>(rng: &mut R) {
        let key = T::Key::new(rng);
        let tag1 = T::mac(&key, DATA);
        let tag2 = T::mac(&key, DATA);
        assert_ct_eq!(tag1, tag2, "tags should be the same");
    }

    /// Tests that [`Mac::update`] is the same as [`Mac::mac`].
    pub fn test_update<T: Mac, R: Csprng>(rng: &mut R) {
        let key = T::Key::new(rng);
        let tag1 = T::mac(&key, DATA);
        let tag2 = {
            let mut h = T::new(&key);
            for c in DATA {
                h.update(&[*c]);
            }
            h.tag()
        };
        assert_ct_eq!(tag1, tag2, "tags should be the same");
    }

    /// Test [`Mac::verify`].
    pub fn test_verify<T: Mac, R: Csprng>(rng: &mut R) {
        let key = T::Key::new(rng);
        let tag1 = T::mac(&key, DATA);

        let mut h = T::new(&key);
        for c in DATA {
            h.update(&[*c]);
        }
        h.verify(&tag1).expect("tags should be the same");
    }

    /// Negative tests for different keys.
    pub fn test_different_keys<T: Mac, R: Csprng>(rng: &mut R) {
        let key1 = T::Key::new(rng);
        let key2 = T::Key::new(rng);
        assert_ct_ne!(key1, key2, "keys should differ");

        let tag1 = T::mac(&key1, DATA);
        let tag2 = T::mac(&key2, DATA);
        assert_ct_ne!(tag1, tag2, "tags should differ");
    }

    /// Negative test for MACs of different data.
    pub fn test_different_data<T: Mac, R: Csprng>(rng: &mut R) {
        let key = T::Key::new(rng);
        let tag1 = T::mac(&key, b"hello");
        let tag2 = T::mac(&key, b"world");
        assert_ct_ne!(tag1, tag2, "tags should differ");
    }
}

/// Performs all of the tests inside the `signer` module.
///
/// This macro expands into a bunch of individual `#[test]`
/// functions.
///
/// This is used by [`test_ciphersuite`], but can also be used
/// manually.
///
/// # Example
///
/// ```
/// use crypto::{test_signer, rust::P256};
///
/// // Without test vectors.
/// test_signer!(p256, P256);
///
/// // With test vectors.
/// test_signer!(p256_with_vecs, P256, EcdsaTest::Secp256r1Sha256);
/// ```
#[macro_export]
macro_rules! test_signer {
    ($name:ident, $signer:ty) => {
        $crate::__test_signer!($name, $signer);
    };
    ($name:ident, $signer:ty, EcdsaTest::$vectors:ident $(,)?) => {
        $crate::__test_signer!($name, $signer, test_ecdsa, EcdsaTest, $vectors);
    };
    ($name:ident, $signer:ty, EddsaTest::$vectors:ident $(,)?) => {
        $crate::__test_signer!($name, $signer, test_eddsa, EddsaTest, $vectors);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __test_signer {
    ($name:ident, $signer:ty $(, $f:ident, $which:ident, $vectors:ident)? $(,)?) => {
        macro_rules! test {
            ($test:ident) => {
                #[test]
                fn $test() {
                    $crate::test_util::signer::$test::<$signer, _>(&mut $crate::Rng)
                }
            };
        }

        mod $name {
            #[allow(unused_imports)]
            use super::*;

            test!(test_default);
            test!(test_pk_eq);
            test!(test_sk_ct_eq);
            test!(test_public);
            test!(test_batch_simple_good);
            test!(test_batch_simple_bad);

            $(
                #[test]
                fn vectors() {
                    $crate::test_util::vectors::$f::<$signer>(
                        $crate::test_util::vectors::$which::$vectors,
                    );
                }
            )?
        }
    };
}
pub use test_signer;

/// [`Signer`] tests.
pub mod signer {
    extern crate alloc;

    use {
        crate::{
            csprng::Csprng,
            keys::SecretKey,
            signer::{Signer, SigningKey, VerifyingKey},
        },
        alloc::vec::Vec,
        core::borrow::Borrow,
    };

    /// The base positive test.
    pub fn test_default<T: Signer, R: Csprng>(rng: &mut R) {
        const MSG: &[u8] = b"hello, world!";
        let sk = T::SigningKey::new(rng);
        let sig = sk.sign(MSG).expect("unable to create signature");
        sk.public()
            .verify(MSG, &sig)
            .expect("unable to verify signature");
    }

    /// Test `Signer::SigningKey::ct_eq`.
    ///
    /// It also tests `Signer::SigningKey::import`.
    pub fn test_sk_ct_eq<T: Signer, R: Csprng>(rng: &mut R) {
        let sk1 = T::SigningKey::new(rng);
        let sk2 = T::SigningKey::new(rng);

        fn same_key<T: Signer, K: SigningKey<T>>(k: K) {
            let data = match k.try_export_secret() {
                Ok(data) => data,
                Err(_) => {
                    // Can't export the secret, so skip the test.
                    return;
                }
            };
            let sk1 = K::import(data.borrow()).expect("should be able to import key");
            let sk2 = K::import(data.borrow()).expect("should be able to import key");
            assert_ct_eq!(sk1, sk2);
        }

        // The two keys should be different.
        assert_ct_ne!(sk1, sk2);
        // But each key should be equal to itself.
        same_key(sk1);
        same_key(sk2);
    }

    /// Test `Signer::VerifyingKey::eq`.
    ///
    /// It also tests `Signer::VerifyingKey::import`.
    pub fn test_pk_eq<T: Signer, R: Csprng>(rng: &mut R) {
        let pk1 = T::SigningKey::new(rng).public();
        let pk2 = T::SigningKey::new(rng).public();

        fn same_key<T: Signer, K: VerifyingKey<T>>(k: K) {
            let pk1 = K::import(k.export().borrow()).expect("should be able to import key");
            let pk2 = K::import(k.export().borrow()).expect("should be able to import key");
            assert_eq!(pk1, pk2);
        }

        // The two keys should be different.
        assert_ne!(pk1, pk2);
        // But each key should be equal to itself.
        same_key(pk1);
        same_key(pk2);
    }

    /// [`SigningKey::public`] should always return the same key.
    pub fn test_public<T: Signer, R: Csprng>(rng: &mut R) {
        let sk = T::SigningKey::new(rng);
        assert_eq!(sk.public(), sk.public());
    }

    /// Simple positive test for [`Signer::verify_batch`].
    pub fn test_batch_simple_good<T: Signer, R: Csprng>(rng: &mut R) {
        const MSGS: &[&[u8]] = &[
            b"hello",
            b"world",
            b"!",
            b"a longer message",
            b"",
            b"test_batch_simple_good",
            b"message #7",
            b"message #9",
            b"off by one",
        ];
        let (pks, sigs): (Vec<_>, Vec<_>) = MSGS
            .iter()
            .map(|msg| {
                let sk = T::SigningKey::new(rng);
                let sig = sk.sign(msg).expect("should not fail");
                (sk.public(), sig)
            })
            .unzip();
        T::verify_batch(MSGS, &sigs[..], &pks[..]).expect("should not fail")
    }

    /// Simple negative test for [`Signer::verify_batch`].
    pub fn test_batch_simple_bad<T: Signer, R: Csprng>(rng: &mut R) {
        let msgs: &mut [&[u8]] = &mut [
            b"hello",
            b"world",
            b"!",
            b"a longer message",
            b"",
            b"test_batch_simple_bad",
            b"message #7",
            b"message #9",
            b"off by one",
        ];
        let (pks, sigs): (Vec<_>, Vec<_>) = msgs
            .iter()
            .map(|msg| {
                let sk = T::SigningKey::new(rng);
                let sig = sk.sign(msg).expect("should not fail");
                (sk.public(), sig)
            })
            .unzip();
        msgs[msgs.len() / 2] = b"AAAAAAAAAAAAA";
        T::verify_batch(msgs, &sigs[..], &pks[..]).expect_err("should fail");
    }
}

/// Test specific algorithms using test vectors.
pub mod vectors {
    extern crate alloc;

    use {
        super::{AeadWithDefaults, KdfWithDefaults, MacWithDefaults, SignerWithDefaults},
        crate::{
            aead::Aead,
            hpke::Hpke,
            hpke::SendCtx,
            import::Import,
            kdf::Kdf,
            kem::{Ecdh, Kem},
            mac::Mac,
            signer::{Signer, VerifyingKey},
        },
        alloc::{string::ToString, vec},
        core::borrow::Borrow,
        subtle::ConstantTimeEq,
        wycheproof::{aead, ecdh, ecdsa, eddsa, hkdf, mac},
    };

    pub use hpke::TestName as HpkeTest;
    pub use wycheproof::{
        self, aead::TestName as AeadTest, ecdh::TestName as EcdhTest, ecdsa::TestName as EcdsaTest,
        eddsa::TestName as EddsaTest, hkdf::TestName as HkdfTest, mac::TestName as MacTest,
        TestResult,
    };

    /// HPKE tests.
    #[allow(missing_docs)]
    pub mod hpke {
        extern crate alloc;

        use {
            crate::{
                hpke::{Mode, Psk},
                import::Import,
            },
            alloc::{boxed::Box, vec::Vec},
            core::{result::Result, str::FromStr},
            serde::{self, Deserialize},
            serde_json,
            wycheproof::{ByteString, WycheproofError},
        };

        macro_rules! test_names {
            ($($name:ident),* $(,)?) => {
                pub enum TestName {
                    $($name,)*
                }

                impl TestName {
                    fn json_data(&self) -> &'static str {
                        match self {
                            $(
                                Self::$name => include_str!(concat!("testdata/", stringify!($name), ".json")),
                            )*
                        }
                    }
                }

                impl FromStr for TestName {
                    type Err = WycheproofError;

                    fn from_str(s: &str) -> Result<Self, Self::Err> {
                        match s {
                            $(
                                stringify!($name) => Ok(Self::$name),
                            )*
                            _ => Err(WycheproofError::NoDataSet),
                        }
                    }
                }
            };
        }

        test_names! {
            HpkeDhKemP256HkdfSha256HkdfSha256Aes128Gcm,
            HpkeDhKemP256HkdfSha256HkdfSha256Aes256Gcm,
            HpkeDhKemP256HkdfSha256HkdfSha256ChaCha20Poly1305,
            HpkeDhKemP256HkdfSha256HkdfSha256ExportOnly,
            HpkeDhKemP256HkdfSha256HkdfSha512Aes128Gcm,
            HpkeDhKemP256HkdfSha256HkdfSha512Aes256Gcm,
            HpkeDhKemP256HkdfSha256HkdfSha512ChaCha20Poly1305,
            HpkeDhKemP256HkdfSha256HkdfSha512ExportOnly,
            HpkeDhKemP521HkdfSha512HkdfSha256Aes128Gcm,
            HpkeDhKemP521HkdfSha512HkdfSha256Aes256Gcm,
            HpkeDhKemP521HkdfSha512HkdfSha256ChaCha20Poly1305,
            HpkeDhKemP521HkdfSha512HkdfSha256ExportOnly,
            HpkeDhKemP521HkdfSha512HkdfSha512Aes128Gcm,
            HpkeDhKemP521HkdfSha512HkdfSha512Aes256Gcm,
            HpkeDhKemP521HkdfSha512HkdfSha512ChaCha20Poly1305,
            HpkeDhKemP521HkdfSha512HkdfSha512ExportOnly,
            HpkeDhKemX25519HkdfSha256HkdfSha256Aes128Gcm,
            HpkeDhKemX25519HkdfSha256HkdfSha256Aes256Gcm,
            HpkeDhKemX25519HkdfSha256HkdfSha256ChaCha20Poly1305,
            HpkeDhKemX25519HkdfSha256HkdfSha256ExportOnly,
            HpkeDhKemX25519HkdfSha256HkdfSha512Aes128Gcm,
            HpkeDhKemX25519HkdfSha256HkdfSha512Aes256Gcm,
            HpkeDhKemX25519HkdfSha256HkdfSha512ChaCha20Poly1305,
            HpkeDhKemX25519HkdfSha256HkdfSha512ExportOnly,
            HpkeDhKemX448HkdfSha512HkdfSha256Aes128Gcm,
            HpkeDhKemX448HkdfSha512HkdfSha256Aes256Gcm,
            HpkeDhKemX448HkdfSha512HkdfSha256ChaCha20Poly1305,
            HpkeDhKemX448HkdfSha512HkdfSha256ExportOnly,
            HpkeDhKemX448HkdfSha512HkdfSha512Aes128Gcm,
            HpkeDhKemX448HkdfSha512HkdfSha512Aes256Gcm,
            HpkeDhKemX448HkdfSha512HkdfSha512ChaCha20Poly1305,
            HpkeDhKemX448HkdfSha512HkdfSha512ExportOnly,
        }

        #[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
        pub(crate) struct TestSet {
            pub test_groups: Vec<TestGroup>,
        }

        impl TestSet {
            pub fn load(test: TestName) -> Result<Self, WycheproofError> {
                match serde_json::from_str(test.json_data()) {
                    Ok(set) => Ok(set),
                    Err(e) => Err(WycheproofError::ParsingFailed(Box::new(e))),
                }
            }
        }

        /// An HPKE mode.
        #[repr(u8)]
        #[derive(serde_repr::Deserialize_repr, Copy, Clone, Debug, Eq, PartialEq)]
        pub enum HpkeMode {
            Base = 0x00,
            Psk = 0x01,
            Auth = 0x02,
            AuthPsk = 0x03,
        }

        #[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(non_snake_case)]
        pub(crate) struct TestGroup {
            pub mode: HpkeMode,
            pub kem_id: u16,
            pub kdf_id: u16,
            pub aead_id: u16,
            pub info: ByteString,
            pub ikmR: ByteString,
            pub ikmS: ByteString,
            pub ikmE: ByteString,
            pub skRm: ByteString,
            pub skSm: ByteString,
            pub skEm: ByteString,
            pub psk: ByteString,
            pub psk_id: ByteString,
            pub pkRm: ByteString,
            pub pkSm: ByteString,
            pub pkEm: ByteString,
            pub enc: ByteString,
            pub shared_secret: ByteString,
            pub key_schedule_context: ByteString,
            pub secret: ByteString,
            pub key: ByteString,
            pub base_nonce: ByteString,
            pub exporter_secret: ByteString,
            #[serde(rename = "encryptions")]
            pub tests: Vec<Test>,
            pub exports: Vec<ExportTest>,
        }

        #[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub(crate) struct Test {
            pub aad: ByteString,
            pub ct: ByteString,
            pub nonce: ByteString,
            pub pt: ByteString,
        }

        #[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub(crate) struct ExportTest {
            pub exporter_context: ByteString,
            #[serde(rename = "L")]
            pub len: usize,
            pub exported_value: ByteString,
        }

        impl TestGroup {
            #[allow(non_snake_case)]
            pub(super) fn get_mode<'a, T: Import<&'a [u8]>>(
                &'a self,
                id: usize,
                xkSm: &'a [u8],
            ) -> Mode<'_, T> {
                match self.mode {
                    HpkeMode::Base => Mode::Base,
                    HpkeMode::Psk => {
                        let psk = Psk::new(&self.psk[..], &self.psk_id[..])
                            .unwrap_or_else(|_| panic!("{id}"));
                        Mode::Psk(psk)
                    }
                    HpkeMode::Auth => {
                        let xkS = T::import(xkSm).unwrap_or_else(|_| panic!("{id}"));
                        Mode::Auth(xkS)
                    }
                    HpkeMode::AuthPsk => {
                        let xkS = T::import(xkSm).unwrap_or_else(|_| panic!("{id}"));
                        let psk = Psk::new(&self.psk[..], &self.psk_id[..])
                            .unwrap_or_else(|_| panic!("{id}"));
                        Mode::AuthPsk(xkS, psk)
                    }
                }
            }
        }
    }

    /// Tests an [`Aead`] against Project Wycheproof test vectors.
    ///
    /// It tests both `A` and [`AeadWithDefaults<T>`].
    pub fn test_aead<A: Aead>(name: AeadTest) {
        test_aead_inner::<A>(name);
        test_aead_inner::<AeadWithDefaults<A>>(name);
    }

    fn test_aead_inner<A: Aead>(name: AeadTest) {
        let set = aead::TestSet::load(name).expect("should be able to load tests");
        for g in &set.test_groups {
            if g.nonce_size / 8 != A::NONCE_SIZE
                || g.key_size / 8 != A::KEY_SIZE
                || g.tag_size / 8 != A::OVERHEAD
            {
                continue;
            }
            for tc in &g.tests {
                let id = tc.tc_id;

                let key = A::Key::import(&tc.key[..]).unwrap_or_else(|_| panic!("{id}"));
                let aead = A::new(&key);
                let nonce = A::Nonce::try_from(&tc.nonce[..]).unwrap_or_else(|_| panic!("{id}"));

                macro_rules! check {
                    ($tc:ident, $res:ident) => {
                        match tc.result {
                            TestResult::Valid | TestResult::Acceptable => {
                                let plaintext = $res.unwrap_or_else(|_| panic!("{id}"));
                                assert_eq!(plaintext, *tc.pt, "{id}");
                            }
                            TestResult::Invalid => {
                                $res.err().unwrap_or_else(|| panic!("{id}"));
                            }
                        }
                    };
                }

                let res = {
                    let ciphertext = [&tc.ct[..], &tc.tag[..]].concat();
                    let mut dst = vec![0u8; ciphertext.len() - A::OVERHEAD];
                    aead.open(&mut dst[..], nonce.borrow(), &ciphertext, &tc.aad[..])
                        .map(|_| dst)
                };
                check!(tc, res);

                let res = {
                    let mut data = tc.ct.to_vec();
                    aead.open_in_place(nonce.borrow(), &mut data, &tc.tag[..], &tc.aad[..])
                        .map(|_| data)
                };
                check!(tc, res);

                if tc.result == TestResult::Invalid {
                    // Can't test encryption if our data is for
                    // a test failure.
                    continue;
                }

                let (ct, tag) = {
                    let mut dst = vec![0u8; tc.pt.len() + A::OVERHEAD];
                    aead.seal(&mut dst[..], nonce.borrow(), &tc.pt[..], &tc.aad[..])
                        .unwrap_or_else(|_| panic!("{id}"));
                    let tag = dst.split_off(dst.len() - A::OVERHEAD);
                    (dst, tag)
                };
                assert_eq!(ct, *tc.ct, "{id}");
                assert_eq!(tag, *tc.tag, "{id}");

                let (ct, tag) = {
                    let mut data = tc.pt.clone().to_vec();
                    let mut tag = vec![0u8; A::OVERHEAD];
                    aead.seal_in_place(nonce.borrow(), &mut data, &mut tag[..], &tc.aad[..])
                        .unwrap_or_else(|_| panic!("{id}"));
                    (data, tag)
                };
                assert_eq!(ct, *tc.ct, "{id}");
                assert_eq!(tag, *tc.tag, "{id}");
            }
        }
    }

    /// Tests an [`Ecdh`] against Project Wycheproof test
    /// vectors.
    pub fn test_ecdh<T: Ecdh>(name: EcdhTest) {
        let set = ecdh::TestSet::load(name).expect("should be able to load tests");
        for g in &set.test_groups {
            for tc in &g.tests {
                let id = tc.tc_id;

                let sk = match T::PrivateKey::import(&tc.private_key[..]) {
                    Ok(sk) => sk,
                    Err(_) => continue,
                };
                let pk = match T::PublicKey::import(&tc.public_key[..]) {
                    Ok(pk) => pk,
                    Err(_) => continue,
                };

                let res = T::ecdh(&sk, &pk);
                match tc.result {
                    TestResult::Valid | TestResult::Acceptable => {
                        let got = res.unwrap_or_else(|_| panic!("{id}"));
                        assert_eq!(got.borrow(), &tc.shared_secret[..]);
                    }
                    TestResult::Invalid => {
                        res.err().unwrap_or_else(|| panic!("{id}"));
                    }
                };
            }
        }
    }

    /// Tests a [`Signer`] that implements ECDSA against Project
    /// Wycheproof test vectors.
    ///
    /// It tests both `T` and [`SignerWithDefaults<T>`].
    pub fn test_ecdsa<T: Signer>(name: EcdsaTest) {
        test_ecdsa_inner::<T>(name);
        test_ecdsa_inner::<SignerWithDefaults<T>>(name);
    }

    fn test_ecdsa_inner<T: Signer>(name: EcdsaTest) {
        let set = ecdsa::TestSet::load(name).expect("should be able to load tests");
        for g in &set.test_groups {
            for tc in &g.tests {
                let id = tc.tc_id;

                let pk = T::VerifyingKey::import(&g.key.key[..]).unwrap_or_else(|_| panic!("{id}"));
                // TODO(eric): fail the test if we reject a valid
                // signature.
                let sig = match T::Signature::import(&tc.sig[..]) {
                    Ok(sig) => sig,
                    Err(_) => continue,
                };

                let res = pk.verify(&tc.msg[..], &sig);
                match tc.result {
                    TestResult::Valid | TestResult::Acceptable => {
                        res.unwrap_or_else(|_| panic!("{id}"));
                    }
                    TestResult::Invalid => {
                        res.expect_err(msg!(id));
                    }
                };
            }
        }
    }

    /// Tests a [`Signer`] that implements EdDSA against Project
    /// Wycheproof test vectors.
    ///
    /// It tests both `T` and [`SignerWithDefaults<T>`].
    pub fn test_eddsa<T: Signer>(name: EddsaTest) {
        test_eddsa_inner::<T>(name);
        test_eddsa_inner::<SignerWithDefaults<T>>(name);
    }

    fn test_eddsa_inner<T: Signer>(name: EddsaTest) {
        fn sig_len(name: eddsa::TestName) -> usize {
            match name {
                eddsa::TestName::Ed25519 => 64,
                eddsa::TestName::Ed448 => 114,
            }
        }

        let set = eddsa::TestSet::load(name).expect("should be able to load tests");
        for g in &set.test_groups {
            for tc in &g.tests {
                let id = tc.tc_id;

                let pk = T::VerifyingKey::import(&g.key.pk[..]).unwrap_or_else(|_| panic!("{id}"));

                let wrong_len = sig_len(name) != tc.sig.len();
                let sig = match T::Signature::import(&tc.sig[..]) {
                    Err(_) => {
                        // Can't import the signature, so it's
                        // either an incorrect length or (r,s)
                        // are invalid.
                        assert!(wrong_len || tc.result == TestResult::Invalid, "#{id}");
                        // Since we can't import the signature,
                        // it's impossible to test.
                        continue;
                    }
                    Ok(sig) => {
                        // We could import the signature, so it
                        // must be the correct length.
                        assert!(!wrong_len);
                        sig
                    }
                };

                // TODO(eric): EdDSA signatures are
                // deterministic, so also check the output of
                // sign.

                let res = pk.verify(&tc.msg[..], &sig);
                match tc.result {
                    TestResult::Valid | TestResult::Acceptable => {
                        res.unwrap_or_else(|_| panic!("{id}"));
                    }
                    TestResult::Invalid => {
                        res.expect_err(msg!(id));
                    }
                };
            }
        }
    }

    /// Tests a [`Kdf`] that implements HKDF against Project
    /// Wycheproof test vectors.
    ///
    /// It tests both `T` and [`KdfWithDefaults<T>`].
    pub fn test_hkdf<T: Kdf>(name: HkdfTest) {
        test_hkdf_inner::<T>(name);
        test_hkdf_inner::<KdfWithDefaults<T>>(name);
    }

    fn test_hkdf_inner<T: Kdf>(name: HkdfTest) {
        let set = hkdf::TestSet::load(name).expect("should be able to load tests");
        for g in &set.test_groups {
            for tc in &g.tests {
                let id = tc.tc_id;

                let mut out = vec![0u8; tc.okm.len()];
                T::extract_and_expand(&mut out[..], &tc.ikm[..], &tc.salt[..], &tc.info[..])
                    .unwrap_or_else(|_| panic!("{id}"));
                assert_eq!(&out[..], &tc.okm[..], "{id}");
            }
        }
    }

    /// Tests an [`Hpke`] against test vectors.
    #[allow(non_snake_case)]
    pub fn test_hpke<K, F, A>(name: HpkeTest)
    where
        K: Kem,
        F: Kdf,
        A: Aead,
    {
        let set = hpke::TestSet::load(name).expect("should be able to load tests");
        for (i, g) in set.test_groups.iter().enumerate() {
            let (enc, mut send) = {
                let skE = K::DecapKey::import(&g.skEm[..]).unwrap_or_else(|_| panic!("group={i}"));
                let pkR = K::EncapKey::import(&g.pkRm[..]).unwrap_or_else(|_| panic!("group={i}"));
                let mode = g.get_mode(i, &g.skSm[..]);
                Hpke::<K, F, A>::setup_send_deterministically(mode.as_ref(), &pkR, &g.info, skE)
                    .unwrap_or_else(|_| panic!("group={i}"))
            };
            let mut recv = {
                let skR = K::DecapKey::import(&g.skRm[..]).unwrap_or_else(|_| panic!("group={i}"));
                let mode = g.get_mode(i, &g.pkSm[..]);
                Hpke::<K, F, A>::setup_recv(mode.as_ref(), &enc, &skR, &g.info)
                    .unwrap_or_else(|_| panic!("group={i}"))
            };

            for (id, tc) in g.tests.iter().enumerate() {
                let ct = {
                    let mut dst = vec![0u8; tc.pt.len() + SendCtx::<K, F, A>::OVERHEAD];
                    send.seal(&mut dst, &tc.pt, &tc.aad).unwrap_or_else(|_| {
                        panic!("encryption failure: {id}/{} (g={i})", g.tests.len())
                    });
                    dst
                };
                assert_eq!(
                    ct,
                    &tc.ct[..],
                    "invalid ciphertext for enc {id}/{} (g={i})",
                    g.tests.len()
                );

                let pt = {
                    let mut dst = vec![0u8; tc.pt.len()];
                    recv.open(&mut dst, &tc.ct, &tc.aad).unwrap_or_else(|_| {
                        panic!("decryption failure: {id}/{} (g={i})", g.tests.len())
                    });
                    dst
                };
                assert_eq!(
                    pt,
                    &tc.pt[..],
                    "invalid plaintext for enc {id}/{} (g={i})",
                    g.tests.len()
                );
            }

            for (id, tc) in g.exports.iter().enumerate() {
                let n = g.exports.len();

                let mut got = vec![0u8; tc.len];
                send.export(got.as_mut(), &tc.exporter_context)
                    .expect("unable to export secret {id}/{n} (g={i})");
                assert_eq!(
                    got,
                    &tc.exported_value[..],
                    "invalid exported secret {id}/{n} (g={i})",
                );

                let mut got = vec![0u8; tc.len];
                recv.export(got.as_mut(), &tc.exporter_context)
                    .expect("unable to export secret {id}/{n} (g={i})");
                assert_eq!(
                    got,
                    &tc.exported_value[..],
                    "invalid exported secret {id}/{n} (g={i})",
                );
            }
        }
    }

    /// Tests a [`Mac`] against Project Wycheproof test vectors.
    ///
    /// It tests both `T` and [`MacWithDefaults<T>`].
    pub fn test_mac<T: Mac>(name: MacTest)
    where
        T::Key: ConstantTimeEq,
        T::Tag: for<'a> TryFrom<&'a [u8]>,
    {
        test_mac_inner::<T>(name);
        test_mac_inner::<MacWithDefaults<T>>(name);
    }

    fn test_mac_inner<T: Mac>(name: MacTest)
    where
        T::Key: ConstantTimeEq,
        T::Tag: for<'a> TryFrom<&'a [u8]>,
    {
        let set = mac::TestSet::load(name).expect("should be able to load tests");
        for g in &set.test_groups {
            for tc in &g.tests {
                let id = tc.tc_id;

                let tc_tag: T::Tag = match tc.tag[..].try_into() {
                    Ok(tag) => tag,
                    // Skip truncated tags.
                    Err(_) => continue,
                };

                let key = match T::Key::import(&tc.key[..]) {
                    Ok(h) => h,
                    // Skip insecure keys.
                    Err(_) => continue,
                };
                let mut h = T::new(&key);

                // Update one character at a time.
                for c in tc.msg.iter() {
                    h.update(&[*c]);
                }
                // An empty update.
                h.update(&[]);

                match tc.result {
                    TestResult::Valid | TestResult::Acceptable => {
                        h.clone().verify(&tc_tag).unwrap_or_else(|_| panic!("{id}"));
                        assert_eq!(h.clone().tag().ct_eq(&tc_tag).unwrap_u8(), 1, "{id}");
                        assert_eq!(h.clone().tag().ct_eq(&h.tag()).unwrap_u8(), 1, "{id}");
                    }
                    TestResult::Invalid => {
                        h.verify(&tc_tag).expect_err(msg!(id));
                    }
                };
            }
        }
    }
}
