//! Utilities for testing [`Engine`], [`CipherSuite`], and
//! cryptography implementations.
//!
//! If you implement any traits in this crate it is **very
//! highly** recommended that you use these tests.

#![allow(clippy::panic)]
#![cfg(any(test, docs, feature = "test_util"))]
#![cfg_attr(docs, doc(cfg(feature = "test_util")))]
#![forbid(unsafe_code)]

extern crate alloc;

use {
    crate::{
        aead::{Aead, AeadError, AeadId},
        apq::{self, ReceiverSecretKey, Sender, SenderSecretKey, SenderSigningKey, TopicKey},
        ciphersuite::CipherSuite,
        csprng::Csprng,
        default::Rng,
        engine::{Engine, WrappedKey},
        error::Error,
        groupkey::GroupKey,
        hash::Hash,
        hpke::{Hpke, Mode, Psk, RecvCtx, SendCtx},
        hybrid_array::{
            typenum::{operator_aliases::Sum, U64},
            ArraySize,
        },
        id::Id,
        import::Import,
        kdf::{Kdf, KdfError, KdfId},
        kem::{DecapKey, Ecdh, Kem},
        keys::SecretKey,
        mac::{Mac, MacId, MacKey, Tag},
        signer::{Signer, SigningKey, VerifyingKey},
        userkeys::{EncryptionKey, IdentityKey, SigningKey as UserSigningKey},
        Context,
    },
    alloc::{string::ToString, vec},
    core::{
        borrow::{Borrow, BorrowMut},
        fmt::Debug,
        marker::PhantomData,
        ops::{Add, FnMut},
    },
    more_asserts::assert_ge,
    subtle::ConstantTimeEq,
};

pub use wycheproof::{aead, ecdh, ecdsa, hkdf, mac, TestResult};

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
pub(crate) use assert_ct_eq;

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
pub(crate) use assert_ct_ne;

/// Checks that each byte in `data` is zero.
macro_rules! assert_all_zero {
    ($data:expr) => {
        for c in $data.borrow() {
            assert_eq!(*c, 0, "Default must return all zeros");
        }
    };
}

/// HPKE tests.
#[allow(missing_docs)]
pub mod hpke {
    use {
        super::*,
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

/// Test cases for a primitive.
pub trait Test<O = ()> {
    /// Performs the test.
    fn test<R: Csprng>(rng: &mut R, opts: O);
}

/// Test an [`Engine`].
///
/// It also performs [`test_ciphersuite`].
pub fn test_engine<R, E, F>(rng: &mut R, f: F)
where
    R: Csprng,
    E: Engine,
    <E::Aead as Aead>::TagSize: Add<U64>,
    Sum<<E::Aead as Aead>::TagSize, U64>: ArraySize,
    F: FnMut() -> E,
{
    test_ciphersuite::<E, _>(rng);

    EngineTest::test(rng, f);
}

/// Tests an [`Engine`].
///
/// This is used by [`test_engine`], but can also be used
/// manually.
pub struct EngineTest<E: Engine>(PhantomData<E>);

impl<E, F> Test<F> for EngineTest<E>
where
    E: Engine,
    <E::Aead as Aead>::TagSize: Add<U64>,
    Sum<<E::Aead as Aead>::TagSize, U64>: ArraySize,
    F: FnMut() -> E,
{
    fn test<R: Csprng>(rng: &mut R, mut f: F) {
        //
        // Aranya
        //
        Self::test_simple_user_signing_key_sign(rng);

        Self::test_simple_send_group_key(rng);
        Self::test_simple_wrap_group_key(rng, f());
        Self::test_simple_wrap_user_identity_key(rng, f());
        Self::test_simple_wrap_user_signing_key(rng, f());
        Self::test_simple_wrap_user_encryption_key(rng, f());

        Self::test_group_key_seal(rng);
        Self::test_group_key_open_wrong_key(rng);
        Self::test_group_key_open_wrong_context(rng);
        Self::test_group_key_open_bad_ciphertext(rng);

        //
        // APQ
        //
        Self::test_simple_sender_signing_key_sign(rng);

        Self::test_simple_seal_topic_key(rng);
        Self::test_simple_wrap_user_sender_secret_key(rng, f());
        Self::test_simple_wrap_user_sender_signing_key(rng, f());
        Self::test_simple_wrap_user_receiver_secret_key(rng, f());

        Self::test_topic_key_seal(rng);
        Self::test_topic_key_open_wrong_key(rng);
        Self::test_topic_key_open_wrong_context(rng);
        Self::test_topic_key_open_bad_ciphertext(rng);
    }
}

impl<E: Engine> EngineTest<E>
where
    E: Engine,
    <E::Aead as Aead>::TagSize: Add<U64>,
    Sum<<E::Aead as Aead>::TagSize, U64>: ArraySize,
{
    /// Simple positive test for [`UserSigningKey`].
    fn test_simple_user_signing_key_sign<R: Csprng>(rng: &mut R) {
        const MSG: &[u8] = b"hello, world!";

        let sign_key = UserSigningKey::<E>::new(rng);
        let sig = sign_key
            .sign(MSG, "test_simple_user_signing_key_sign")
            .expect("unable to create signature");
        sign_key
            .public()
            .verify(MSG, "test_simple_user_signing_key_sign", &sig)
            .expect("the signature should be valid");
    }

    /// Simple positive test for encrypting/decrypting
    /// [`GroupKey`]s.
    fn test_simple_send_group_key<R: Csprng>(rng: &mut R) {
        let enc_key = EncryptionKey::<E>::new(rng);

        let group = Id::default();
        let want = GroupKey::new(rng);
        let (enc, ciphertext) = enc_key
            .public()
            .seal_group_key(rng, &want, group)
            .expect("unable to encrypt `GroupKey`");
        let got = enc_key
            .open_group_key(&enc, &ciphertext, group)
            .expect("unable to decrypt `GroupKey`");
        assert_eq!(want.id(), got.id());
    }

    /// Simple positive test for wrapping [`GroupKey`]s.
    fn test_simple_wrap_group_key<R: Csprng>(rng: &mut R, mut eng: E) {
        let want = GroupKey::new(rng);
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
    fn test_simple_wrap_user_identity_key<R: Csprng>(rng: &mut R, mut eng: E) {
        let want = IdentityKey::new(rng);
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

    /// Simple positive test for wrapping [`UserSigningKey`]s.
    fn test_simple_wrap_user_signing_key<R: Csprng>(rng: &mut R, mut eng: E) {
        let want = UserSigningKey::new(rng);
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

    /// Simple positive test for wrapping [`EncryptionKey`]s.
    fn test_simple_wrap_user_encryption_key<R: Csprng>(rng: &mut R, mut eng: E) {
        let want = EncryptionKey::new(rng);
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

    /// Simple positive test for encryption using a [`GroupKey`].
    fn test_group_key_seal<R: Csprng>(rng: &mut R) {
        const INPUT: &[u8] = b"hello, world!";

        let author = UserSigningKey::<E>::new(rng).public();

        let gk = GroupKey::new(rng);
        let ciphertext = {
            let mut dst = vec![0u8; INPUT.len() + gk.overhead()];
            gk.seal(
                rng,
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
    fn test_group_key_open_wrong_key<R: Csprng>(rng: &mut R) {
        const INPUT: &[u8] = b"hello, world!";

        let author = UserSigningKey::<E>::new(rng).public();

        let gk1 = GroupKey::new(rng);
        let gk2 = GroupKey::new(rng);

        let ciphertext = {
            let mut dst = vec![0u8; INPUT.len() + gk1.overhead()];
            gk1.seal(
                rng,
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
    fn test_group_key_open_wrong_context<R: Csprng>(rng: &mut R) {
        const INPUT: &[u8] = b"hello, world!";

        let author1 = UserSigningKey::<E>::new(rng).public();
        let author2 = UserSigningKey::<E>::new(rng).public();

        let gk = GroupKey::new(rng);
        let ciphertext = {
            let mut dst = vec![0u8; INPUT.len() + gk.overhead()];
            gk.seal(
                rng,
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
    fn test_group_key_open_bad_ciphertext<R: Csprng>(rng: &mut R) {
        const INPUT: &[u8] = b"hello, world!";

        let author = UserSigningKey::<E>::new(rng).public();

        let gk = GroupKey::new(rng);
        let mut ciphertext = {
            let mut dst = vec![0u8; INPUT.len() + gk.overhead()];
            gk.seal(
                rng,
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

    /// Simple positive test for [`SenderSigningKey`].
    fn test_simple_sender_signing_key_sign<R: Csprng>(rng: &mut R) {
        const RECORD: &[u8] = b"some encoded record";
        const RECORD_NAME: &str = "MessageRecord";

        const VERSION: apq::Version = apq::Version(1);
        const TOPIC: apq::Topic = apq::Topic(4);

        let sign_key = SenderSigningKey::<E>::new(rng);
        let sig = sign_key
            .sign(VERSION, TOPIC, RECORD, RECORD_NAME)
            .expect("unable to create signature");
        sign_key
            .public()
            .verify(VERSION, TOPIC, RECORD, RECORD_NAME, &sig)
            .expect("the signature should be valid");
    }

    /// Simple positive test for encrypting/decrypting
    /// [`TopicKey`]s.
    fn test_simple_seal_topic_key<R: Csprng>(rng: &mut R) {
        let send_sk = SenderSecretKey::<E>::new(rng);
        let send_pk = send_sk.public();
        let recv_sk = ReceiverSecretKey::<E>::new(rng);
        let recv_pk = recv_sk.public();

        const VERSION: apq::Version = apq::Version(1);
        const TOPIC: apq::Topic = apq::Topic(4);

        let want = TopicKey::new(rng, VERSION, TOPIC).expect("unable to create new `TopicKey`");
        let (enc, ciphertext) = recv_pk
            .seal_topic_key(rng, VERSION, TOPIC, &send_sk, &want)
            .expect("unable to encrypt `TopicKey`");
        let got = recv_sk
            .open_topic_key(VERSION, TOPIC, &send_pk, &enc, &ciphertext)
            .expect("unable to decrypt `TopicKey`");
        assert_eq!(want.id(), got.id());
    }

    /// Simple positive test for wrapping [`SenderSecretKey`]s.
    fn test_simple_wrap_user_sender_secret_key<R: Csprng>(rng: &mut R, mut eng: E) {
        let want = SenderSecretKey::new(rng);
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
    fn test_simple_wrap_user_sender_signing_key<R: Csprng>(rng: &mut R, mut eng: E) {
        let want = SenderSigningKey::new(rng);
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
    fn test_simple_wrap_user_receiver_secret_key<R: Csprng>(rng: &mut R, mut eng: E) {
        let want = ReceiverSecretKey::new(rng);
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
    fn test_topic_key_seal<R: Csprng>(rng: &mut R) {
        const INPUT: &[u8] = b"hello, world!";

        let ident = Sender {
            enc_key: SenderSecretKey::<E>::new(&mut Rng).public(),
            sign_key: SenderSigningKey::<E>::new(&mut Rng).public(),
        };

        const VERSION: apq::Version = apq::Version(1);
        const TOPIC: apq::Topic = apq::Topic(4);

        let tk = TopicKey::new(rng, VERSION, TOPIC).expect("unable to create new `TopicKey`");
        let ciphertext = {
            let mut dst = vec![0u8; INPUT.len() + tk.overhead()];
            tk.seal_message(rng, &mut dst, INPUT, VERSION, TOPIC, &ident)
                .expect("should succeed");
            dst
        };
        let plaintext = {
            let mut dst = vec![0u8; ciphertext.len() - tk.overhead()];
            tk.open_message(&mut dst, &ciphertext, VERSION, TOPIC, &ident)
                .expect("should succeed");
            dst
        };
        assert_eq!(&plaintext, INPUT);
    }

    /// Negative test for the wrong [`TopicKey`].
    fn test_topic_key_open_wrong_key<R: Csprng>(rng: &mut R) {
        const INPUT: &[u8] = b"hello, world!";

        let ident = Sender {
            enc_key: SenderSecretKey::<E>::new(&mut Rng).public(),
            sign_key: SenderSigningKey::<E>::new(&mut Rng).public(),
        };

        const VERSION: apq::Version = apq::Version(1);
        const TOPIC: apq::Topic = apq::Topic(4);

        let tk1 = TopicKey::new(rng, VERSION, TOPIC).expect("unable to create new `TopicKey`");
        let tk2 = TopicKey::new(rng, VERSION, TOPIC).expect("unable to create new `TopicKey`");

        let ciphertext = {
            let mut dst = vec![0u8; INPUT.len() + tk1.overhead()];
            tk1.seal_message(rng, &mut dst, INPUT, VERSION, TOPIC, &ident)
                .expect("should succeed");
            dst
        };
        let mut dst = vec![0u8; ciphertext.len() - tk2.overhead()];
        let err = tk2
            .open_message(&mut dst, &ciphertext, VERSION, TOPIC, &ident)
            .expect_err("should have failed");
        assert_eq!(err, Error::Aead(AeadError::Authentication));
    }

    /// Negative test for the wrong [`Context`].
    fn test_topic_key_open_wrong_context<R: Csprng>(rng: &mut R) {
        const INPUT: &[u8] = b"hello, world!";

        let ident = Sender {
            enc_key: SenderSecretKey::<E>::new(&mut Rng).public(),
            sign_key: SenderSigningKey::<E>::new(&mut Rng).public(),
        };
        let wrong_ident = Sender {
            enc_key: SenderSecretKey::<E>::new(&mut Rng).public(),
            sign_key: SenderSigningKey::<E>::new(&mut Rng).public(),
        };

        const VERSION: apq::Version = apq::Version(1);
        const TOPIC: apq::Topic = apq::Topic(4);

        let tk = TopicKey::new(rng, VERSION, TOPIC).expect("unable to create `TopicKey`");
        let ciphertext = {
            let mut dst = vec![0u8; INPUT.len() + tk.overhead()];
            tk.seal_message(rng, &mut dst, INPUT, VERSION, TOPIC, &ident)
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
        should_fail!("wrong version", apq::Version(VERSION.0 + 1), TOPIC, &ident);
        should_fail!("wrong topic", VERSION, apq::Topic(TOPIC.0 + 1), &ident);
        should_fail!("wrong ident", VERSION, TOPIC, &wrong_ident);
    }

    /// Negative test for a modified ciphertext.
    fn test_topic_key_open_bad_ciphertext<R: Csprng>(rng: &mut R) {
        const INPUT: &[u8] = b"hello, world!";

        let ident = Sender {
            enc_key: SenderSecretKey::<E>::new(&mut Rng).public(),
            sign_key: SenderSigningKey::<E>::new(&mut Rng).public(),
        };

        const VERSION: apq::Version = apq::Version(1);
        const TOPIC: apq::Topic = apq::Topic(4);

        let tk = TopicKey::new(rng, VERSION, TOPIC).expect("unable to create `TopicKey`");
        let mut ciphertext = {
            let mut dst = vec![0u8; INPUT.len() + tk.overhead()];
            tk.seal_message(rng, &mut dst, INPUT, VERSION, TOPIC, &ident)
                .expect("should succeed");
            dst
        };

        ciphertext[0] = ciphertext[0].wrapping_add(1);

        let mut dst = vec![0u8; ciphertext.len() - tk.overhead()];
        let err = tk
            .open_message(&mut dst, &ciphertext, VERSION, TOPIC, &ident)
            .expect_err("should have failed");
        assert_eq!(err, Error::Aead(AeadError::Authentication));
    }
}

/// Tests a [`CipherSuite`].
///
/// It uses the various `TestX` types that implement [`Test`].
pub fn test_ciphersuite<S: CipherSuite, R: Csprng>(rng: &mut R) {
    macro_rules! run_tests {
        () => {};
        (
            $name:ident => $($type:ty),+;
            $($tail:tt)*
        ) => {
            $name::<$($type),+>::test(rng, ());
            run_tests!{ $($tail)* }
        };
    }
    run_tests! {
        AeadTest => S::Aead;
        AeadTest => AeadWithDefaults<S::Aead>;
        HashTest => S::Hash;
        HpkeTest => S::Kem, S::Kdf, S::Aead;
        KdfTest => S::Kdf;
        KdfTest => KdfWithDefaults<S::Kdf>;
        MacTest => S::Mac;
        MacTest => MacWithDefaults<S::Mac>;
        SignerTest => S::Signer;
    }
}

/// Tests an [`Aead`].
///
/// This is used by [`test_ciphersuite`], but can also be used
/// manually.
pub struct AeadTest<A: Aead>(PhantomData<A>);

impl<A: Aead> Test for AeadTest<A> {
    fn test<R: Csprng>(_rng: &mut R, _opts: ()) {
        // The minimum key size is 128 bits.
        assert_ge!(A::KEY_SIZE, 16);
        // The minimum tag size is 128 bits.
        assert_ge!(A::TAG_SIZE, 16);
        // Must be at least 2^32-1.
        assert_ge!(A::MAX_PLAINTEXT_SIZE, u64::from(u32::MAX));
        // Must be `TAG_SIZE` bytes larger than the plaintext.
        assert_eq!(
            A::MAX_CIPHERTEXT_SIZE,
            A::MAX_PLAINTEXT_SIZE + A::TAG_SIZE as u64
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

        Self::test_round_trip();
        Self::test_in_place_round_trip();
        Self::test_bad_key();
        Self::test_bad_nonce();
        Self::test_bad_ciphertext();
        Self::test_bad_ad();
        Self::test_bad_tag();

        // TODO(eric): add tests for boundaries. E.g., nonce is
        // too long, tag is too short, etc.
    }
}

impl<A: Aead> AeadTest<A> {
    const GOLDEN: &[u8] = b"hello, world!";
    const AD: &[u8] = b"some additional data";

    /// A round-trip positive test.
    fn test_round_trip() {
        let key =
            A::Key::import(<A::Key as SecretKey>::Data::default()).expect("unable to import key");
        let nonce = A::Nonce::default();
        assert_all_zero!(nonce);

        let ciphertext = {
            let mut dst = vec![0u8; Self::GOLDEN.len() + A::TAG_SIZE];
            A::new(&key)
                .seal(&mut dst[..], nonce.borrow(), Self::GOLDEN, Self::AD)
                .expect("unable to encrypt data");
            dst
        };

        let plaintext = {
            let mut dst = vec![0u8; ciphertext.len() - A::TAG_SIZE];
            A::new(&key)
                .open(&mut dst[..], nonce.borrow(), &ciphertext, Self::AD)
                .expect("unable to decrypt data");
            dst
        };
        assert_eq!(&plaintext, Self::GOLDEN, "round trip test failed");
    }

    /// An in-place round-trip positive test.
    fn test_in_place_round_trip() {
        let key =
            A::Key::import(<A::Key as SecretKey>::Data::default()).expect("unable to import key");
        let nonce = A::Nonce::default();
        assert_all_zero!(nonce);

        let ciphertext = {
            let mut data = vec![0u8; Self::GOLDEN.len() + A::TAG_SIZE];
            let (out, tag) = data.split_at_mut(Self::GOLDEN.len());
            out.clone_from_slice(Self::GOLDEN);
            A::new(&key)
                .seal_in_place(nonce.borrow(), out, tag, Self::AD)
                .expect("unable to encrypt data in-place");
            data
        };

        let plaintext = {
            let mut data = ciphertext.to_vec();
            let (out, tag) = data.split_at_mut(Self::GOLDEN.len());
            A::new(&key)
                .open_in_place(nonce.borrow(), out, tag, Self::AD)
                .expect("unable to decrypt data in-place");
            out.to_vec()
        };
        assert_eq!(&plaintext, Self::GOLDEN, "in-place round trip test failed");
    }

    /// Decryption should fail with an incorrect key.
    fn test_bad_key() {
        let nonce = A::Nonce::default();
        assert_all_zero!(nonce);

        let ciphertext = {
            let mut data = <A::Key as SecretKey>::Data::default();
            data.borrow_mut().fill(b'A');
            let key = A::Key::import(data).expect("unable to import key");

            let mut dst = vec![0u8; Self::GOLDEN.len() + A::TAG_SIZE];
            A::new(&key)
                .seal(&mut dst[..], nonce.borrow(), Self::GOLDEN, Self::AD)
                .expect("unable to encrypt data");
            dst
        };

        let mut data = <A::Key as SecretKey>::Data::default();
        assert_all_zero!(data);
        data.borrow_mut().fill(b'B');
        let key = A::Key::import(data).expect("unable to import key");

        let mut dst = vec![0u8; ciphertext.len() - A::TAG_SIZE];
        let err = A::new(&key)
            .open(&mut dst[..], nonce.borrow(), &ciphertext, Self::AD)
            .expect_err("decryption should have failed due to a different key");
        assert_eq!(err, AeadError::Authentication);
    }

    /// Decryption should fail with an incorrect nonce.
    fn test_bad_nonce() {
        let key =
            A::Key::import(<A::Key as SecretKey>::Data::default()).expect("unable to import key");

        let ciphertext = {
            let mut nonce = A::Nonce::default();
            assert_all_zero!(nonce);
            nonce.borrow_mut().fill(b'A');

            let mut dst = vec![0u8; Self::GOLDEN.len() + A::TAG_SIZE];
            A::new(&key)
                .seal(&mut dst[..], nonce.borrow(), Self::GOLDEN, Self::AD)
                .expect("unable to encrypt data");
            dst
        };

        let mut nonce = A::Nonce::default();
        assert_all_zero!(nonce);
        nonce.borrow_mut().fill(b'B');

        let mut dst = vec![0u8; ciphertext.len() - A::TAG_SIZE];
        let err = A::new(&key)
            .open(&mut dst[..], nonce.borrow(), &ciphertext, Self::AD)
            .expect_err("decryption should have failed due to a modified nonce");
        assert_eq!(err, AeadError::Authentication);
    }

    /// Decryption should fail with a modified AD.
    fn test_bad_ad() {
        let key =
            A::Key::import(<A::Key as SecretKey>::Data::default()).expect("unable to import key");
        let nonce = A::Nonce::default();
        assert_all_zero!(nonce);

        let ciphertext = {
            let mut dst = vec![0u8; Self::GOLDEN.len() + A::TAG_SIZE];
            A::new(&key)
                .seal(&mut dst[..], nonce.borrow(), Self::GOLDEN, Self::AD)
                .expect("unable to encrypt data");
            dst
        };

        let mut dst = vec![0u8; ciphertext.len() - A::TAG_SIZE];
        let err = A::new(&key)
            .open(&mut dst[..], nonce.borrow(), &ciphertext, b"some bad AD")
            .expect_err("decryption should have failed due to a modified AD");
        assert_eq!(err, AeadError::Authentication);
    }

    /// Decryption should fail with a modified ciphertext.
    fn test_bad_ciphertext() {
        let key =
            A::Key::import(<A::Key as SecretKey>::Data::default()).expect("unable to import key");
        let nonce = A::Nonce::default();
        assert_all_zero!(nonce);

        let mut ciphertext = {
            let mut dst = vec![0u8; Self::GOLDEN.len() + A::TAG_SIZE];
            A::new(&key)
                .seal(&mut dst[..], nonce.borrow(), Self::GOLDEN, Self::AD)
                .expect("unable to encrypt data");
            dst
        };

        ciphertext[0] = ciphertext[0].wrapping_add(1);

        let mut dst = vec![0u8; ciphertext.len() - A::TAG_SIZE];
        let err = A::new(&key)
            .open(&mut dst[..], nonce.borrow(), &ciphertext, Self::AD)
            .expect_err("decryption should have failed due to a modified ciphertext");
        assert_eq!(err, AeadError::Authentication);
    }

    /// Decryption should fail with a modified authentication
    /// tag.
    fn test_bad_tag() {
        let key =
            A::Key::import(<A::Key as SecretKey>::Data::default()).expect("unable to import key");
        let nonce = A::Nonce::default();
        assert_all_zero!(nonce);

        let mut ciphertext = {
            let mut dst = vec![0u8; Self::GOLDEN.len() + A::TAG_SIZE];
            A::new(&key)
                .seal(&mut dst[..], nonce.borrow(), Self::GOLDEN, Self::AD)
                .expect("unable to encrypt data");
            dst
        };

        // It's possible that the tag isn't at the end, but for
        // most AEADs it will be.
        let n = ciphertext.len() - 1;
        ciphertext[n] = ciphertext[n].wrapping_add(1);

        let mut dst = vec![0u8; ciphertext.len() - A::TAG_SIZE];
        let err = A::new(&key)
            .open(&mut dst[..], nonce.borrow(), &ciphertext, Self::AD)
            .expect_err("decryption should have failed due to a modified auth tag");
        assert_eq!(err, AeadError::Authentication);
    }
}

/// Tests a [`Hash`].
///
/// This is used by [`test_ciphersuite`], but can also be used
/// manually.
pub struct HashTest<T: Hash>(PhantomData<T>);

impl<T: Hash> Test for HashTest<T> {
    fn test<R: Csprng>(_rng: &mut R, _opts: ()) {
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

/// Tests an [`Hpke`].
pub struct HpkeTest<K: Kem, F: Kdf, A: Aead>(Hpke<K, F, A>);

impl<K: Kem, F: Kdf, A: Aead> Test for HpkeTest<K, F, A> {
    fn test<R: Csprng>(rng: &mut R, _opts: ()) {
        Self::test_round_trip(rng)
    }
}

#[allow(non_snake_case)]
impl<K: Kem, F: Kdf, A: Aead> HpkeTest<K, F, A> {
    fn test_round_trip<R: Csprng>(rng: &mut R) {
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

/// Tests a [`Kdf`].
///
/// This is used by [`test_ciphersuite`], but can also be used
/// manually.
pub struct KdfTest<T: Kdf>(PhantomData<T>);

impl<T: Kdf> Test for KdfTest<T> {
    fn test<R: Csprng>(_rng: &mut R, _opts: ()) {
        // Must support at least 512 bits of output.
        assert_ge!(T::MAX_OUTPUT, 64);

        Self::test_arbitrary_len();
        Self::test_max_output();
    }
}

impl<T: Kdf> KdfTest<T> {
    /// Asserts the following:
    ///
    /// - invoking [`Kdf::extract`] twice results in the same PRK
    /// - invoking [`Kdf::expand`] twice results in the same key
    /// - [`Kdf::extract_and_expand`] is the same as invoking
    /// both [`Kdf::extract`] and [`Kdf::expand`].
    fn check(out1: &mut [u8], out2: &mut [u8], ikm: &[u8], salt: &[u8], info: &[u8]) {
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
    fn test_arbitrary_len() {
        const N: usize = 255 * 64;

        let mut out1 = [0u8; 517];
        let mut out2 = [0u8; 517];

        // Must support arbitrary length IKMs, salts, and infos.
        let ikm = [0u8; N];
        let salt = [0u8; N];
        let info = [0u8; N];
        for i in (0..ikm.len()).step_by(77) {
            Self::check(&mut out1, &mut out2, &ikm[..i], &salt[..i], &info[..i]);
        }
    }

    /// Tests that we can't exceed [`Kdf::MAX_OUTPUT`].
    fn test_max_output() {
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

/// Tests a [`Mac`].
///
/// This is used by [`test_ciphersuite`], but can also be used
/// manually.
pub struct MacTest<T: Mac>(PhantomData<T>)
where
    T::Key: ConstantTimeEq;

impl<T: Mac> Test for MacTest<T>
where
    T::Key: ConstantTimeEq,
{
    fn test<R: Csprng>(rng: &mut R, _opts: ()) {
        Self::test_default(rng);
        Self::test_update(rng);
        Self::test_verify(rng);
        Self::test_different_keys(rng);
        Self::test_different_data(rng);
    }
}

impl<T: Mac> MacTest<T>
where
    T::Key: ConstantTimeEq,
{
    const DATA: &[u8] = b"hello, world!";

    /// Basic positive test.
    fn test_default<R: Csprng>(rng: &mut R) {
        let key = T::Key::new(rng);
        let tag1 = T::mac(&key, Self::DATA);
        let tag2 = T::mac(&key, Self::DATA);
        assert_ct_eq!(tag1, tag2, "tags should be the same");
    }

    /// Tests that [`Mac::update`] is the same as [`Mac::mac`].
    fn test_update<R: Csprng>(rng: &mut R) {
        let key = T::Key::new(rng);
        let tag1 = T::mac(&key, Self::DATA);
        let tag2 = {
            let mut h = T::new(&key);
            for c in Self::DATA {
                h.update(&[*c]);
            }
            h.tag()
        };
        assert_ct_eq!(tag1, tag2, "tags should be the same");
    }

    /// Test [`Mac::verify`].
    fn test_verify<R: Csprng>(rng: &mut R) {
        let key = T::Key::new(rng);
        let tag1 = T::mac(&key, Self::DATA);

        let mut h = T::new(&key);
        for c in Self::DATA {
            h.update(&[*c]);
        }
        h.verify(&tag1).expect("tags should be the same");
    }

    /// Negative tests for different keys.
    fn test_different_keys<R: Csprng>(rng: &mut R) {
        let key1 = T::Key::new(rng);
        let key2 = T::Key::new(rng);
        assert_ct_ne!(key1, key2, "keys should differ");

        let tag1 = T::mac(&key1, Self::DATA);
        let tag2 = T::mac(&key2, Self::DATA);
        assert_ct_ne!(tag1, tag2, "tags should differ");
    }

    /// Negative test for MACs of different data.
    fn test_different_data<R: Csprng>(rng: &mut R) {
        let key = T::Key::new(rng);
        let tag1 = T::mac(&key, b"hello");
        let tag2 = T::mac(&key, b"world");
        assert_ct_ne!(tag1, tag2, "tags should differ");
    }
}

/// Tests a [`Signer`].
///
/// This is used by [`test_ciphersuite`], but can also be used
/// manually.
pub struct SignerTest<T: Signer>(PhantomData<T>);

impl<T: Signer> Test for SignerTest<T> {
    fn test<R: Csprng>(rng: &mut R, _opts: ()) {
        Self::test_default(rng);
        Self::test_pk_eq(rng);
        Self::test_sk_ct_eq(rng);
        Self::test_public(rng);
    }
}

impl<T: Signer> SignerTest<T> {
    /// The base positive test.
    fn test_default<R: Csprng>(rng: &mut R) {
        const MSG: &[u8] = b"hello, world!";
        let sk = T::SigningKey::new(rng);
        let sig = sk.sign(MSG).expect("unable to create signature");
        sk.public()
            .verify(MSG, &sig)
            .expect("unable to verify signature");
    }

    /// Test [`Signer::SigningKey::ct_eq`].
    ///
    /// It also tests [`Signer::SigningKey::import`].
    fn test_sk_ct_eq<R: Csprng>(rng: &mut R) {
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

    /// Test [`Signer::VerifyingKey::eq`].
    ///
    /// It also tests [`Signer::VerifyingKey::import`].
    fn test_pk_eq<R: Csprng>(rng: &mut R) {
        let pk1 = T::SigningKey::new(rng).public();
        let pk2 = T::SigningKey::new(rng).public();

        fn same_key<T: Signer, K: VerifyingKey<T>>(k: K) {
            let pk1 = K::import(k.export()).expect("should be able to import key");
            let pk2 = K::import(k.export()).expect("should be able to import key");
            assert_eq!(pk1, pk2);
        }

        // The two keys should be different.
        assert_ne!(pk1, pk2);
        // But each key should be equal to itself.
        same_key(pk1);
        same_key(pk2);
    }

    /// [`SigningKey::public`] should always return the same key.
    fn test_public<R: Csprng>(rng: &mut R) {
        let sk = T::SigningKey::new(rng);
        assert_eq!(sk.public(), sk.public());
    }
}

/// Tests an [`Aead`] against Project Wycheproof test vectors.
///
/// It tests both `A` and [`AeadWithDefaults<T>`].
///
/// It also performs [`AeadTest`].
pub fn test_aead<A: Aead>(name: aead::TestName) {
    test_aead_inner::<A>(name);
    test_aead_inner::<AeadWithDefaults<A>>(name);
}

fn test_aead_inner<A: Aead>(name: aead::TestName) {
    AeadTest::<A>::test(&mut Rng, ());

    let set = aead::TestSet::load(name).expect("should be able to load tests");
    for g in &set.test_groups {
        if g.nonce_size / 8 != A::NONCE_SIZE
            || g.key_size / 8 != A::KEY_SIZE
            || g.tag_size / 8 != A::TAG_SIZE
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
                let mut dst = vec![0u8; ciphertext.len() - A::TAG_SIZE];
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
                let mut dst = vec![0u8; tc.pt.len() + A::TAG_SIZE];
                aead.seal(&mut dst[..], nonce.borrow(), &tc.pt[..], &tc.aad[..])
                    .unwrap_or_else(|_| panic!("{id}"));
                let tag = dst.split_off(dst.len() - A::TAG_SIZE);
                (dst, tag)
            };
            assert_eq!(ct, *tc.ct, "{id}");
            assert_eq!(tag, *tc.tag, "{id}");

            let (ct, tag) = {
                let mut data = tc.pt.clone().to_vec();
                let mut tag = vec![0u8; A::TAG_SIZE];
                aead.seal_in_place(nonce.borrow(), &mut data, &mut tag[..], &tc.aad[..])
                    .unwrap_or_else(|_| panic!("{id}"));
                (data, tag)
            };
            assert_eq!(ct, *tc.ct, "{id}");
            assert_eq!(tag, *tc.tag, "{id}");
        }
    }
}

/// A [`Aead`] that that uses the default trait methods.
pub struct AeadWithDefaults<T: Aead>(T);

impl<T: Aead> Aead for AeadWithDefaults<T> {
    const ID: AeadId = T::ID;

    type KeySize = T::KeySize;
    const KEY_SIZE: usize = T::KEY_SIZE;

    type NonceSize = T::NonceSize;
    const NONCE_SIZE: usize = T::NONCE_SIZE;

    type TagSize = T::TagSize;
    const TAG_SIZE: usize = T::TAG_SIZE;

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

/// Tests an [`Ecdh`] against Project Wycheproof test vectors.
pub fn test_ecdh<T: Ecdh>(name: ecdh::TestName) {
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

/// A digital signature that can be created without validation.
pub trait UncheckedSignature<T: Signer + ?Sized> {
    /// Creates a signature from its byte representation without
    /// validating it.
    fn from_bytes_unchecked(data: &[u8]) -> Self;
}

/// Tests a [`Signer`] that implements ECDSA (or EdDSA) against
/// Project Wycheproof test vectors.
///
/// It also performs [`SignerTest`].
pub fn test_ecdsa<T: Signer>(name: ecdsa::TestName)
where
    <T as Signer>::Signature: UncheckedSignature<T>,
{
    SignerTest::<T>::test(&mut Rng, ());

    let set = ecdsa::TestSet::load(name).expect("should be able to load tests");
    for g in &set.test_groups {
        for tc in &g.tests {
            let id = tc.tc_id;

            let pk = T::VerifyingKey::import(&g.key.key[..]).unwrap_or_else(|_| panic!("{id}"));
            let sig = {
                // TODO(eric): reject syntactically invalid
                // signatures. I tried doing this based on the
                // test flags, but it had too many false
                // positives. For example, some BER signatures
                // are valid DER signatures.
                T::Signature::from_bytes_unchecked(&tc.sig[..])
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

/// Tests a [`Kdf`] that implements HKDF against Project
/// Wycheproof test vectors.
///
/// It tests both `T` and [`KdfWithDefaults<T>`].
///
/// It also performs [`KdfTest`].
pub fn test_hkdf<T: Kdf>(name: hkdf::TestName) {
    test_hkdf_inner::<T>(name);
    test_hkdf_inner::<KdfWithDefaults<T>>(name);
}

fn test_hkdf_inner<T: Kdf>(name: hkdf::TestName) {
    KdfTest::<T>::test(&mut Rng, ());

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

/// Tests an [`Hpke`] against test vectors.
///
/// It also performs [`HpkeTest`].
#[allow(non_snake_case)]
pub fn test_hpke<K, F, A>(name: hpke::TestName)
where
    K: Kem,
    F: Kdf,
    A: Aead,
{
    HpkeTest::<K, F, A>::test(&mut Rng, ());

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
///
/// It also performs [`MacTest`].
pub fn test_mac<T: Mac>(name: mac::TestName)
where
    T::Key: ConstantTimeEq,
    T::Tag: for<'a> TryFrom<&'a [u8]>,
{
    test_mac_inner::<T>(name);
    test_mac_inner::<MacWithDefaults<T>>(name);
}

fn test_mac_inner<T: Mac>(name: mac::TestName)
where
    T::Key: ConstantTimeEq,
    T::Tag: for<'a> TryFrom<&'a [u8]>,
{
    MacTest::<T>::test(&mut Rng, ());

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
