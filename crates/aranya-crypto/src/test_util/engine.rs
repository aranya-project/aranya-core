//! [`Engine`] tests.

extern crate alloc;

use alloc::vec;
use core::ops::Add;

use generic_array::ArrayLength;
use typenum::{Sum, U64};

use super::{assert_ct_eq, assert_ct_ne};
use crate::{
    aead::{Aead, OpenError},
    afc::{
        AuthData, BidiAuthorSecret, BidiChannel, BidiKeys, BidiSecrets, OpenKey, RawSealKey,
        SealKey, Seq, UniAuthorSecret, UniChannel, UniOpenKey, UniSealKey, UniSecrets,
    },
    apq::{
        EncryptedTopicKey, ReceiverSecretKey, Sender, SenderSecretKey, SenderSigningKey, Topic,
        TopicKey, Version,
    },
    aranya::{Encap, EncryptionKey, IdentityKey, SigningKey as UserSigningKey, UserId},
    csprng::Random,
    engine::Engine,
    error::Error,
    groupkey::{Context, EncryptedGroupKey, GroupKey},
    id::Id,
    CipherSuite,
};

/// Invokes `callback` for each Engine test.
///
/// # Example
///
/// ```
/// use aranya_crypto::{
///     default::{
///         DefaultCipherSuite,
///         DefaultEngine,
///     },
///     Rng,
///     test_engine,
/// };
///
/// # aranya_crypto::__doctest_os_hardware_rand!();
/// macro_rules! run_test {
///     ($test:ident) => {
///         aranya_crypto::test_util::engine::$test(&mut {
///             let (eng, _) = DefaultEngine::<_, DefaultCipherSuite>::from_entropy(Rng);
///             eng
///         });
///     };
/// }
/// aranya_crypto::for_each_engine_test!(run_test);
/// ```
#[macro_export]
macro_rules! for_each_engine_test {
    ($callback:ident) => {
        $crate::__apply! {
            $callback,

            // Aranya

            test_simple_user_signing_key_sign,

            test_simple_seal_group_key,
            test_simple_wrap_group_key,
            test_simple_wrap_user_identity_key,
            test_simple_export_user_identity_key,
            test_simple_identity_key_sign,
            test_simple_wrap_user_signing_key,
            test_simple_export_user_signing_key,
            test_simple_wrap_user_encryption_key,
            test_simple_export_user_encryption_key,

            test_group_key_seal,
            test_group_key_open_wrong_key,
            test_group_key_open_wrong_context,
            test_group_key_open_bad_ciphertext,

            test_encrypted_group_key_encode,

            // APQ

            test_simple_sender_signing_key_sign,

            test_simple_seal_topic_key,
            test_simple_wrap_user_sender_secret_key,
            test_simple_wrap_user_sender_signing_key,
            test_simple_wrap_user_receiver_secret_key,

            test_topic_key_seal,
            test_topic_key_open_wrong_key,
            test_topic_key_open_wrong_context,
            test_topic_key_open_bad_ciphertext,

            // AFC

            test_same_seal_key_open_key,
            test_different_seal_key_open_key,
            test_seal_key_monotonic_seq_number,
            test_seal_key_seq_number_exhausted,
            test_open_key_seq_number_exhausted,
            test_open_key_wrong_seq_number,
            test_open_key_wrong_auth_data,

            test_derive_bidi_keys,
            test_derive_bidi_keys_different_labels,
            test_derive_bidi_keys_different_user_ids,
            test_derive_bidi_keys_different_cmd_ids,
            test_derive_bidi_keys_different_keys,
            test_derive_bidi_keys_same_user_id,
            test_wrap_bidi_author_secret,

            test_derive_uni_key,
            test_derive_uni_key_different_labels,
            test_derive_uni_key_different_user_ids,
            test_derive_uni_key_different_cmd_ids,
            test_derive_uni_key_different_keys,
            test_derive_uni_seal_key_same_user_id,
            test_derive_uni_open_key_same_user_id,
            test_wrap_uni_author_secret,
        }
    };
}
pub use for_each_engine_test;

/// Performs all of the tests inside this module.
///
/// This macro expands into a bunch of individual `#[test]`
/// functions.
///
/// It also performs
/// [`test_ciphersuite`][super::test_ciphersuite].
///
/// # Example
///
/// ```
/// use aranya_crypto::{
///     test_engine,
///     default::{
///         DefaultCipherSuite,
///         DefaultEngine,
///     },
///     Rng,
/// };
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

            $crate::test_engine!(|| -> $engine { $($args)+ });
        }
    };
    (|| -> $engine:ty { $($args:tt)+ }) => {
        $crate::test_util::test_ciphersuite!(ciphersuite, <$engine as $crate::engine::Engine>::CS);

        macro_rules! __engine_test {
            ($test:ident) => {
                #[test]
                fn $test() {
                    $crate::test_util::engine::$test(&mut { $($args)+ });
                }
            };
        }
        $crate::for_each_engine_test!(__engine_test);
    };
}
pub use test_engine;

/// Simple test for [`UserSigningKey`].
pub fn test_simple_user_signing_key_sign<E: Engine>(eng: &mut E) {
    const MSG: &[u8] = b"hello, world!";
    const CONTEXT: &[u8] = b"test_simple_user_signing_key_sign";

    let sign_key = UserSigningKey::<E::CS>::new(eng);

    let sig = sign_key
        .sign(MSG, CONTEXT)
        .expect("unable to create signature");

    sign_key
        .public()
        .expect("sender signing key should be valid")
        .verify(MSG, CONTEXT, &sig)
        .expect("the signature should be valid");

    sign_key
        .public()
        .expect("sender signing key should be valid")
        .verify(MSG, b"wrong context", &sig)
        .expect_err("should fail with wrong context");

    let wrong_sig = sign_key
        .sign(b"different", b"signature")
        .expect("should not fail to create signature");

    sign_key
        .public()
        .expect("sender signing key should be valid")
        .verify(MSG, CONTEXT, &wrong_sig)
        .expect_err("should fail with wrong signature");
}

/// Simple positive test for encrypting/decrypting
/// [`GroupKey`]s.
pub fn test_simple_seal_group_key<E: Engine>(eng: &mut E) {
    let enc_key = EncryptionKey::<E::CS>::new(eng);

    let group = Id::default();
    let want = GroupKey::new(eng);
    let (enc, ciphertext) = enc_key
        .public()
        .expect("public encryption key should be valid")
        .seal_group_key(eng, &want, group)
        .expect("unable to encrypt `GroupKey`");
    let got = enc_key
        .open_group_key(&enc, ciphertext, group)
        .expect("unable to decrypt `GroupKey`");
    assert_eq!(want.id(), got.id());
}

/// Simple positive test for wrapping [`GroupKey`]s.
pub fn test_simple_wrap_group_key<E: Engine>(eng: &mut E) {
    let want = GroupKey::new(eng);
    let bytes = postcard::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `GroupKey`"),
    )
    .expect("should be able to encode wrapped `GroupKey`");
    let wrapped =
        postcard::from_bytes(&bytes).expect("should be able to decode encoded wrapped `GroupKey`");
    let got: GroupKey<E::CS> = eng
        .unwrap(&wrapped)
        .expect("should be able to unwrap `GroupKey`");
    assert_eq!(want.id(), got.id());
}

/// Simple positive test for wrapping [`IdentityKey`]s.
pub fn test_simple_wrap_user_identity_key<E: Engine>(eng: &mut E) {
    let want = IdentityKey::new(eng);
    let bytes = postcard::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `IdentityKey`"),
    )
    .expect("should be able to encode wrapped `IdentityKey`");
    let wrapped = postcard::from_bytes(&bytes)
        .expect("should be able to decode encoded wrapped `IdentityKey`");
    let got: IdentityKey<E::CS> = eng
        .unwrap(&wrapped)
        .expect("should be able to unwrap `IdentityKey`");
    assert_eq!(want.id(), got.id());
}

/// Simple positive test for exporting the public half of
/// [`IdentityKey`]s.
pub fn test_simple_export_user_identity_key<E: Engine>(eng: &mut E) {
    let want = IdentityKey::<E::CS>::new(eng)
        .public()
        .expect("identity key should be valid");
    let bytes =
        postcard::to_allocvec(&want).expect("should be able to encode an `IdentityVerifyingKey`");
    let got =
        postcard::from_bytes(&bytes).expect("should be able to decode an `IdentityVerifyingKey`");
    assert_eq!(want, got);
}

/// Simple test for [`IdentityKey`].
/// Creates a signature over `msg` bound to some `context`.
/// `msg` must NOT be pre-hashed.
pub fn test_simple_identity_key_sign<E: Engine>(eng: &mut E) {
    let sign_key = IdentityKey::<E::CS>::new(eng);

    const MESSAGE: &[u8] = b"hello, world!";
    const CONTEXT: &[u8] = b"test_simple_identity_key_sign";

    let sig = sign_key
        .sign(MESSAGE, CONTEXT)
        .expect("should not fail to create signature");

    sign_key
        .public()
        .expect("sender signing key should be valid")
        .verify(MESSAGE, CONTEXT, &sig)
        .expect("should not fail with correct signature");

    sign_key
        .public()
        .expect("sender signing key should be valid")
        .verify(MESSAGE, b"wrong context", &sig)
        .expect_err("should fail with wrong context");

    let wrong_sig = sign_key
        .sign(b"different", b"signature")
        .expect("should not fail to create signature");

    sign_key
        .public()
        .expect("sender signing key should be valid")
        .verify(MESSAGE, CONTEXT, &wrong_sig)
        .expect_err("should fail with wrong signature");
}

/// Simple positive test for wrapping [`UserSigningKey`]s.
pub fn test_simple_wrap_user_signing_key<E: Engine>(eng: &mut E) {
    let want = UserSigningKey::new(eng);
    let bytes = postcard::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `UserSigningKey`"),
    )
    .expect("should be able to encode wrapped `UserSigningKey`");
    let wrapped = postcard::from_bytes(&bytes)
        .expect("should be able to decode encoded wrapped `UserSigningKey`");
    let got: UserSigningKey<E::CS> = eng
        .unwrap(&wrapped)
        .expect("should be able to unwrap `UserSigningKey`");
    assert_eq!(want.id(), got.id());
}

/// Simple positive test for exporting the public half of
/// [`UserSigningKey`]s.
pub fn test_simple_export_user_signing_key<E: Engine>(eng: &mut E) {
    let want = UserSigningKey::<E::CS>::new(eng)
        .public()
        .expect("user signing key should be valid");
    let bytes = postcard::to_allocvec(&want).expect("should be able to encode an `VerifyingKey`");
    let got = postcard::from_bytes(&bytes).expect("should be able to decode an `VerifyingKey`");
    assert_eq!(want, got);
}

/// Simple positive test for wrapping [`EncryptionKey`]s.
pub fn test_simple_wrap_user_encryption_key<E: Engine>(eng: &mut E) {
    let want = EncryptionKey::new(eng);
    let bytes = postcard::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `EncryptionKey`"),
    )
    .expect("should be able to encode wrapped `EncryptionKey`");
    let wrapped = postcard::from_bytes(&bytes)
        .expect("should be able to decode encoded wrapped `EncryptionKey`");
    let got: EncryptionKey<E::CS> = eng
        .unwrap(&wrapped)
        .expect("should be able to unwrap `EncryptionKey`");
    assert_eq!(want.id(), got.id());
}

/// Simple positive test for exporting the public half of
/// [`EncryptionKey`]s.
pub fn test_simple_export_user_encryption_key<E: Engine>(eng: &mut E) {
    let want = EncryptionKey::<E::CS>::new(eng)
        .public()
        .expect("encryption public key should be valid");
    let bytes =
        postcard::to_allocvec(&want).expect("should be able to encode an `EncryptionPublicKey`");
    let got =
        postcard::from_bytes(&bytes).expect("should be able to decode an `EncryptionPublicKey`");
    assert_eq!(want, got);
}

/// Simple positive test for encryption using a [`GroupKey`].
pub fn test_group_key_seal<E: Engine>(eng: &mut E) {
    const INPUT: &[u8] = b"hello, world!";

    let author_sign_pk = UserSigningKey::<E::CS>::new(eng)
        .public()
        .expect("author signing key should be valid");

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
                author_sign_pk: &author_sign_pk,
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
                author_sign_pk: &author_sign_pk,
            },
        )
        .expect("should succeed");
        dst
    };
    assert_eq!(&plaintext, INPUT);
}

/// Negative test for the wrong [`GroupKey`].
pub fn test_group_key_open_wrong_key<E: Engine>(eng: &mut E) {
    const INPUT: &[u8] = b"hello, world!";

    let author_sign_pk = UserSigningKey::<E::CS>::new(eng)
        .public()
        .expect("author signing key should be valid");

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
                author_sign_pk: &author_sign_pk,
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
                author_sign_pk: &author_sign_pk,
            },
        )
        .expect_err("should have failed");
    assert_eq!(err, Error::Open(OpenError::Authentication));
}

/// Negative test for the wrong [`Context`].
pub fn test_group_key_open_wrong_context<E: Engine>(eng: &mut E) {
    const INPUT: &[u8] = b"hello, world!";

    let author_pk1 = UserSigningKey::<E::CS>::new(eng)
        .public()
        .expect("author 1 signing key should be valid");
    let author_pk2 = UserSigningKey::<E::CS>::new(eng)
        .public()
        .expect("author 2 signing key should be valid");

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
                author_sign_pk: &author_pk1,
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
            assert_eq!(err, Error::Open(OpenError::Authentication), $msg);
        };
    }
    should_fail!(
        "wrong label",
        Context {
            label: "wrong label",
            parent: Id::default(),
            author_sign_pk: &author_pk1,
        }
    );
    should_fail!(
        "wrong `parent`",
        Context {
            label: "some label",
            parent: [1u8; 64].into(),
            author_sign_pk: &author_pk1,
        }
    );
    should_fail!(
        "wrong `author`",
        Context {
            label: "some label",
            parent: Id::default(),
            author_sign_pk: &author_pk2,
        }
    );
}

/// Negative test for a modified ciphertext.
pub fn test_group_key_open_bad_ciphertext<E: Engine>(eng: &mut E) {
    const INPUT: &[u8] = b"hello, world!";

    let author_sign_pk = UserSigningKey::<E::CS>::new(eng)
        .public()
        .expect("author signing key should be valid");

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
                author_sign_pk: &author_sign_pk,
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
                author_sign_pk: &author_sign_pk,
            },
        )
        .expect_err("should have failed");
    assert_eq!(err, Error::Open(OpenError::Authentication));
}

/// Test encoding/decoding [`EncryptedGroupKey`].
pub fn test_encrypted_group_key_encode<E: Engine>(eng: &mut E)
where
    <<E::CS as CipherSuite>::Aead as Aead>::Overhead: Add<U64>,
    Sum<<<E::CS as CipherSuite>::Aead as Aead>::Overhead, U64>: ArrayLength,
{
    let enc_key = EncryptionKey::<E::CS>::new(eng);

    let group = Id::default();
    let want = GroupKey::new(eng);
    let (enc, ciphertext) = enc_key
        .public()
        .expect("encryption public key should be valid")
        .seal_group_key(eng, &want, group)
        .expect("unable to encrypt `GroupKey`");
    let enc = Encap::<E::CS>::from_bytes(enc.as_bytes()).expect("should be able to decode `Encap`");
    let ciphertext: EncryptedGroupKey<E::CS> = postcard::from_bytes(
        &postcard::to_allocvec(&ciphertext).expect("should be able to encode `EncryptedGroupKey`"),
    )
    .expect("should be able to decode `EncryptedGroupKey`");
    let got = enc_key
        .open_group_key(&enc, ciphertext, group)
        .expect("unable to decrypt `GroupKey`");
    assert_eq!(want.id(), got.id());
}

/// Simple test for [`SenderSigningKey`].
/// Creates a signature over an encoded record.
pub fn test_simple_sender_signing_key_sign<E: Engine>(eng: &mut E)
where
    <<E::CS as CipherSuite>::Aead as Aead>::Overhead: Add<U64>,
    Sum<<<E::CS as CipherSuite>::Aead as Aead>::Overhead, U64>: ArrayLength,
{
    const RECORD: &[u8] = b"some encoded record";

    const VERSION: Version = Version::new(1);
    let topic = Topic::new("SomeTopic");

    let sign_key = SenderSigningKey::<E::CS>::new(eng);
    let sig = sign_key
        .sign(VERSION, &topic, RECORD)
        .expect("unable to create signature");

    sign_key
        .public()
        .expect("sender signing key should be valid")
        .verify(VERSION, &topic, RECORD, &sig)
        .expect("the signature should be valid");

    sign_key
        .public()
        .expect("sender signing key should be valid")
        .verify(Version::new(VERSION.as_u32() + 1), &topic, RECORD, &sig)
        .expect_err("should fail: wrong version");

    sign_key
        .public()
        .expect("sender signing key should be valid")
        .verify(VERSION, &Topic::new("WrongTopic"), RECORD, &sig)
        .expect_err("should fail: wrong topic");

    sign_key
        .public()
        .expect("sender signing key should be valid")
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
        .expect("sender signing key should be valid")
        .verify(VERSION, &topic, RECORD, &wrong_sig)
        .expect_err("should fail: wrong signature");
}

/// Simple positive test for encrypting/decrypting
/// [`TopicKey`]s.
pub fn test_simple_seal_topic_key<E: Engine>(eng: &mut E)
where
    <<E::CS as CipherSuite>::Aead as Aead>::Overhead: Add<U64>,
    Sum<<<E::CS as CipherSuite>::Aead as Aead>::Overhead, U64>: ArrayLength,
{
    let send_sk = SenderSecretKey::<E::CS>::new(eng);
    let send_pk = send_sk.public().expect("sender public key should be valid");
    let recv_sk = ReceiverSecretKey::<E::CS>::new(eng);
    let recv_pk = recv_sk
        .public()
        .expect("receiver public key should be valid");

    const VERSION: Version = Version::new(1);
    let topic = Topic::new("SomeTopic");

    let want = TopicKey::new(eng, VERSION, &topic).expect("unable to create new `TopicKey`");
    let (enc, ciphertext) = recv_pk
        .seal_topic_key(eng, VERSION, &topic, &send_sk, &want)
        .expect("unable to encrypt `TopicKey`");
    let enc = Encap::<E::CS>::from_bytes(enc.as_bytes()).expect("should be able to decode `Encap`");
    let ciphertext = EncryptedTopicKey::<E::CS>::from_bytes(ciphertext.as_bytes())
        .expect("should be able to decode `EncryptedTopicKey`");
    let got = recv_sk
        .open_topic_key(VERSION, &topic, &send_pk, &enc, &ciphertext)
        .expect("unable to decrypt `TopicKey`");
    assert_eq!(want.id(), got.id());
}

/// Simple positive test for wrapping [`SenderSecretKey`]s.
pub fn test_simple_wrap_user_sender_secret_key<E: Engine>(eng: &mut E) {
    let want = SenderSecretKey::new(eng);
    let bytes = postcard::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `SenderSecretKey`"),
    )
    .expect("should be able to encode wrapped `SenderSecretKey`");
    let wrapped = postcard::from_bytes(&bytes)
        .expect("should be able to decode encoded wrapped `SenderSecretKey`");
    let got: SenderSecretKey<E::CS> = eng
        .unwrap(&wrapped)
        .expect("should be able to unwrap `SenderSecretKey`");
    assert_eq!(want.id(), got.id());
}

/// Simple positive test for wrapping [`SenderSigningKey`]s.
pub fn test_simple_wrap_user_sender_signing_key<E: Engine>(eng: &mut E) {
    let want = SenderSigningKey::new(eng);
    let bytes = postcard::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `SenderSigningKey`"),
    )
    .expect("should be able to encode wrapped `SenderSigningKey`");
    let wrapped = postcard::from_bytes(&bytes)
        .expect("should be able to decode encoded wrapped `SenderSigningKey`");
    let got: SenderSigningKey<E::CS> = eng
        .unwrap(&wrapped)
        .expect("should be able to unwrap `SenderSigningKey`");
    assert_eq!(want.id(), got.id());
}

/// Simple positive test for wrapping [`ReceiverSecretKey`]s.
pub fn test_simple_wrap_user_receiver_secret_key<E: Engine>(eng: &mut E) {
    let want = ReceiverSecretKey::new(eng);
    let bytes = postcard::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `ReceiverSecretKey`"),
    )
    .expect("should be able to encode wrapped `ReceiverSecretKey`");
    let wrapped = postcard::from_bytes(&bytes)
        .expect("should be able to decode encoded wrapped `ReceiverSecretKey`");
    let got: ReceiverSecretKey<E::CS> = eng
        .unwrap(&wrapped)
        .expect("should be able to unwrap `ReceiverSecretKey`");
    assert_eq!(want.id(), got.id());
}

/// Simple positive test for encryption using a [`TopicKey`].
pub fn test_topic_key_seal<E: Engine>(eng: &mut E) {
    const INPUT: &[u8] = b"hello, world!";

    let ident = Sender {
        enc_key: &SenderSecretKey::<E::CS>::new(eng)
            .public()
            .expect("sender public encryption key should be valid"),
        sign_key: &SenderSigningKey::<E::CS>::new(eng)
            .public()
            .expect("sender public signing key should be valid"),
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
pub fn test_topic_key_open_wrong_key<E: Engine>(eng: &mut E) {
    const INPUT: &[u8] = b"hello, world!";

    let ident = Sender {
        enc_key: &SenderSecretKey::<E::CS>::new(eng)
            .public()
            .expect("sender public encryption key should be valid"),
        sign_key: &SenderSigningKey::<E::CS>::new(eng)
            .public()
            .expect("sender public signing key should be valid"),
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
    assert_eq!(err, Error::Open(OpenError::Authentication));
}

/// Negative test for the wrong [`Context`].
pub fn test_topic_key_open_wrong_context<E: Engine>(eng: &mut E) {
    const INPUT: &[u8] = b"hello, world!";

    let ident = Sender {
        enc_key: &SenderSecretKey::<E::CS>::new(eng)
            .public()
            .expect("sender public encryption key should be valid"),
        sign_key: &SenderSigningKey::<E::CS>::new(eng)
            .public()
            .expect("sender public signing key should be valid"),
    };
    let wrong_ident = Sender {
        enc_key: &SenderSecretKey::<E::CS>::new(eng)
            .public()
            .expect("sender public encryption key should be valid"),
        sign_key: &SenderSigningKey::<E::CS>::new(eng)
            .public()
            .expect("sender public signing key should be valid"),
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
            assert_eq!(err, Error::Open(OpenError::Authentication), $msg);
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
pub fn test_topic_key_open_bad_ciphertext<E: Engine>(eng: &mut E) {
    const INPUT: &[u8] = b"hello, world!";

    let ident = Sender {
        enc_key: &SenderSecretKey::<E::CS>::new(eng)
            .public()
            .expect("sender public encryption key should be valid"),
        sign_key: &SenderSigningKey::<E::CS>::new(eng)
            .public()
            .expect("sender public signing key should be valid"),
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
    assert_eq!(err, Error::Open(OpenError::Authentication));
}

/// Checks that `open` can decrypt ciphertexts from `seal`.
fn assert_same_afc_keys<CS: CipherSuite>(seal: &mut SealKey<CS>, open: &OpenKey<CS>) {
    const GOLDEN: &str = "hello, world!";
    const AD: AuthData = AuthData {
        version: 1,
        label: 2,
    };

    let (ciphertext, seq) = {
        let mut dst = vec![0u8; GOLDEN.len() + SealKey::<CS>::OVERHEAD];
        let seq = seal
            .seal(&mut dst, GOLDEN.as_bytes(), &AD)
            .expect("should be able to encrypt plaintext");
        (dst, seq)
    };

    let mut plaintext = vec![0u8; ciphertext.len() - OpenKey::<CS>::OVERHEAD];
    open.open(&mut plaintext, &ciphertext, &AD, seq)
        .expect("decryption failed; keys differ");

    assert_eq!(
        GOLDEN.as_bytes(),
        &plaintext,
        "`OpenKey` produced incorrect plaintext"
    );
}

/// Checks that `open` cannot decrypt ciphertexts from
/// `seal`.
///
/// If `seal` is `None` then a random key will be used.
fn assert_different_afc_keys<E: Engine>(
    eng: &mut E,
    seal: Option<SealKey<E::CS>>,
    open: &OpenKey<E::CS>,
) {
    const GOLDEN: &str = "hello, world!";
    const AD: AuthData = AuthData {
        version: 1,
        label: 2,
    };

    let (ciphertext, seq) = {
        let mut dst = vec![0u8; GOLDEN.len() + SealKey::<E::CS>::OVERHEAD];
        let seq = seal
            .unwrap_or_else(|| {
                SealKey::from_raw(&Random::random(eng), Seq::ZERO)
                    .expect("should be able to generate random `SealKey`")
            })
            .seal(&mut dst, GOLDEN.as_bytes(), &AD)
            .expect("should be able to encrypt plaintext");
        (dst, seq)
    };

    let mut plaintext = vec![0u8; ciphertext.len() - OpenKey::<E::CS>::OVERHEAD];
    let err = open
        .open(&mut plaintext, &ciphertext, &AD, seq)
        .expect_err("should not be able to decrypt ciphertext with mismatched keys");
    assert_eq!(
        err,
        crate::afc::OpenError::Authentication,
        "should have received `Authentication` error"
    );
}

/// A simple positive test for [`SealKey`] and [`OpenKey`].
pub fn test_same_seal_key_open_key<E: Engine>(eng: &mut E) {
    let raw: RawSealKey<E::CS> = Random::random(eng);
    let mut seal =
        SealKey::<E::CS>::from_raw(&raw, Seq::ZERO).expect("should be able to create `SealKey`");
    let open = OpenKey::<E::CS>::from_raw(&raw.into()).expect("should be able to create `OpenKey`");
    assert_same_afc_keys(&mut seal, &open);
}

/// A simple negative test for [`SealKey`] and [`OpenKey`].
pub fn test_different_seal_key_open_key<E: Engine>(eng: &mut E) {
    let seal = SealKey::from_raw(&Random::random(eng), Seq::ZERO)
        .expect("should be able to create `SealKey`");
    let open = OpenKey::from_raw(&Random::random(eng)).expect("should be able to create `OpenKey`");
    assert_different_afc_keys(eng, Some(seal), &open);
    assert_different_afc_keys(eng, None, &open);
}

/// Tests that [`SealKey`]'s sequence number monotonically
/// advances by one each time.
pub fn test_seal_key_monotonic_seq_number<E: Engine>(eng: &mut E) {
    let mut seal = SealKey::<E::CS>::from_raw(&Random::random(eng), Seq::ZERO)
        .expect("should be able to create `SealKey`");

    const GOLDEN: &str = "hello, world!";
    const AD: AuthData = AuthData {
        version: 1,
        label: 2,
    };
    let mut dst = vec![0u8; GOLDEN.len() + SealKey::<E::CS>::OVERHEAD];
    // The upper bound is arbitrary. We obviously cannot test
    // all 2^61-1 integers.
    for idx in 0..u16::MAX {
        let seq = seal
            .seal(&mut dst, GOLDEN.as_bytes(), &AD)
            .expect("should be able to encrypt plaintext");
        assert_eq!(seq, Seq::new(u64::from(idx)));
    }
}

/// Tests that [`SealKey`] refuses to encrypt when its
/// sequence number has been exhausted.
pub fn test_seal_key_seq_number_exhausted<E: Engine>(eng: &mut E) {
    let max = Seq::max::<<<E::CS as CipherSuite>::Aead as Aead>::NonceSize>();
    // Start at one before the max.
    let start = Seq::new(max - 1);
    let mut seal = SealKey::<E::CS>::from_raw(&Random::random(eng), start)
        .expect("should be able to create `SealKey`");

    const GOLDEN: &str = "hello, world!";
    const AD: AuthData = AuthData {
        version: 1,
        label: 2,
    };
    let mut dst = vec![0u8; GOLDEN.len() + SealKey::<E::CS>::OVERHEAD];

    // The first encryption should succeed since seq < max.
    let seq = seal
        .seal(&mut dst, GOLDEN.as_bytes(), &AD)
        .expect("should be able to encrypt plaintext");
    assert_eq!(seq, Seq::new(max - 1));

    // All encryptions afterward should fail since seq >=
    // max.
    let err = seal
        .seal(&mut dst, GOLDEN.as_bytes(), &AD)
        .expect_err("sequence counter should be exhausted");
    assert_eq!(err, crate::afc::SealError::MessageLimitReached);
}

/// Tests that [`OpenKey`] refuses to decrypt when the
/// sequence number has been exhausted.
pub fn test_open_key_seq_number_exhausted<E: Engine>(eng: &mut E) {
    let raw: RawSealKey<E::CS> = Random::random(eng);
    let mut seal =
        SealKey::<E::CS>::from_raw(&raw, Seq::ZERO).expect("should be able to create `SealKey`");
    let open = OpenKey::from_raw(&raw.into()).expect("should be able to create `OpenKey`");
    assert_same_afc_keys(&mut seal, &open);

    const GOLDEN: &str = "hello, world!";
    const AD: AuthData = AuthData {
        version: 1,
        label: 2,
    };
    let mut ciphertext = vec![0u8; GOLDEN.len() + SealKey::<E::CS>::OVERHEAD];
    let mut plaintext = vec![0u8; ciphertext.len() - OpenKey::<E::CS>::OVERHEAD];

    // `OpenKey` should reject the sequence number before
    // attempting to decrypt the ciphertext, but start with
    // a valid ciphertext anyway.
    seal.seal(&mut ciphertext, GOLDEN.as_bytes(), &AD)
        .expect("should be able to encrypt plaintext");

    let exhausted_seq = Seq::new(Seq::max::<<<E::CS as CipherSuite>::Aead as Aead>::NonceSize>());
    // Decryption should fail since seq >= max.
    let err = open
        .open(&mut plaintext, &ciphertext, &AD, exhausted_seq)
        .expect_err("should not be able to decrypt ciphertext with exhausted seq number");
    assert_eq!(
        err,
        crate::afc::OpenError::MessageLimitReached,
        "should have received `MessageLimitReached` error"
    );
}

/// Tests that [`OpenKey`]'s fails when the incorrect
/// sequence number is provided.
pub fn test_open_key_wrong_seq_number<E: Engine>(eng: &mut E) {
    let raw: RawSealKey<E::CS> = Random::random(eng);
    let mut seal =
        SealKey::<E::CS>::from_raw(&raw, Seq::ZERO).expect("should be able to create `SealKey`");
    let open = OpenKey::from_raw(&raw.into()).expect("should be able to create `OpenKey`");
    assert_same_afc_keys(&mut seal, &open);

    const GOLDEN: &str = "hello, world!";
    const AD: AuthData = AuthData {
        version: 1,
        label: 2,
    };
    let mut ciphertext = vec![0u8; GOLDEN.len() + SealKey::<E::CS>::OVERHEAD];
    let mut plaintext = vec![0u8; ciphertext.len() - OpenKey::<E::CS>::OVERHEAD];
    for _ in 0..100 {
        let seq = seal
            .seal(&mut ciphertext, GOLDEN.as_bytes(), &AD)
            .expect("should be able to encrypt plaintext");

        let wrong_seq = Seq::new(seq.to_u64() + 1);
        let err = open
            .open(&mut plaintext, &ciphertext, &AD, wrong_seq)
            .expect_err("should not be able to decrypt ciphertext with the wrong seq number");
        assert_eq!(
            err,
            crate::afc::OpenError::Authentication,
            "should have received `Authentication` error"
        );
    }
}

/// Tests that [`OpenKey`]'s fails when the incorrect
/// [`AuthData`] is provided.
pub fn test_open_key_wrong_auth_data<E: Engine>(eng: &mut E) {
    let raw: RawSealKey<E::CS> = Random::random(eng);
    let mut seal =
        SealKey::<E::CS>::from_raw(&raw, Seq::ZERO).expect("should be able to create `SealKey`");
    let open = OpenKey::from_raw(&raw.into()).expect("should be able to create `OpenKey`");
    assert_same_afc_keys(&mut seal, &open);

    const GOLDEN: &str = "hello, world!";
    const GOOD_AD: AuthData = AuthData {
        version: 1,
        label: 2,
    };
    const WRONG_AD: AuthData = AuthData {
        version: 3,
        label: 4,
    };

    let mut ciphertext = vec![0u8; GOLDEN.len() + SealKey::<E::CS>::OVERHEAD];
    let seq = seal
        .seal(&mut ciphertext, GOLDEN.as_bytes(), &GOOD_AD)
        .expect("should be able to encrypt plaintext");

    let mut plaintext = vec![0u8; ciphertext.len() - OpenKey::<E::CS>::OVERHEAD];
    let err = open
        .open(&mut plaintext, &ciphertext, &WRONG_AD, seq)
        .expect_err("should not be able to decrypt ciphertext with the wrong `AuthData`");
    assert_eq!(
        err,
        crate::afc::OpenError::Authentication,
        "should have received `Authentication` error"
    );
}

/// Checks that `lhs` and `rhs` match; that is, `lhs`'s
/// encryption key should match `rhs`'s decryption key and
/// vice versa.
fn assert_bidi_keys_match<CS: CipherSuite>(lhs: BidiKeys<CS>, rhs: BidiKeys<CS>) {
    // We should never generate duplicate keys.
    assert_ct_ne!(lhs.seal_key(), rhs.seal_key(), "duplicate `SealKey`");
    assert_ct_ne!(lhs.open_key(), rhs.open_key(), "duplicate `OpenKey`");

    // Simple test: they should not have the same bytes.
    {
        let (lhs_seal, lhs_open) = lhs.as_raw_keys();
        let (rhs_seal, rhs_open) = rhs.as_raw_keys();
        assert_ct_eq!(lhs_seal.to_testing_key(), rhs_open.to_testing_key());
        assert_ct_eq!(lhs_open.to_testing_key(), rhs_seal.to_testing_key());
    }

    // Double check that the `to_testing_key` impls are
    // correct: actually perform encryption, which should
    // fail.
    let (mut lhs_seal, lhs_open) = lhs
        .into_keys()
        .expect("should be able to create bidi keys tuple");
    let (mut rhs_seal, rhs_open) = rhs
        .into_keys()
        .expect("should be able to create bidi keys tuple");
    assert_same_afc_keys(&mut lhs_seal, &rhs_open);
    assert_same_afc_keys(&mut rhs_seal, &lhs_open);
}

/// Checks that `lhs` and `rhs` do _not_ match.
fn assert_bidi_keys_mismatch<E: Engine>(eng: &mut E, lhs: BidiKeys<E::CS>, rhs: BidiKeys<E::CS>) {
    // We should never generate duplicate keys.
    assert_ct_ne!(lhs.seal_key(), rhs.seal_key(), "duplicate `SealKey`");
    assert_ct_ne!(lhs.open_key(), rhs.open_key(), "duplicate `OpenKey`");

    let (lhs_seal, lhs_open) = lhs
        .into_keys()
        .expect("should be able to create bidi keys tuple");
    let (rhs_seal, rhs_open) = rhs
        .into_keys()
        .expect("should be able to create bidi keys tuple");
    assert_different_afc_keys(eng, Some(lhs_seal), &rhs_open);
    assert_different_afc_keys(eng, Some(rhs_seal), &lhs_open);
}

/// A simple positive test for deriving [`BidiKeys`].
pub fn test_derive_bidi_keys<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let label = 123;
    let ch1 = BidiChannel {
        parent_cmd_id: Id::random(eng),
        our_sk: &sk1,
        our_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("sender id should be valid"),
        their_pk: &sk2
            .public()
            .expect("receiver public encryption key should be valid"),
        their_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("receiver id should be valid"),
        label,
    };
    let ch2 = BidiChannel {
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        our_id: ch1.their_id,
        their_pk: &sk1
            .public()
            .expect("receiver public encryption key should be valid"),
        their_id: ch1.our_id,
        label,
    };
    assert_eq!(ch1.author_info(), ch2.peer_info());
    assert_eq!(ch1.peer_info(), ch2.author_info());

    let BidiSecrets { author, peer } =
        BidiSecrets::new(eng, &ch1).expect("unable to create `BidiSecrets`");
    let ck1 =
        BidiKeys::from_author_secret(&ch1, author).expect("unable to decrypt author `BidiKeys`");
    let ck2 = BidiKeys::from_peer_encap(&ch2, peer).expect("unable to decrypt peer `BidiKeys`");

    // `ck1` and `ck2` should be the reverse of each other.
    assert_bidi_keys_match(ck1, ck2);
}

/// Different labels should create different [`BidiKeys`].
pub fn test_derive_bidi_keys_different_labels<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = BidiChannel {
        parent_cmd_id: Id::random(eng),
        our_sk: &sk1,
        our_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("sender id should be valid"),
        their_pk: &sk2.public().expect("encryption public key should be valid"),
        their_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("receiver id should be valid"),
        label: 123,
    };
    let ch2 = BidiChannel {
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        our_id: ch1.their_id,
        their_pk: &sk1
            .public()
            .expect("receiver public encryption key should be valid"),
        their_id: ch1.our_id,
        label: 456,
    };
    assert_ne!(ch1.author_info(), ch2.peer_info());
    assert_ne!(ch1.peer_info(), ch2.author_info());

    let BidiSecrets { author, peer } =
        BidiSecrets::new(eng, &ch1).expect("unable to create `BidiSecrets`");
    let ck1 = BidiKeys::from_author_secret(&ch1, author).expect("unable to decrypt `BidiKeys`");
    let ck2 = BidiKeys::from_peer_encap(&ch2, peer).expect("unable to decrypt `BidiKeys`");

    // The labels are different, so the keys should also be
    // different.
    assert_bidi_keys_mismatch(eng, ck1, ck2);
}

/// Different UserIDs should create different
/// [`BidiKeys`].
///
/// E.g., derive(label, u1, u2, c1) != derive(label, u2, u3, c1).
pub fn test_derive_bidi_keys_different_user_ids<E: Engine>(eng: &mut E) {
    let label = 123;
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = BidiChannel {
        parent_cmd_id: Id::random(eng),
        our_sk: &sk1,
        our_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("sender id should be valid"),
        their_pk: &sk2
            .public()
            .expect("receiver public encryption key should be valid"),
        their_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("receiver id should be valid"),
        label,
    };
    let ch2 = BidiChannel {
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        our_id: ch1.their_id,
        their_pk: &sk1
            .public()
            .expect("receiver public encryption key should be valid"),
        their_id: UserId::random(eng),
        label,
    };
    assert_ne!(ch1.author_info(), ch2.peer_info());
    assert_ne!(ch1.peer_info(), ch2.author_info());

    let BidiSecrets { author, peer } =
        BidiSecrets::new(eng, &ch1).expect("unable to create `BidiSecrets`");
    let ck1 =
        BidiKeys::from_author_secret(&ch1, author).expect("unable to decrypt author `BidiKeys`");
    let ck2 = BidiKeys::from_peer_encap(&ch2, peer).expect("unable to decrypt peer `BidiKeys`");

    assert_bidi_keys_mismatch(eng, ck1, ck2);
}

/// Different command IDs should create different
/// [`BidiKeys`].
///
/// E.g., derive(label, u1, u2, c1) != derive(label, u2, u1, c2).
pub fn test_derive_bidi_keys_different_cmd_ids<E: Engine>(eng: &mut E) {
    let label = 123;
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = BidiChannel {
        parent_cmd_id: Id::random(eng),
        our_sk: &sk1,
        our_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("sender id should be valid"),
        their_pk: &sk2
            .public()
            .expect("receiver public encryption key should be valid"),
        their_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("receiver id should be valid"),
        label,
    };
    let ch2 = BidiChannel {
        parent_cmd_id: Id::random(eng),
        our_sk: &sk2,
        our_id: ch1.their_id,
        their_pk: &sk1
            .public()
            .expect("receiver public encryption key should be valid"),
        their_id: ch1.our_id,
        label,
    };
    assert_ne!(ch1.author_info(), ch2.peer_info());
    assert_ne!(ch1.peer_info(), ch2.author_info());

    let BidiSecrets { author, peer } =
        BidiSecrets::new(eng, &ch1).expect("unable to create `BidiSecrets`");
    let ck1 =
        BidiKeys::from_author_secret(&ch1, author).expect("unable to decrypt author `BidiKeys`");
    let ck2 = BidiKeys::from_peer_encap(&ch2, peer).expect("unable to decrypt peer `BidiKeys`");

    assert_bidi_keys_mismatch(eng, ck1, ck2);
}

/// Different encryption keys should create different
/// [`BidiKeys`].
///
/// E.g., derive(label, u1, u2, c1) != derive(label, u2, u1, c2).
pub fn test_derive_bidi_keys_different_keys<E: Engine>(eng: &mut E) {
    let label = 123;
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = BidiChannel {
        parent_cmd_id: Id::random(eng),
        our_sk: &sk1,
        our_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("sender id should be valid"),
        their_pk: &sk2
            .public()
            .expect("receiver public encryption key should be valid"),
        their_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("receiver id should be valid"),
        label,
    };
    let ch2 = BidiChannel {
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        our_id: ch1.their_id,
        their_pk: &EncryptionKey::<E::CS>::new(eng)
            .public()
            .expect("receiver id should be valid"),
        their_id: ch1.our_id,
        label,
    };
    // The info params are equal here because they do not
    // include the encryption key IDs. Those are mixed in
    // using HPKE's auth mode.
    assert_eq!(ch1.author_info(), ch2.peer_info());
    assert_eq!(ch1.peer_info(), ch2.author_info());

    let BidiSecrets { author, peer } =
        BidiSecrets::new(eng, &ch1).expect("unable to create `BidiSecrets`");
    let ck1 =
        BidiKeys::from_author_secret(&ch1, author).expect("unable to decrypt author `BidiKeys`");
    let ck2 = BidiKeys::from_peer_encap(&ch2, peer).expect("unable to decrypt peer `BidiKeys`");

    assert_bidi_keys_mismatch(eng, ck1, ck2);
}

/// It is an error to use the same `UserId` when deriving
/// [`BidiKeys`].
pub fn test_derive_bidi_keys_same_user_id<E: Engine>(eng: &mut E) {
    let label = 123;
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let mut ch1 = BidiChannel {
        parent_cmd_id: Id::random(eng),
        our_sk: &sk1,
        our_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("sender id should be valid"),
        their_pk: &sk2
            .public()
            .expect("receiver public encryption key should be valid"),
        their_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("receiver id should be valid"),
        label,
    };
    let mut ch2 = BidiChannel {
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        our_id: ch1.their_id,
        their_pk: &EncryptionKey::<E::CS>::new(eng)
            .public()
            .expect("receiver public encryption key should be valid"),
        their_id: ch1.our_id,
        label,
    };

    let BidiSecrets { peer, .. } = {
        let prev = ch1.our_id;
        ch1.our_id = ch1.their_id;

        let err = BidiSecrets::new(eng, &ch1)
            .err()
            .expect("should not be able to create `BidiSecrets`");
        assert_eq!(err, Error::same_user_id());

        ch1.our_id = prev;
        BidiSecrets::new(eng, &ch1).expect("unable to create `BidiSecrets`")
    };

    ch2.their_id = ch2.our_id;
    let err = BidiKeys::from_peer_encap(&ch2, peer)
        .err()
        .expect("should not be able to decrypt `BidiKeys`");
    assert_eq!(err, Error::same_user_id());
}

/// Simple positive test for wrapping [`BidiAuthorSecret`]s.
pub fn test_wrap_bidi_author_secret<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::new(eng);
    let sk2 = EncryptionKey::new(eng);
    let ch = BidiChannel {
        parent_cmd_id: Id::random(eng),
        our_sk: &sk1,
        our_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("sender id should be valid"),
        their_pk: &sk2
            .public()
            .expect("receiver public encryption key should be valid"),
        their_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("receiver id should be valid"),
        label: 123,
    };

    let BidiSecrets { author: want, .. } =
        BidiSecrets::new(eng, &ch).expect("unable to create `BidiSecrets`");
    let bytes = postcard::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `BidiAuthorSecret`"),
    )
    .expect("should be able to encode wrapped `BidiAuthorSecret`");
    let wrapped = postcard::from_bytes(&bytes)
        .expect("should be able to decode encoded wrapped `BidiAuthorSecret`");
    let got: BidiAuthorSecret<E::CS> = eng
        .unwrap(&wrapped)
        .expect("should be able to unwrap `BidiAuthorSecret`");
    assert_ct_eq!(want, got);
}

/// Checks that `seal` and `open` are the same key.
fn assert_same_uni_key<CS: CipherSuite>(seal: UniSealKey<CS>, open: UniOpenKey<CS>) {
    // Simple test: they should have the same bytes.
    {
        let seal = seal.as_raw_key();
        let open = open.as_raw_key();
        assert_ct_eq!(seal.to_testing_key(), open.to_testing_key());
    }

    // Double check that the `to_testing_key` impls are
    // correct: actually perform encryption.
    let mut seal = seal.into_key().expect("should have got `SealKey`");
    let open = open.into_key().expect("should have got `OpenKey`");
    assert_same_afc_keys(&mut seal, &open);
}

/// Checks that `seal` and `open` are different keys.
fn assert_different_uni_key<E: Engine>(
    eng: &mut E,
    seal: UniSealKey<E::CS>,
    open: UniOpenKey<E::CS>,
) {
    // Simple test: they should not have the same bytes.
    {
        let seal = seal.as_raw_key();
        let open = open.as_raw_key();
        assert_ct_ne!(seal.to_testing_key(), open.to_testing_key());
    }

    // Double check that the `to_testing_key` impls are
    // correct: actually perform encryption, which should
    // fail.
    //
    // First check with `open` with `seal`.
    let seal = seal.into_key().expect("should have got `SealKey`");
    let open = open.into_key().expect("should have got `OpenKey`");
    assert_different_afc_keys(eng, Some(seal), &open);

    // Then also check `open` with a randomly generated key.
    assert_different_afc_keys(eng, None, &open);
}

/// A simple positive test for deriving [`UniSealKey`] and
/// [`UniOpenKey`].
pub fn test_derive_uni_key<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let label = 123;
    let ch1 = UniChannel {
        parent_cmd_id: Id::random(eng),
        our_sk: &sk1,
        their_pk: &sk2
            .public()
            .expect("receiver public encryption key should be valid"),
        seal_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("seal id should be valid"),
        open_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("open id should be valid"),
        label,
    };
    let ch2 = UniChannel {
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        their_pk: &sk1
            .public()
            .expect("receiver public encryption key should be valid"),
        seal_id: ch1.seal_id,
        open_id: ch1.open_id,
        label,
    };
    assert_eq!(ch1.info(), ch2.info());

    let UniSecrets { author, peer } =
        UniSecrets::new(eng, &ch1).expect("unable to create `UniSecrets`");
    let ck1 = UniSealKey::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `UniSealKey`");
    let ck2 = UniOpenKey::from_peer_encap(&ch2, peer).expect("unable to decrypt peer `UniOpenKey`");

    assert_same_uni_key(ck1, ck2);
}

/// Different labels should create different [`UniSealKey`]
/// and [`UniOpenKey`]s.
pub fn test_derive_uni_key_different_labels<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = UniChannel {
        parent_cmd_id: Id::random(eng),
        our_sk: &sk1,
        their_pk: &sk2
            .public()
            .expect("receiver public encryption key should be valid"),
        seal_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("seal id should be valid"),
        open_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("open id should be valid"),
        label: 123,
    };
    let ch2 = UniChannel {
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        their_pk: &sk1
            .public()
            .expect("receiver public encryption key should be valid"),
        seal_id: ch1.seal_id,
        open_id: ch1.open_id,
        label: 456,
    };
    assert_ne!(ch1.info(), ch2.info());

    let UniSecrets { author, peer } =
        UniSecrets::new(eng, &ch1).expect("unable to create `UniSecrets`");
    let ck1 = UniSealKey::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `UniSealKey`");
    let ck2 = UniOpenKey::from_peer_encap(&ch2, peer).expect("unable to decrypt peer `UniOpenKey`");

    assert_different_uni_key(eng, ck1, ck2);
}

/// Different UserIDs should create different
/// [`UniSealKey`] and [`UniOpenKey`]s.
///
/// E.g., derive(label, u1, u2, c1) != derive(label, u2, u3, c1).
pub fn test_derive_uni_key_different_user_ids<E: Engine>(eng: &mut E) {
    let label = 123;
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = UniChannel {
        parent_cmd_id: Id::random(eng),
        our_sk: &sk1,
        their_pk: &sk2
            .public()
            .expect("receiver public encryption key should be valid"),
        seal_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("seal id should be valid"),
        open_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("open id should be valid"),
        label,
    };
    let ch2 = UniChannel {
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        their_pk: &sk1
            .public()
            .expect("receiver public encryption key should be valid"),
        seal_id: ch1.seal_id,
        open_id: UserId::random(eng),
        label,
    };
    assert_ne!(ch1.info(), ch2.info());

    let UniSecrets { author, peer } =
        UniSecrets::new(eng, &ch1).expect("unable to create `UniSecrets`");
    let ck1 = UniSealKey::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `UniSealKey`");
    let ck2 = UniOpenKey::from_peer_encap(&ch2, peer).expect("unable to decrypt peer `UniOpenKey`");

    assert_different_uni_key(eng, ck1, ck2);
}

/// Different command IDs should create different
/// [`UniSealKey`] and [`UniOpenKey`]s.
///
/// E.g., derive(label, u1, u2, c1) != derive(label, u2, u1, c2).
pub fn test_derive_uni_key_different_cmd_ids<E: Engine>(eng: &mut E) {
    let label = 123;
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = UniChannel {
        parent_cmd_id: Id::random(eng),
        our_sk: &sk1,
        their_pk: &sk2
            .public()
            .expect("receiver public encryption key should be valid"),
        seal_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("seal id should be valid"),
        open_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("open id should be valid"),
        label,
    };
    let ch2 = UniChannel {
        parent_cmd_id: Id::random(eng),
        our_sk: &sk2,
        their_pk: &sk1
            .public()
            .expect("receiver public encryption key should be valid"),
        seal_id: ch1.seal_id,
        open_id: ch1.open_id,
        label,
    };
    assert_ne!(ch1.info(), ch2.info());

    let UniSecrets { author, peer } =
        UniSecrets::new(eng, &ch1).expect("unable to create `UniSecrets`");
    let ck1 = UniSealKey::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `UniSealKey`");
    let ck2 = UniOpenKey::from_peer_encap(&ch2, peer).expect("unable to decrypt peer `UniOpenKey`");

    assert_different_uni_key(eng, ck1, ck2);
}

/// Different encryption keys should create different
/// [`UniSealKey`] and [`UniOpenKey`]s.
///
/// E.g., derive(label, u1, u2, c1) != derive(label, u2, u1, c2).
pub fn test_derive_uni_key_different_keys<E: Engine>(eng: &mut E) {
    let label = 123;
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = UniChannel {
        parent_cmd_id: Id::random(eng),
        our_sk: &sk1,
        their_pk: &sk2
            .public()
            .expect("receiver public encryption key should be valid"),
        seal_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("seal id should be valid"),
        open_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("open id should be valid"),
        label,
    };
    let ch2 = UniChannel {
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        their_pk: &EncryptionKey::<E::CS>::new(eng)
            .public()
            .expect("receiver public encryption key should be valid"),
        seal_id: ch1.seal_id,
        open_id: ch1.open_id,
        label,
    };

    let UniSecrets { author, peer } =
        UniSecrets::new(eng, &ch1).expect("unable to create `UniSecrets`");
    let ck1 = UniSealKey::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `UniSealKey`");
    let ck2 = UniOpenKey::from_peer_encap(&ch2, peer).expect("unable to decrypt peer `UniOpenKey`");

    assert_different_uni_key(eng, ck1, ck2);
}

/// It is an error to use the same `UserId` when deriving
/// [`UniSealKey`]s.
pub fn test_derive_uni_seal_key_same_user_id<E: Engine>(eng: &mut E) {
    let label = 123;
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let mut ch1 = UniChannel {
        parent_cmd_id: Id::random(eng),
        our_sk: &sk1,
        their_pk: &sk2
            .public()
            .expect("receiver public encryption key should be valid"),
        seal_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("seal id should be valid"),
        open_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("open id should be valid"),
        label,
    };
    let mut ch2 = UniChannel {
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        their_pk: &EncryptionKey::<E::CS>::new(eng)
            .public()
            .expect("receiver public encryption key should be valid"),
        seal_id: ch1.seal_id,
        open_id: ch1.open_id,
        label,
    };
    assert_eq!(ch1.info(), ch2.info());

    let UniSecrets { peer, .. } = {
        let prev = ch1.seal_id;
        ch1.seal_id = ch1.open_id;

        let err = UniSecrets::new(eng, &ch1)
            .err()
            .expect("should not be able to create `UniSecrets`");
        assert_eq!(err, Error::same_user_id());

        ch1.seal_id = prev;
        UniSecrets::new(eng, &ch1).expect("unable to create `UniSecrets`")
    };

    ch2.seal_id = ch2.open_id;
    let err = UniSealKey::from_peer_encap(&ch2, peer)
        .err()
        .expect("should not be able to decrypt `UniSealKey`");
    assert_eq!(err, Error::same_user_id());
}

/// It is an error to use the same `UserId` when deriving
/// [`UniOpenKey`]s.
pub fn test_derive_uni_open_key_same_user_id<E: Engine>(eng: &mut E) {
    let label = 123;
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let mut ch1 = UniChannel {
        parent_cmd_id: Id::random(eng),
        our_sk: &sk1,
        their_pk: &sk2
            .public()
            .expect("receiver public encryption key should be valid"),
        seal_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("seal id should be valid"),
        open_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("open id should be valid"),
        label,
    };
    let mut ch2 = UniChannel {
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        their_pk: &EncryptionKey::<E::CS>::new(eng)
            .public()
            .expect("receiver public encryption key should be valid"),
        seal_id: ch1.seal_id,
        open_id: ch1.open_id,
        label,
    };
    assert_eq!(ch1.info(), ch2.info());

    let UniSecrets { peer, .. } = {
        let prev = ch1.seal_id;
        ch1.seal_id = ch1.open_id;

        let err = UniSecrets::new(eng, &ch1)
            .err()
            .expect("should not be able to create `UniSecrets`");
        assert_eq!(err, Error::same_user_id());

        ch1.seal_id = prev;
        UniSecrets::new(eng, &ch1).expect("unable to create `UniSecrets`")
    };

    ch2.seal_id = ch2.open_id;
    let err = UniOpenKey::from_peer_encap(&ch2, peer)
        .err()
        .expect("should not be able to decrypt `UniOpenKey`");
    assert_eq!(err, Error::same_user_id());
}

/// Simple positive test for wrapping [`UniAuthorSecret`]s.
pub fn test_wrap_uni_author_secret<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::new(eng);
    let sk2 = EncryptionKey::new(eng);
    let ch = UniChannel {
        parent_cmd_id: Id::random(eng),
        our_sk: &sk1,
        their_pk: &sk2
            .public()
            .expect("receiver public encryption key should be valid"),
        seal_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("seal id should be valid"),
        open_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("open id should be valid"),
        label: 123,
    };

    let UniSecrets { author: want, .. } =
        UniSecrets::new(eng, &ch).expect("unable to create `UniSecrets`");
    let bytes = postcard::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `UniAuthorSecret`"),
    )
    .expect("should be able to encode wrapped `UniAuthorSecret`");
    let wrapped = postcard::from_bytes(&bytes)
        .expect("should be able to decode encoded wrapped `UniAuthorSecret`");
    let got: UniAuthorSecret<E::CS> = eng
        .unwrap(&wrapped)
        .expect("should be able to unwrap `UniAuthorSecret`");
    assert_ct_eq!(want, got);
}
