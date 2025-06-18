//! [`Engine`] tests.

extern crate alloc;

use alloc::{collections::BTreeSet, vec};
use core::ops::Add;

use spideroak_crypto::{
    aead::{Aead, OpenError},
    csprng::Random,
    generic_array::ArrayLength,
    hpke::HpkeError,
    typenum::{Sum, U64},
};

use super::{assert_ct_eq, assert_ct_ne};
use crate::{
    afc,
    apq::{
        EncryptedTopicKey, ReceiverSecretKey, Sender, SenderSecretKey, SenderSigningKey, Topic,
        TopicKey, Version,
    },
    aqc,
    aranya::{Encap, EncryptionKey, IdentityKey, SigningKey as DeviceSigningKey},
    ciphersuite::CipherSuite,
    engine::Engine,
    error::Error,
    groupkey::{Context, EncryptedGroupKey, GroupKey},
    id::{Id, Identified as _},
    policy::{GroupId, PolicyId},
    tls,
    util::cbor,
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

            test_simple_device_signing_key_sign,

            test_simple_seal_group_key,
            test_simple_wrap_group_key,
            test_simple_wrap_device_identity_key,
            test_simple_export_device_identity_key,
            test_simple_identity_key_sign,
            test_simple_wrap_device_signing_key,
            test_simple_export_device_signing_key,
            test_simple_wrap_device_encryption_key,
            test_simple_export_device_encryption_key,

            test_group_key_seal,
            test_group_key_open_wrong_key,
            test_group_key_open_wrong_context,
            test_group_key_open_bad_ciphertext,

            test_encrypted_group_key_encode,

            // APQ

            test_simple_sender_signing_key_sign,

            test_simple_seal_topic_key,
            test_simple_wrap_device_sender_secret_key,
            test_simple_wrap_device_sender_signing_key,
            test_simple_wrap_device_receiver_secret_key,

            test_topic_key_seal,
            test_topic_key_open_wrong_key,
            test_topic_key_open_wrong_context,
            test_topic_key_open_bad_ciphertext,

            // AFC

            test_afc_same_seal_key_open_key,
            test_afc_different_seal_key_open_key,
            test_afc_seal_key_monotonic_seq_number,
            test_afc_seal_key_seq_number_exhausted,
            test_afc_open_key_seq_number_exhausted,
            test_afc_open_key_wrong_seq_number,
            test_afc_open_key_wrong_auth_data,

            test_afc_derive_bidi_keys,
            test_afc_derive_bidi_keys_different_labels,
            test_afc_derive_bidi_keys_different_device_ids,
            test_afc_derive_bidi_keys_different_cmd_ids,
            test_afc_derive_bidi_keys_different_keys,
            test_afc_derive_bidi_keys_same_device_id,
            test_afc_wrap_bidi_author_secret,

            test_afc_derive_uni_key,
            test_afc_derive_uni_key_different_labels,
            test_afc_derive_uni_key_different_device_ids,
            test_afc_derive_uni_key_different_cmd_ids,
            test_afc_derive_uni_key_different_keys,
            test_afc_derive_uni_seal_key_same_device_id,
            test_afc_derive_uni_open_key_same_device_id,
            test_afc_wrap_uni_author_secret,

            // AQC

            test_aqc_derive_bidi_psk,
            test_aqc_derive_bidi_psk_different_labels,
            test_aqc_derive_bidi_psk_different_device_ids,
            test_aqc_derive_bidi_psk_different_cmd_ids,
            test_aqc_derive_bidi_psk_different_keys,
            test_aqc_derive_bidi_psk_different_cipher_suites,
            test_aqc_derive_bidi_psk_same_device_id,
            test_aqc_derive_bidi_psk_psk_too_short,
            test_aqc_derive_bidi_psk_psk_too_long,
            test_aqc_wrap_bidi_author_secret,

            test_aqc_derive_uni_psk,
            test_aqc_derive_uni_psk_different_labels,
            test_aqc_derive_uni_psk_different_device_ids,
            test_aqc_derive_uni_psk_different_cmd_ids,
            test_aqc_derive_uni_psk_different_keys,
            test_aqc_derive_uni_send_psk_same_device_id,
            test_aqc_derive_uni_recv_psk_same_device_id,
            test_aqc_derive_uni_send_psk_psk_too_short,
            test_aqc_derive_uni_recv_psk_psk_too_short,
            test_aqc_derive_uni_send_psk_psk_too_long,
            test_aqc_derive_uni_recv_psk_psk_too_long,
            test_aqc_wrap_uni_author_secret,

            // TLS

            test_tls_psk_different_suites,
            test_tls_psk_different_policy_ids,
            test_tls_psk_seed_simple_wrap,
            test_tls_psk_seed_seal_open,
            test_tls_psk_seed_open_wrong_peer_pk,
            test_tls_psk_seed_open_wrong_sk,
            test_tls_psk_seed_open_wrong_group,
            test_tls_psk_seed_open_wrong_ciphertext,
            test_tls_psk_seed_open_wrong_tag,
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

/// Simple test for [`DeviceSigningKey`].
pub fn test_simple_device_signing_key_sign<E: Engine>(eng: &mut E) {
    const MSG: &[u8] = b"hello, world!";
    const CONTEXT: &[u8] = b"test_simple_device_signing_key_sign";

    let sign_key = DeviceSigningKey::<E::CS>::new(eng);

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
    let bytes = cbor::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `GroupKey`"),
    )
    .expect("should be able to encode wrapped `GroupKey`");
    let wrapped =
        cbor::from_bytes(&bytes).expect("should be able to decode encoded wrapped `GroupKey`");
    let got: GroupKey<E::CS> = eng
        .unwrap(&wrapped)
        .expect("should be able to unwrap `GroupKey`");
    assert_eq!(want.id(), got.id());
}

/// Simple positive test for wrapping [`IdentityKey`]s.
pub fn test_simple_wrap_device_identity_key<E: Engine>(eng: &mut E) {
    let want = IdentityKey::new(eng);
    let bytes = cbor::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `IdentityKey`"),
    )
    .expect("should be able to encode wrapped `IdentityKey`");
    let wrapped =
        cbor::from_bytes(&bytes).expect("should be able to decode encoded wrapped `IdentityKey`");
    let got: IdentityKey<E::CS> = eng
        .unwrap(&wrapped)
        .expect("should be able to unwrap `IdentityKey`");
    assert_eq!(want.id(), got.id());
}

/// Simple positive test for exporting the public half of
/// [`IdentityKey`]s.
pub fn test_simple_export_device_identity_key<E: Engine>(eng: &mut E) {
    let want = IdentityKey::<E::CS>::new(eng)
        .public()
        .expect("identity key should be valid");
    let bytes =
        cbor::to_allocvec(&want).expect("should be able to encode an `IdentityVerifyingKey`");
    let got = cbor::from_bytes(&bytes).expect("should be able to decode an `IdentityVerifyingKey`");
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

/// Simple positive test for wrapping [`DeviceSigningKey`]s.
pub fn test_simple_wrap_device_signing_key<E: Engine>(eng: &mut E) {
    let want = DeviceSigningKey::new(eng);
    let bytes = cbor::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `DeviceSigningKey`"),
    )
    .expect("should be able to encode wrapped `DeviceSigningKey`");
    let wrapped = cbor::from_bytes(&bytes)
        .expect("should be able to decode encoded wrapped `DeviceSigningKey`");
    let got: DeviceSigningKey<E::CS> = eng
        .unwrap(&wrapped)
        .expect("should be able to unwrap `DeviceSigningKey`");
    assert_eq!(want.id(), got.id());
}

/// Simple positive test for exporting the public half of
/// [`DeviceSigningKey`]s.
pub fn test_simple_export_device_signing_key<E: Engine>(eng: &mut E) {
    let want = DeviceSigningKey::<E::CS>::new(eng)
        .public()
        .expect("device signing key should be valid");
    let bytes = cbor::to_allocvec(&want).expect("should be able to encode an `VerifyingKey`");
    let got = cbor::from_bytes(&bytes).expect("should be able to decode an `VerifyingKey`");
    assert_eq!(want, got);
}

/// Simple positive test for wrapping [`EncryptionKey`]s.
pub fn test_simple_wrap_device_encryption_key<E: Engine>(eng: &mut E) {
    let want = EncryptionKey::new(eng);
    let bytes = cbor::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `EncryptionKey`"),
    )
    .expect("should be able to encode wrapped `EncryptionKey`");
    let wrapped =
        cbor::from_bytes(&bytes).expect("should be able to decode encoded wrapped `EncryptionKey`");
    let got: EncryptionKey<E::CS> = eng
        .unwrap(&wrapped)
        .expect("should be able to unwrap `EncryptionKey`");
    assert_eq!(want.id(), got.id());
}

/// Simple positive test for exporting the public half of
/// [`EncryptionKey`]s.
pub fn test_simple_export_device_encryption_key<E: Engine>(eng: &mut E) {
    let want = EncryptionKey::<E::CS>::new(eng)
        .public()
        .expect("encryption public key should be valid");
    let bytes =
        cbor::to_allocvec(&want).expect("should be able to encode an `EncryptionPublicKey`");
    let got = cbor::from_bytes(&bytes).expect("should be able to decode an `EncryptionPublicKey`");
    assert_eq!(want, got);
}

/// Simple positive test for encryption using a [`GroupKey`].
pub fn test_group_key_seal<E: Engine>(eng: &mut E) {
    const INPUT: &[u8] = b"hello, world!";

    let author_sign_pk = DeviceSigningKey::<E::CS>::new(eng)
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

    let author_sign_pk = DeviceSigningKey::<E::CS>::new(eng)
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

    let author_pk1 = DeviceSigningKey::<E::CS>::new(eng)
        .public()
        .expect("author 1 signing key should be valid");
    let author_pk2 = DeviceSigningKey::<E::CS>::new(eng)
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
            parent: [1u8; 32].into(),
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

    let author_sign_pk = DeviceSigningKey::<E::CS>::new(eng)
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
    let ciphertext: EncryptedGroupKey<E::CS> = cbor::from_bytes(
        &cbor::to_allocvec(&ciphertext).expect("should be able to encode `EncryptedGroupKey`"),
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
pub fn test_simple_wrap_device_sender_secret_key<E: Engine>(eng: &mut E) {
    let want = SenderSecretKey::new(eng);
    let bytes = cbor::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `SenderSecretKey`"),
    )
    .expect("should be able to encode wrapped `SenderSecretKey`");
    let wrapped = cbor::from_bytes(&bytes)
        .expect("should be able to decode encoded wrapped `SenderSecretKey`");
    let got: SenderSecretKey<E::CS> = eng
        .unwrap(&wrapped)
        .expect("should be able to unwrap `SenderSecretKey`");
    assert_eq!(want.id(), got.id());
}

/// Simple positive test for wrapping [`SenderSigningKey`]s.
pub fn test_simple_wrap_device_sender_signing_key<E: Engine>(eng: &mut E) {
    let want = SenderSigningKey::new(eng);
    let bytes = cbor::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `SenderSigningKey`"),
    )
    .expect("should be able to encode wrapped `SenderSigningKey`");
    let wrapped = cbor::from_bytes(&bytes)
        .expect("should be able to decode encoded wrapped `SenderSigningKey`");
    let got: SenderSigningKey<E::CS> = eng
        .unwrap(&wrapped)
        .expect("should be able to unwrap `SenderSigningKey`");
    assert_eq!(want.id(), got.id());
}

/// Simple positive test for wrapping [`ReceiverSecretKey`]s.
pub fn test_simple_wrap_device_receiver_secret_key<E: Engine>(eng: &mut E) {
    let want = ReceiverSecretKey::new(eng);
    let bytes = cbor::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `ReceiverSecretKey`"),
    )
    .expect("should be able to encode wrapped `ReceiverSecretKey`");
    let wrapped = cbor::from_bytes(&bytes)
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
fn assert_same_afc_keys<CS: CipherSuite>(seal: &mut afc::SealKey<CS>, open: &afc::OpenKey<CS>) {
    const GOLDEN: &str = "hello, world!";
    const AD: afc::AuthData = afc::AuthData {
        version: 1,
        label: 2,
    };

    let (ciphertext, seq) = {
        let mut dst = vec![0u8; GOLDEN.len() + afc::SealKey::<CS>::OVERHEAD];
        let seq = seal
            .seal(&mut dst, GOLDEN.as_bytes(), &AD)
            .expect("should be able to encrypt plaintext");
        (dst, seq)
    };

    let mut plaintext = vec![0u8; ciphertext.len() - afc::OpenKey::<CS>::OVERHEAD];
    open.open(&mut plaintext, &ciphertext, &AD, seq)
        .expect("decryption failed; keys differ");

    assert_eq!(
        GOLDEN.as_bytes(),
        &plaintext,
        "`afc::OpenKey` produced incorrect plaintext"
    );
}

/// Checks that `open` cannot decrypt ciphertexts from
/// `seal`.
///
/// If `seal` is `None` then a random key will be used.
fn assert_different_afc_keys<E: Engine>(
    eng: &mut E,
    seal: Option<afc::SealKey<E::CS>>,
    open: &afc::OpenKey<E::CS>,
) {
    const GOLDEN: &str = "hello, world!";
    const AD: afc::AuthData = afc::AuthData {
        version: 1,
        label: 2,
    };

    let (ciphertext, seq) = {
        let mut dst = vec![0u8; GOLDEN.len() + afc::SealKey::<E::CS>::OVERHEAD];
        let seq = seal
            .unwrap_or_else(|| {
                afc::SealKey::from_raw(&Random::random(eng), afc::Seq::ZERO)
                    .expect("should be able to generate random `afc::SealKey`")
            })
            .seal(&mut dst, GOLDEN.as_bytes(), &AD)
            .expect("should be able to encrypt plaintext");
        (dst, seq)
    };

    let mut plaintext = vec![0u8; ciphertext.len() - afc::OpenKey::<E::CS>::OVERHEAD];
    let err = open
        .open(&mut plaintext, &ciphertext, &AD, seq)
        .expect_err("should not be able to decrypt ciphertext with mismatched keys");
    assert_eq!(
        err,
        afc::OpenError::Authentication,
        "should have received `Authentication` error"
    );
}

/// A simple positive test for [`afc::SealKey`] and [`afc::OpenKey`].
pub fn test_afc_same_seal_key_open_key<E: Engine>(eng: &mut E) {
    let raw: afc::RawSealKey<E::CS> = Random::random(eng);
    let mut seal = afc::SealKey::<E::CS>::from_raw(&raw, afc::Seq::ZERO)
        .expect("should be able to create `afc::SealKey`");
    let open = afc::OpenKey::<E::CS>::from_raw(&raw.into())
        .expect("should be able to create `afc::OpenKey`");
    assert_same_afc_keys(&mut seal, &open);
}

/// A simple negative test for [`afc::SealKey`] and [`afc::OpenKey`].
pub fn test_afc_different_seal_key_open_key<E: Engine>(eng: &mut E) {
    let seal = afc::SealKey::from_raw(&Random::random(eng), afc::Seq::ZERO)
        .expect("should be able to create `afc::SealKey`");
    let open = afc::OpenKey::from_raw(&Random::random(eng))
        .expect("should be able to create `afc::OpenKey`");
    assert_different_afc_keys(eng, Some(seal), &open);
    assert_different_afc_keys(eng, None, &open);
}

/// Tests that [`afc::SealKey`]'s sequence number monotonically
/// advances by one each time.
pub fn test_afc_seal_key_monotonic_seq_number<E: Engine>(eng: &mut E) {
    let mut seal = afc::SealKey::<E::CS>::from_raw(&Random::random(eng), afc::Seq::ZERO)
        .expect("should be able to create `afc::SealKey`");

    const GOLDEN: &str = "hello, world!";
    const AD: afc::AuthData = afc::AuthData {
        version: 1,
        label: 2,
    };
    let mut dst = vec![0u8; GOLDEN.len() + afc::SealKey::<E::CS>::OVERHEAD];
    // The upper bound is arbitrary. We obviously cannot test
    // all 2^61-1 integers.
    for idx in 0..u16::MAX {
        let seq = seal
            .seal(&mut dst, GOLDEN.as_bytes(), &AD)
            .expect("should be able to encrypt plaintext");
        assert_eq!(seq, afc::Seq::new(u64::from(idx)));
    }
}

/// Tests that [`afc::SealKey`] refuses to encrypt when its
/// sequence number has been exhausted.
pub fn test_afc_seal_key_seq_number_exhausted<E: Engine>(eng: &mut E) {
    let max = afc::Seq::max::<<<E::CS as CipherSuite>::Aead as Aead>::NonceSize>();
    // Start at one before the max.
    let start = afc::Seq::new(max - 1);
    let mut seal = afc::SealKey::<E::CS>::from_raw(&Random::random(eng), start)
        .expect("should be able to create `afc::SealKey`");

    const GOLDEN: &str = "hello, world!";
    const AD: afc::AuthData = afc::AuthData {
        version: 1,
        label: 2,
    };
    let mut dst = vec![0u8; GOLDEN.len() + afc::SealKey::<E::CS>::OVERHEAD];

    // The first encryption should succeed since seq < max.
    let seq = seal
        .seal(&mut dst, GOLDEN.as_bytes(), &AD)
        .expect("should be able to encrypt plaintext");
    assert_eq!(seq, afc::Seq::new(max - 1));

    // All encryptions afterward should fail since seq >=
    // max.
    let err = seal
        .seal(&mut dst, GOLDEN.as_bytes(), &AD)
        .expect_err("sequence counter should be exhausted");
    assert_eq!(err, afc::SealError::MessageLimitReached);
}

/// Tests that [`afc::OpenKey`] refuses to decrypt when the
/// sequence number has been exhausted.
pub fn test_afc_open_key_seq_number_exhausted<E: Engine>(eng: &mut E) {
    let raw: afc::RawSealKey<E::CS> = Random::random(eng);
    let mut seal = afc::SealKey::<E::CS>::from_raw(&raw, afc::Seq::ZERO)
        .expect("should be able to create `afc::SealKey`");
    let open =
        afc::OpenKey::from_raw(&raw.into()).expect("should be able to create `afc::OpenKey`");
    assert_same_afc_keys(&mut seal, &open);

    const GOLDEN: &str = "hello, world!";
    const AD: afc::AuthData = afc::AuthData {
        version: 1,
        label: 2,
    };
    let mut ciphertext = vec![0u8; GOLDEN.len() + afc::SealKey::<E::CS>::OVERHEAD];
    let mut plaintext = vec![0u8; ciphertext.len() - afc::OpenKey::<E::CS>::OVERHEAD];

    // `afc::OpenKey` should reject the sequence number before
    // attempting to decrypt the ciphertext, but start with
    // a valid ciphertext anyway.
    seal.seal(&mut ciphertext, GOLDEN.as_bytes(), &AD)
        .expect("should be able to encrypt plaintext");

    let exhausted_seq = afc::Seq::new(afc::Seq::max::<
        <<E::CS as CipherSuite>::Aead as Aead>::NonceSize,
    >());
    // Decryption should fail since seq >= max.
    let err = open
        .open(&mut plaintext, &ciphertext, &AD, exhausted_seq)
        .expect_err("should not be able to decrypt ciphertext with exhausted seq number");
    assert_eq!(
        err,
        afc::OpenError::MessageLimitReached,
        "should have received `MessageLimitReached` error"
    );
}

/// Tests that [`afc::OpenKey`]'s fails when the incorrect
/// sequence number is provided.
pub fn test_afc_open_key_wrong_seq_number<E: Engine>(eng: &mut E) {
    let raw: afc::RawSealKey<E::CS> = Random::random(eng);
    let mut seal = afc::SealKey::<E::CS>::from_raw(&raw, afc::Seq::ZERO)
        .expect("should be able to create `afc::SealKey`");
    let open =
        afc::OpenKey::from_raw(&raw.into()).expect("should be able to create `afc::OpenKey`");
    assert_same_afc_keys(&mut seal, &open);

    const GOLDEN: &str = "hello, world!";
    const AD: afc::AuthData = afc::AuthData {
        version: 1,
        label: 2,
    };
    let mut ciphertext = vec![0u8; GOLDEN.len() + afc::SealKey::<E::CS>::OVERHEAD];
    let mut plaintext = vec![0u8; ciphertext.len() - afc::OpenKey::<E::CS>::OVERHEAD];
    for _ in 0..100 {
        let seq = seal
            .seal(&mut ciphertext, GOLDEN.as_bytes(), &AD)
            .expect("should be able to encrypt plaintext");

        let wrong_seq = afc::Seq::new(seq.to_u64() + 1);
        let err = open
            .open(&mut plaintext, &ciphertext, &AD, wrong_seq)
            .expect_err("should not be able to decrypt ciphertext with the wrong seq number");
        assert_eq!(
            err,
            afc::OpenError::Authentication,
            "should have received `Authentication` error"
        );
    }
}

/// Tests that [`afc::OpenKey`]'s fails when the incorrect
/// [`afc::AuthData`] is provided.
pub fn test_afc_open_key_wrong_auth_data<E: Engine>(eng: &mut E) {
    let raw: afc::RawSealKey<E::CS> = Random::random(eng);
    let mut seal = afc::SealKey::<E::CS>::from_raw(&raw, afc::Seq::ZERO)
        .expect("should be able to create `afc::SealKey`");
    let open =
        afc::OpenKey::from_raw(&raw.into()).expect("should be able to create `afc::OpenKey`");
    assert_same_afc_keys(&mut seal, &open);

    const GOLDEN: &str = "hello, world!";
    const GOOD_AD: afc::AuthData = afc::AuthData {
        version: 1,
        label: 2,
    };
    const WRONG_AD: afc::AuthData = afc::AuthData {
        version: 3,
        label: 4,
    };

    let mut ciphertext = vec![0u8; GOLDEN.len() + afc::SealKey::<E::CS>::OVERHEAD];
    let seq = seal
        .seal(&mut ciphertext, GOLDEN.as_bytes(), &GOOD_AD)
        .expect("should be able to encrypt plaintext");

    let mut plaintext = vec![0u8; ciphertext.len() - afc::OpenKey::<E::CS>::OVERHEAD];
    let err = open
        .open(&mut plaintext, &ciphertext, &WRONG_AD, seq)
        .expect_err("should not be able to decrypt ciphertext with the wrong `afc::AuthData`");
    assert_eq!(
        err,
        afc::OpenError::Authentication,
        "should have received `Authentication` error"
    );
}

/// Checks that `lhs` and `rhs` match; that is, `lhs`'s
/// encryption key should match `rhs`'s decryption key and
/// vice versa.
fn assert_afc_bidi_keys_match<CS: CipherSuite>(lhs: afc::BidiKeys<CS>, rhs: afc::BidiKeys<CS>) {
    // We should never generate duplicate keys.
    assert_ct_ne!(lhs.seal_key(), rhs.seal_key(), "duplicate `afc::SealKey`");
    assert_ct_ne!(lhs.open_key(), rhs.open_key(), "duplicate `afc::OpenKey`");

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
fn assert_afc_bidi_keys_mismatch<E: Engine>(
    eng: &mut E,
    lhs: afc::BidiKeys<E::CS>,
    rhs: afc::BidiKeys<E::CS>,
) {
    // We should never generate duplicate keys.
    assert_ct_ne!(lhs.seal_key(), rhs.seal_key(), "duplicate `afc::SealKey`");
    assert_ct_ne!(lhs.open_key(), rhs.open_key(), "duplicate `afc::OpenKey`");

    let (lhs_seal, lhs_open) = lhs
        .into_keys()
        .expect("should be able to create bidi keys tuple");
    let (rhs_seal, rhs_open) = rhs
        .into_keys()
        .expect("should be able to create bidi keys tuple");
    assert_different_afc_keys(eng, Some(lhs_seal), &rhs_open);
    assert_different_afc_keys(eng, Some(rhs_seal), &lhs_open);
}

/// A simple positive test for deriving [`afc::BidiKeys`].
pub fn test_afc_derive_bidi_keys<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let label = 123;
    let ch1 = afc::BidiChannel {
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
    let ch2 = afc::BidiChannel {
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

    let afc::BidiSecrets { author, peer } =
        afc::BidiSecrets::new(eng, &ch1).expect("unable to create `afc::BidiSecrets`");
    let ck1 = afc::BidiKeys::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `afc::BidiKeys`");
    let ck2 =
        afc::BidiKeys::from_peer_encap(&ch2, peer).expect("unable to decrypt peer `afc::BidiKeys`");

    // `ck1` and `ck2` should be the reverse of each other.
    assert_afc_bidi_keys_match(ck1, ck2);
}

/// Different labels should create different [`afc::BidiKeys`].
pub fn test_afc_derive_bidi_keys_different_labels<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = afc::BidiChannel {
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
    let ch2 = afc::BidiChannel {
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

    let afc::BidiSecrets { author, peer } =
        afc::BidiSecrets::new(eng, &ch1).expect("unable to create `afc::BidiSecrets`");
    let ck1 =
        afc::BidiKeys::from_author_secret(&ch1, author).expect("unable to decrypt `afc::BidiKeys`");
    let ck2 =
        afc::BidiKeys::from_peer_encap(&ch2, peer).expect("unable to decrypt `afc::BidiKeys`");

    // The labels are different, so the keys should also be
    // different.
    assert_afc_bidi_keys_mismatch(eng, ck1, ck2);
}

/// Different DeviceIDs should create different
/// [`afc::BidiKeys`].
///
/// E.g., derive(label, u1, u2, c1) != derive(label, u2, u3, c1).
pub fn test_afc_derive_bidi_keys_different_device_ids<E: Engine>(eng: &mut E) {
    let label = 123;
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = afc::BidiChannel {
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
    let ch2 = afc::BidiChannel {
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        our_id: ch1.their_id,
        their_pk: &sk1
            .public()
            .expect("receiver public encryption key should be valid"),
        their_id: Id::random(eng).into_id(),
        label,
    };
    assert_ne!(ch1.author_info(), ch2.peer_info());
    assert_ne!(ch1.peer_info(), ch2.author_info());

    let afc::BidiSecrets { author, peer } =
        afc::BidiSecrets::new(eng, &ch1).expect("unable to create `afc::BidiSecrets`");
    let ck1 = afc::BidiKeys::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `afc::BidiKeys`");
    let ck2 =
        afc::BidiKeys::from_peer_encap(&ch2, peer).expect("unable to decrypt peer `afc::BidiKeys`");

    assert_afc_bidi_keys_mismatch(eng, ck1, ck2);
}

/// Different command IDs should create different
/// [`afc::BidiKeys`].
///
/// E.g., derive(label, u1, u2, c1) != derive(label, u2, u1, c2).
pub fn test_afc_derive_bidi_keys_different_cmd_ids<E: Engine>(eng: &mut E) {
    let label = 123;
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = afc::BidiChannel {
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
    let ch2 = afc::BidiChannel {
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

    let afc::BidiSecrets { author, peer } =
        afc::BidiSecrets::new(eng, &ch1).expect("unable to create `afc::BidiSecrets`");
    let ck1 = afc::BidiKeys::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `afc::BidiKeys`");
    let ck2 =
        afc::BidiKeys::from_peer_encap(&ch2, peer).expect("unable to decrypt peer `afc::BidiKeys`");

    assert_afc_bidi_keys_mismatch(eng, ck1, ck2);
}

/// Different encryption keys should create different
/// [`afc::BidiKeys`].
///
/// E.g., derive(label, u1, u2, c1) != derive(label, u2, u1, c2).
pub fn test_afc_derive_bidi_keys_different_keys<E: Engine>(eng: &mut E) {
    let label = 123;
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = afc::BidiChannel {
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
    let ch2 = afc::BidiChannel {
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

    let afc::BidiSecrets { author, peer } =
        afc::BidiSecrets::new(eng, &ch1).expect("unable to create `afc::BidiSecrets`");
    let ck1 = afc::BidiKeys::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `afc::BidiKeys`");
    let ck2 =
        afc::BidiKeys::from_peer_encap(&ch2, peer).expect("unable to decrypt peer `afc::BidiKeys`");

    assert_afc_bidi_keys_mismatch(eng, ck1, ck2);
}

/// It is an error to use the same `DeviceId` when deriving
/// [`afc::BidiKeys`].
pub fn test_afc_derive_bidi_keys_same_device_id<E: Engine>(eng: &mut E) {
    let label = 123;
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let mut ch1 = afc::BidiChannel {
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
    let mut ch2 = afc::BidiChannel {
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        our_id: ch1.their_id,
        their_pk: &EncryptionKey::<E::CS>::new(eng)
            .public()
            .expect("receiver public encryption key should be valid"),
        their_id: ch1.our_id,
        label,
    };

    let afc::BidiSecrets { peer, .. } = {
        let prev = ch1.our_id;
        ch1.our_id = ch1.their_id;

        let err = afc::BidiSecrets::new(eng, &ch1)
            .err()
            .expect("should not be able to create `afc::BidiSecrets`");
        assert_eq!(err, Error::same_device_id());

        ch1.our_id = prev;
        afc::BidiSecrets::new(eng, &ch1).expect("unable to create `afc::BidiSecrets`")
    };

    ch2.their_id = ch2.our_id;
    let err = afc::BidiKeys::from_peer_encap(&ch2, peer)
        .err()
        .expect("should not be able to decrypt `afc::BidiKeys`");
    assert_eq!(err, Error::same_device_id());
}

/// Simple positive test for wrapping [`afc::BidiAuthorSecret`]s.
pub fn test_afc_wrap_bidi_author_secret<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::new(eng);
    let sk2 = EncryptionKey::new(eng);
    let ch = afc::BidiChannel {
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

    let afc::BidiSecrets { author: want, .. } =
        afc::BidiSecrets::new(eng, &ch).expect("unable to create `afc::BidiSecrets`");
    let bytes = cbor::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `afc::BidiAuthorSecret`"),
    )
    .expect("should be able to encode wrapped `afc::BidiAuthorSecret`");
    let wrapped = cbor::from_bytes(&bytes)
        .expect("should be able to decode encoded wrapped `afc::BidiAuthorSecret`");
    let got: afc::BidiAuthorSecret<E::CS> = eng
        .unwrap(&wrapped)
        .expect("should be able to unwrap `afc::BidiAuthorSecret`");
    assert_ct_eq!(want, got);
}

/// Checks that `seal` and `open` are the same key.
fn assert_same_afc_uni_key<CS: CipherSuite>(seal: afc::UniSealKey<CS>, open: afc::UniOpenKey<CS>) {
    // Simple test: they should have the same bytes.
    {
        let seal = seal.as_raw_key();
        let open = open.as_raw_key();
        assert_ct_eq!(seal.to_testing_key(), open.to_testing_key());
    }

    // Double check that the `to_testing_key` impls are
    // correct: actually perform encryption.
    let mut seal = seal.into_key().expect("should have got `afc::SealKey`");
    let open = open.into_key().expect("should have got `afc::OpenKey`");
    assert_same_afc_keys(&mut seal, &open);
}

/// Checks that `seal` and `open` are different keys.
fn assert_different_afc_uni_key<E: Engine>(
    eng: &mut E,
    seal: afc::UniSealKey<E::CS>,
    open: afc::UniOpenKey<E::CS>,
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
    let seal = seal.into_key().expect("should have got `afc::SealKey`");
    let open = open.into_key().expect("should have got `afc::OpenKey`");
    assert_different_afc_keys(eng, Some(seal), &open);

    // Then also check `open` with a randomly generated key.
    assert_different_afc_keys(eng, None, &open);
}

/// A simple positive test for deriving [`afc::UniSealKey`] and
/// [`afc::UniOpenKey`].
pub fn test_afc_derive_uni_key<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let label = 123;
    let ch1 = afc::UniChannel {
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
    let ch2 = afc::UniChannel {
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

    let afc::UniSecrets { author, peer } =
        afc::UniSecrets::new(eng, &ch1).expect("unable to create `afc::UniSecrets`");
    let ck1 = afc::UniSealKey::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `afc::UniSealKey`");
    let ck2 = afc::UniOpenKey::from_peer_encap(&ch2, peer)
        .expect("unable to decrypt peer `afc::UniOpenKey`");

    assert_same_afc_uni_key(ck1, ck2);
}

/// Different labels should create different [`afc::UniSealKey`]
/// and [`afc::UniOpenKey`]s.
pub fn test_afc_derive_uni_key_different_labels<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = afc::UniChannel {
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
    let ch2 = afc::UniChannel {
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

    let afc::UniSecrets { author, peer } =
        afc::UniSecrets::new(eng, &ch1).expect("unable to create `afc::UniSecrets`");
    let ck1 = afc::UniSealKey::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `afc::UniSealKey`");
    let ck2 = afc::UniOpenKey::from_peer_encap(&ch2, peer)
        .expect("unable to decrypt peer `afc::UniOpenKey`");

    assert_different_afc_uni_key(eng, ck1, ck2);
}

/// Different DeviceIDs should create different
/// [`afc::UniSealKey`] and [`afc::UniOpenKey`]s.
///
/// E.g., derive(label, u1, u2, c1) != derive(label, u2, u3, c1).
pub fn test_afc_derive_uni_key_different_device_ids<E: Engine>(eng: &mut E) {
    let label = 123;
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = afc::UniChannel {
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
    let ch2 = afc::UniChannel {
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        their_pk: &sk1
            .public()
            .expect("receiver public encryption key should be valid"),
        seal_id: ch1.seal_id,
        open_id: Id::random(eng).into_id(),
        label,
    };
    assert_ne!(ch1.info(), ch2.info());

    let afc::UniSecrets { author, peer } =
        afc::UniSecrets::new(eng, &ch1).expect("unable to create `afc::UniSecrets`");
    let ck1 = afc::UniSealKey::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `afc::UniSealKey`");
    let ck2 = afc::UniOpenKey::from_peer_encap(&ch2, peer)
        .expect("unable to decrypt peer `afc::UniOpenKey`");

    assert_different_afc_uni_key(eng, ck1, ck2);
}

/// Different command IDs should create different
/// [`afc::UniSealKey`] and [`afc::UniOpenKey`]s.
///
/// E.g., derive(label, u1, u2, c1) != derive(label, u2, u1, c2).
pub fn test_afc_derive_uni_key_different_cmd_ids<E: Engine>(eng: &mut E) {
    let label = 123;
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = afc::UniChannel {
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
    let ch2 = afc::UniChannel {
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

    let afc::UniSecrets { author, peer } =
        afc::UniSecrets::new(eng, &ch1).expect("unable to create `afc::UniSecrets`");
    let ck1 = afc::UniSealKey::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `afc::UniSealKey`");
    let ck2 = afc::UniOpenKey::from_peer_encap(&ch2, peer)
        .expect("unable to decrypt peer `afc::UniOpenKey`");

    assert_different_afc_uni_key(eng, ck1, ck2);
}

/// Different encryption keys should create different
/// [`afc::UniSealKey`] and [`afc::UniOpenKey`]s.
///
/// E.g., derive(label, u1, u2, c1) != derive(label, u2, u1, c2).
pub fn test_afc_derive_uni_key_different_keys<E: Engine>(eng: &mut E) {
    let label = 123;
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = afc::UniChannel {
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
    let ch2 = afc::UniChannel {
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        their_pk: &EncryptionKey::<E::CS>::new(eng)
            .public()
            .expect("receiver public encryption key should be valid"),
        seal_id: ch1.seal_id,
        open_id: ch1.open_id,
        label,
    };

    let afc::UniSecrets { author, peer } =
        afc::UniSecrets::new(eng, &ch1).expect("unable to create `afc::UniSecrets`");
    let ck1 = afc::UniSealKey::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `afc::UniSealKey`");
    let ck2 = afc::UniOpenKey::from_peer_encap(&ch2, peer)
        .expect("unable to decrypt peer `afc::UniOpenKey`");

    assert_different_afc_uni_key(eng, ck1, ck2);
}

/// It is an error to use the same `DeviceId` when deriving
/// [`afc::UniSealKey`]s.
pub fn test_afc_derive_uni_seal_key_same_device_id<E: Engine>(eng: &mut E) {
    let label = 123;
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let mut ch1 = afc::UniChannel {
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
    let mut ch2 = afc::UniChannel {
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

    let afc::UniSecrets { peer, .. } = {
        let prev = ch1.seal_id;
        ch1.seal_id = ch1.open_id;

        let err = afc::UniSecrets::new(eng, &ch1)
            .err()
            .expect("should not be able to create `afc::UniSecrets`");
        assert_eq!(err, Error::same_device_id());

        ch1.seal_id = prev;
        afc::UniSecrets::new(eng, &ch1).expect("unable to create `afc::UniSecrets`")
    };

    ch2.seal_id = ch2.open_id;
    let err = afc::UniSealKey::from_peer_encap(&ch2, peer)
        .err()
        .expect("should not be able to decrypt `afc::UniSealKey`");
    assert_eq!(err, Error::same_device_id());
}

/// It is an error to use the same `DeviceId` when deriving
/// [`afc::UniOpenKey`]s.
pub fn test_afc_derive_uni_open_key_same_device_id<E: Engine>(eng: &mut E) {
    let label = 123;
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let mut ch1 = afc::UniChannel {
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
    let mut ch2 = afc::UniChannel {
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

    let afc::UniSecrets { peer, .. } = {
        let prev = ch1.seal_id;
        ch1.seal_id = ch1.open_id;

        let err = afc::UniSecrets::new(eng, &ch1)
            .err()
            .expect("should not be able to create `afc::UniSecrets`");
        assert_eq!(err, Error::same_device_id());

        ch1.seal_id = prev;
        afc::UniSecrets::new(eng, &ch1).expect("unable to create `afc::UniSecrets`")
    };

    ch2.seal_id = ch2.open_id;
    let err = afc::UniOpenKey::from_peer_encap(&ch2, peer)
        .err()
        .expect("should not be able to decrypt `afc::UniOpenKey`");
    assert_eq!(err, Error::same_device_id());
}

/// Simple positive test for wrapping [`afc::UniAuthorSecret`]s.
pub fn test_afc_wrap_uni_author_secret<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::new(eng);
    let sk2 = EncryptionKey::new(eng);
    let ch = afc::UniChannel {
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

    let afc::UniSecrets { author: want, .. } =
        afc::UniSecrets::new(eng, &ch).expect("unable to create `afc::UniSecrets`");
    let bytes = cbor::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `afc::UniAuthorSecret`"),
    )
    .expect("should be able to encode wrapped `afc::UniAuthorSecret`");
    let wrapped = cbor::from_bytes(&bytes)
        .expect("should be able to decode encoded wrapped `afc::UniAuthorSecret`");
    let got: afc::UniAuthorSecret<E::CS> = eng
        .unwrap(&wrapped)
        .expect("should be able to unwrap `afc::UniAuthorSecret`");
    assert_ct_eq!(want, got);
}

/// A simple positive test for deriving [`aqc::BidiPsk`]s.
pub fn test_aqc_derive_bidi_psk<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let label = Id::random(eng);
    let ch1 = aqc::BidiChannel {
        psk_length_in_bytes: 32,
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
    let ch2 = aqc::BidiChannel {
        psk_length_in_bytes: 32,
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

    let aqc::BidiSecrets { author, peer } =
        aqc::BidiSecrets::new(eng, &ch1).expect("unable to create `aqc::BidiSecrets`");
    let psk1 = aqc::BidiSecret::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `aqc::BidiSecret`")
        .generate_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to generate author PSK");
    let psk2 = aqc::BidiSecret::from_peer_encap(&ch2, peer)
        .expect("unable to decrypt peer `aqc::BidiSecret`")
        .generate_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to decrypt peer `aqc::BidiPsk`");

    assert_eq!(psk1.identity(), psk2.identity());
    assert_eq!(psk1.raw_secret_bytes(), psk2.raw_secret_bytes());
}

/// Different labels should create different [`aqc::BidiPsk`]s.
pub fn test_aqc_derive_bidi_psk_different_labels<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = aqc::BidiChannel {
        psk_length_in_bytes: 32,
        parent_cmd_id: Id::random(eng),
        our_sk: &sk1,
        our_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("sender id should be valid"),
        their_pk: &sk2.public().expect("encryption public key should be valid"),
        their_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("receiver id should be valid"),
        label: Id::random(eng),
    };
    let ch2 = aqc::BidiChannel {
        psk_length_in_bytes: 32,
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        our_id: ch1.their_id,
        their_pk: &sk1
            .public()
            .expect("receiver public encryption key should be valid"),
        their_id: ch1.our_id,
        label: Id::random(eng),
    };
    assert_ne!(ch1.author_info(), ch2.peer_info());
    assert_ne!(ch1.peer_info(), ch2.author_info());

    let aqc::BidiSecrets { author, peer } =
        aqc::BidiSecrets::new(eng, &ch1).expect("unable to create `aqc::BidiSecrets`");
    let psk1 = aqc::BidiSecret::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `aqc::BidiSecret`")
        .generate_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to decrypt `aqc::BidiPsk`");
    let psk2 = aqc::BidiSecret::from_peer_encap(&ch2, peer)
        .expect("unable to decrypt peer `aqc::BidiSecret`")
        .generate_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to decrypt `aqc::BidiPsk`");

    // The identities are the same because identities are derived
    // from the peer's encapsulation, not the raw secret bytes.
    assert_eq!(psk1.identity(), psk2.identity());
    // The labels are different, so the keys should also be
    // different.
    assert_ne!(psk1.raw_secret_bytes(), psk2.raw_secret_bytes());
}

/// Different DeviceIDs should create different
/// [`aqc::BidiPsk`]s.
///
/// E.g., derive(label, u1, u2, c1) != derive(label, u2, u3, c1).
pub fn test_aqc_derive_bidi_psk_different_device_ids<E: Engine>(eng: &mut E) {
    let label = Id::random(eng);
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = aqc::BidiChannel {
        psk_length_in_bytes: 32,
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
    let ch2 = aqc::BidiChannel {
        psk_length_in_bytes: 32,
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        our_id: ch1.their_id,
        their_pk: &sk1
            .public()
            .expect("receiver public encryption key should be valid"),
        their_id: Id::random(eng).into_id(),
        label,
    };
    assert_ne!(ch1.author_info(), ch2.peer_info());
    assert_ne!(ch1.peer_info(), ch2.author_info());

    let aqc::BidiSecrets { author, peer } =
        aqc::BidiSecrets::new(eng, &ch1).expect("unable to create `aqc::BidiSecrets`");
    let psk1 = aqc::BidiSecret::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `aqc::BidiSecret`")
        .generate_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to generate author PSK");
    let psk2 = aqc::BidiSecret::from_peer_encap(&ch2, peer)
        .expect("unable to decrypt peer `aqc::BidiSecret`")
        .generate_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to decrypt peer `aqc::BidiPsk`");

    // The identities are the same because identities are derived
    // from the peer's encapsulation, not the raw secret bytes.
    assert_eq!(psk1.identity(), psk2.identity());
    assert_ne!(psk1.raw_secret_bytes(), psk2.raw_secret_bytes());
}

/// Different command IDs should create different
/// [`aqc::BidiPsk`]s.
///
/// E.g., derive(label, u1, u2, c1) != derive(label, u2, u1, c2).
pub fn test_aqc_derive_bidi_psk_different_cmd_ids<E: Engine>(eng: &mut E) {
    let label = Id::random(eng);
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = aqc::BidiChannel {
        psk_length_in_bytes: 32,
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
    let ch2 = aqc::BidiChannel {
        psk_length_in_bytes: 32,
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

    let aqc::BidiSecrets { author, peer } =
        aqc::BidiSecrets::new(eng, &ch1).expect("unable to create `aqc::BidiSecrets`");
    let psk1 = aqc::BidiSecret::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `aqc::BidiSecret`")
        .generate_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to generate author PSK");
    let psk2 = aqc::BidiSecret::from_peer_encap(&ch2, peer)
        .expect("unable to decrypt peer `aqc::BidiSecret`")
        .generate_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to decrypt peer `aqc::BidiPsk`");

    // The identities are the same because identities are derived
    // from the peer's encapsulation, not the raw secret bytes.
    assert_eq!(psk1.identity(), psk2.identity());
    assert_ne!(psk1.raw_secret_bytes(), psk2.raw_secret_bytes());
}

/// Different encryption keys should create different
/// [`aqc::BidiPsk`]s.
///
/// E.g., derive(label, u1, u2, c1) != derive(label, u2, u1, c2).
pub fn test_aqc_derive_bidi_psk_different_keys<E: Engine>(eng: &mut E) {
    let label = Id::random(eng);
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = aqc::BidiChannel {
        psk_length_in_bytes: 32,
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
    let ch2 = aqc::BidiChannel {
        psk_length_in_bytes: 32,
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

    let aqc::BidiSecrets { author, peer } =
        aqc::BidiSecrets::new(eng, &ch1).expect("unable to create `aqc::BidiSecrets`");
    let psk1 = aqc::BidiSecret::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `aqc::BidiSecret`")
        .generate_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to generate author PSK");
    let psk2 = aqc::BidiSecret::from_peer_encap(&ch2, peer)
        .expect("unable to decrypt peer `aqc::BidiSecret`")
        .generate_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to decrypt peer `aqc::BidiPsk`");

    // The identities are the same because identities are derived
    // from the peer's encapsulation, not the raw secret bytes.
    assert_eq!(psk1.identity(), psk2.identity());
    assert_ne!(psk1.raw_secret_bytes(), psk2.raw_secret_bytes());
}

/// Different cipher suites should create different
/// [`aqc::BidiPsk`]s.
///
/// E.g., derive(label, u1, u2, c1) != derive(label, u2, u1, c2).
pub fn test_aqc_derive_bidi_psk_different_cipher_suites<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let label = Id::random(eng);
    let ch1 = aqc::BidiChannel {
        psk_length_in_bytes: 32,
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
    let ch2 = aqc::BidiChannel {
        psk_length_in_bytes: 32,
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

    let aqc::BidiSecrets { author, peer } =
        aqc::BidiSecrets::new(eng, &ch1).expect("unable to create `aqc::BidiSecrets`");
    let psk1 = aqc::BidiSecret::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `aqc::BidiSecret`")
        .generate_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to generate author PSK");
    let psk2 = aqc::BidiSecret::from_peer_encap(&ch2, peer)
        .expect("unable to decrypt peer `aqc::BidiSecret`")
        .generate_psk(aqc::CipherSuiteId::TlsAes256GcmSha384)
        .expect("unable to decrypt peer `aqc::BidiPsk`");

    assert_ne!(psk1.identity(), psk2.identity());
    assert_ne!(psk1.raw_secret_bytes(), psk2.raw_secret_bytes());
}

/// It is an error to use the same `DeviceId` when deriving
/// [`aqc::BidiPsk`]s.
pub fn test_aqc_derive_bidi_psk_same_device_id<E: Engine>(eng: &mut E) {
    let label = Id::random(eng);
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let mut ch1 = aqc::BidiChannel {
        psk_length_in_bytes: 32,
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
    let mut ch2 = aqc::BidiChannel {
        psk_length_in_bytes: 32,
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        our_id: ch1.their_id,
        their_pk: &EncryptionKey::<E::CS>::new(eng)
            .public()
            .expect("receiver public encryption key should be valid"),
        their_id: ch1.our_id,
        label,
    };

    let aqc::BidiSecrets { peer, .. } = {
        let prev = ch1.our_id;
        ch1.our_id = ch1.their_id;

        let err = aqc::BidiSecrets::new(eng, &ch1)
            .err()
            .expect("should not be able to create `aqc::BidiSecrets`");
        assert_eq!(err, Error::same_device_id());

        ch1.our_id = prev;
        aqc::BidiSecrets::new(eng, &ch1).expect("unable to create `aqc::BidiSecrets`")
    };

    ch2.their_id = ch2.our_id;
    let err = aqc::BidiSecret::from_peer_encap(&ch2, peer)
        .expect_err("should not be able to decrypt `aqc::BidiSecret`");
    assert_eq!(err, Error::same_device_id());
}

/// It is an error to specify a PSK length less than than 32 when
/// deriving [`aqc::BidiPsk`]s.
pub fn test_aqc_derive_bidi_psk_psk_too_short<E: Engine>(eng: &mut E) {
    let label = Id::random(eng);
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let mut ch1 = aqc::BidiChannel {
        psk_length_in_bytes: 16,
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
    let ch2 = aqc::BidiChannel {
        psk_length_in_bytes: 31,
        parent_cmd_id: ch1.parent_cmd_id,
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

    let aqc::BidiSecrets { peer, .. } = {
        let err = aqc::BidiSecrets::new(eng, &ch1)
            .err()
            .expect("should not be able to create `aqc::BidiSecrets`");
        assert_eq!(err, Error::invalid_psk_length());

        ch1.psk_length_in_bytes = 32;
        aqc::BidiSecrets::new(eng, &ch1).expect("unable to create `aqc::BidiSecrets`")
    };

    let err = aqc::BidiSecret::from_peer_encap(&ch2, peer)
        .expect_err("should not be able to decrypt `aqc::BidiSecret`");
    assert_eq!(err, Error::invalid_psk_length());
}

/// It is an error to specify a PSK length other than than 32
/// when deriving [`aqc::BidiPsk`]s.
pub fn test_aqc_derive_bidi_psk_psk_too_long<E: Engine>(eng: &mut E) {
    let label = Id::random(eng);
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let mut ch1 = aqc::BidiChannel {
        psk_length_in_bytes: u16::MAX,
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
    let ch2 = aqc::BidiChannel {
        psk_length_in_bytes: 33,
        parent_cmd_id: ch1.parent_cmd_id,
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

    let aqc::BidiSecrets { peer, .. } = {
        let err = aqc::BidiSecrets::new(eng, &ch1)
            .err()
            .expect("should not be able to create `aqc::BidiSecrets`");
        assert_eq!(err, Error::invalid_psk_length());

        ch1.psk_length_in_bytes = 32;
        aqc::BidiSecrets::new(eng, &ch1).expect("unable to create `aqc::BidiSecrets`")
    };

    let err = aqc::BidiSecret::from_peer_encap(&ch2, peer)
        .expect_err("should not be able to decrypt `aqc::BidiSecret`");
    assert_eq!(err, Error::invalid_psk_length());
}

/// Simple positive test for wrapping [`aqc::BidiAuthorSecret`]s.
pub fn test_aqc_wrap_bidi_author_secret<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::new(eng);
    let sk2 = EncryptionKey::new(eng);
    let ch = aqc::BidiChannel {
        psk_length_in_bytes: 32,
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
        label: Id::random(eng),
    };

    let aqc::BidiSecrets { author: want, .. } =
        aqc::BidiSecrets::new(eng, &ch).expect("unable to create `aqc::BidiSecrets`");
    let bytes = cbor::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `aqc::BidiAuthorSecret`"),
    )
    .expect("should be able to encode wrapped `aqc::BidiAuthorSecret`");
    let wrapped = cbor::from_bytes(&bytes)
        .expect("should be able to decode encoded wrapped `aqc::BidiAuthorSecret`");
    let got: aqc::BidiAuthorSecret<E::CS> = eng
        .unwrap(&wrapped)
        .expect("should be able to unwrap `aqc::BidiAuthorSecret`");
    assert_ct_eq!(want, got);
}

/// A simple positive test for deriving [`aqc::UniSendPsk`] and
/// [`aqc::UniRecvPsk`].
pub fn test_aqc_derive_uni_psk<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let label = Id::random(eng);
    let ch1 = aqc::UniChannel {
        psk_length_in_bytes: 32,
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
    let ch2 = aqc::UniChannel {
        psk_length_in_bytes: 32,
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

    let aqc::UniSecrets { author, peer } =
        aqc::UniSecrets::new(eng, &ch1).expect("unable to create `aqc::UniSecrets`");
    let psk1 = aqc::UniSecret::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `aqc::UniSecret`")
        .generate_send_only_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to decrypt author `aqc::UniSendPsk`");
    let psk2 = aqc::UniSecret::from_peer_encap(&ch2, peer)
        .expect("unable to decrypt peer `aqc::UniSecret`")
        .generate_recv_only_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to decrypt peer `aqc::UniRecvPsk`");

    assert_eq!(psk1.identity(), psk2.identity());
    assert_eq!(psk1.raw_secret_bytes(), psk2.raw_secret_bytes());
}

/// Different labels should create different [`aqc::UniSendPsk`]
/// and [`aqc::UniRecvPsk`]s.
pub fn test_aqc_derive_uni_psk_different_labels<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = aqc::UniChannel {
        psk_length_in_bytes: 32,
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
        label: Id::random(eng),
    };
    let ch2 = aqc::UniChannel {
        psk_length_in_bytes: 32,
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        their_pk: &sk1
            .public()
            .expect("receiver public encryption key should be valid"),
        seal_id: ch1.seal_id,
        open_id: ch1.open_id,
        label: Id::random(eng),
    };
    assert_ne!(ch1.info(), ch2.info());

    let aqc::UniSecrets { author, peer } =
        aqc::UniSecrets::new(eng, &ch1).expect("unable to create `aqc::UniSecrets`");
    let psk1 = aqc::UniSecret::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `aqc::UniSecret`")
        .generate_send_only_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to decrypt author `aqc::UniSendPsk`");
    let psk2 = aqc::UniSecret::from_peer_encap(&ch2, peer)
        .expect("unable to decrypt peer `aqc::UniSecret`")
        .generate_recv_only_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to decrypt peer `aqc::UniRecvPsk`");

    // The identities are the same because identities are derived
    // from the peer's encapsulation, not the raw secret bytes.
    assert_eq!(psk1.identity(), psk2.identity());
    assert_ne!(psk1.raw_secret_bytes(), psk2.raw_secret_bytes());
}

/// Different DeviceIDs should create different
/// [`aqc::UniSendPsk`] and [`aqc::UniRecvPsk`]s.
///
/// E.g., derive(label, u1, u2, c1) != derive(label, u2, u3, c1).
pub fn test_aqc_derive_uni_psk_different_device_ids<E: Engine>(eng: &mut E) {
    let label = Id::random(eng);
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = aqc::UniChannel {
        psk_length_in_bytes: 32,
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
    let ch2 = aqc::UniChannel {
        psk_length_in_bytes: 32,
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        their_pk: &sk1
            .public()
            .expect("receiver public encryption key should be valid"),
        seal_id: ch1.seal_id,
        open_id: Id::random(eng).into_id(),
        label,
    };
    assert_ne!(ch1.info(), ch2.info());

    let aqc::UniSecrets { author, peer } =
        aqc::UniSecrets::new(eng, &ch1).expect("unable to create `aqc::UniSecrets`");
    let psk1 = aqc::UniSecret::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `aqc::UniSecret`")
        .generate_send_only_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to decrypt author `aqc::UniSendPsk`");
    let psk2 = aqc::UniSecret::from_peer_encap(&ch2, peer)
        .expect("unable to decrypt peer `aqc::UniSecret`")
        .generate_recv_only_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to decrypt peer `aqc::UniRecvPsk`");

    // The identities are the same because identities are derived
    // from the peer's encapsulation, not the raw secret bytes.
    assert_eq!(psk1.identity(), psk2.identity());
    assert_ne!(psk1.raw_secret_bytes(), psk2.raw_secret_bytes());
}

/// Different command IDs should create different
/// [`aqc::UniSendPsk`] and [`aqc::UniRecvPsk`]s.
///
/// E.g., derive(label, u1, u2, c1) != derive(label, u2, u1, c2).
pub fn test_aqc_derive_uni_psk_different_cmd_ids<E: Engine>(eng: &mut E) {
    let label = Id::random(eng);
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = aqc::UniChannel {
        psk_length_in_bytes: 32,
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
    let ch2 = aqc::UniChannel {
        psk_length_in_bytes: 32,
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

    let aqc::UniSecrets { author, peer } =
        aqc::UniSecrets::new(eng, &ch1).expect("unable to create `aqc::UniSecrets`");
    let psk1 = aqc::UniSecret::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `aqc::UniSecret`")
        .generate_send_only_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to decrypt author `aqc::UniSendPsk`");
    let psk2 = aqc::UniSecret::from_peer_encap(&ch2, peer)
        .expect("unable to decrypt peer `aqc::UniSecret`")
        .generate_recv_only_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to decrypt peer `aqc::UniRecvPsk`");

    // The identities are the same because identities are derived
    // from the peer's encapsulation, not the raw secret bytes.
    assert_eq!(psk1.identity(), psk2.identity());
    assert_ne!(psk1.raw_secret_bytes(), psk2.raw_secret_bytes());
}

/// Different encryption keys should create different
/// [`aqc::UniSendPsk`] and [`aqc::UniRecvPsk`]s.
///
/// E.g., derive(label, u1, u2, c1) != derive(label, u2, u1, c2).
pub fn test_aqc_derive_uni_psk_different_keys<E: Engine>(eng: &mut E) {
    let label = Id::random(eng);
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let ch1 = aqc::UniChannel {
        psk_length_in_bytes: 32,
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
    let ch2 = aqc::UniChannel {
        psk_length_in_bytes: 32,
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        their_pk: &EncryptionKey::<E::CS>::new(eng)
            .public()
            .expect("receiver public encryption key should be valid"),
        seal_id: ch1.seal_id,
        open_id: ch1.open_id,
        label,
    };

    let aqc::UniSecrets { author, peer } =
        aqc::UniSecrets::new(eng, &ch1).expect("unable to create `aqc::UniSecrets`");
    let psk1 = aqc::UniSecret::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `aqc::UniSecret`")
        .generate_send_only_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to decrypt author `aqc::UniSendPsk`");
    let psk2 = aqc::UniSecret::from_peer_encap(&ch2, peer)
        .expect("unable to decrypt peer `aqc::UniSecret`")
        .generate_recv_only_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to decrypt peer `aqc::UniRecvPsk`");

    // The identities are the same because identities are derived
    // from the peer's encapsulation, not the raw secret bytes.
    assert_eq!(psk1.identity(), psk2.identity());
    assert_ne!(psk1.raw_secret_bytes(), psk2.raw_secret_bytes());
}

/// It is an error to use the same `DeviceId` when deriving
/// [`aqc::UniSendPsk`]s.
pub fn test_aqc_derive_uni_send_psk_same_device_id<E: Engine>(eng: &mut E) {
    let label = Id::random(eng);
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let mut ch1 = aqc::UniChannel {
        psk_length_in_bytes: 32,
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
    let mut ch2 = aqc::UniChannel {
        psk_length_in_bytes: 32,
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

    let aqc::UniSecrets { peer, .. } = {
        let prev = ch1.seal_id;
        ch1.seal_id = ch1.open_id;

        let err = aqc::UniSecrets::new(eng, &ch1)
            .err()
            .expect("should not be able to create `aqc::UniSecrets`");
        assert_eq!(err, Error::same_device_id());

        ch1.seal_id = prev;
        aqc::UniSecrets::new(eng, &ch1).expect("unable to create `aqc::UniSecrets`")
    };

    ch2.seal_id = ch2.open_id;
    let err = aqc::UniSecret::from_peer_encap(&ch2, peer)
        .expect_err("should not be able to decrypt `aqc::UniSecret`");
    assert_eq!(err, Error::same_device_id());
}

/// It is an error to use the same `DeviceId` when deriving
/// [`aqc::UniRecvPsk`]s.
pub fn test_aqc_derive_uni_recv_psk_same_device_id<E: Engine>(eng: &mut E) {
    let label = Id::random(eng);
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let mut ch1 = aqc::UniChannel {
        psk_length_in_bytes: 32,
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
    let mut ch2 = aqc::UniChannel {
        psk_length_in_bytes: 32,
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

    let aqc::UniSecrets { peer, .. } = {
        let prev = ch1.seal_id;
        ch1.seal_id = ch1.open_id;

        let err = aqc::UniSecrets::new(eng, &ch1)
            .err()
            .expect("should not be able to create `aqc::UniSecrets`");
        assert_eq!(err, Error::same_device_id());

        ch1.seal_id = prev;
        aqc::UniSecrets::new(eng, &ch1).expect("unable to create `aqc::UniSecrets`")
    };

    ch2.seal_id = ch2.open_id;
    let err = aqc::UniSecret::from_peer_encap(&ch2, peer)
        .expect_err("should not be able to decrypt `aqc::UniSecret`");
    assert_eq!(err, Error::same_device_id());
}

/// It is an error to specify a PSK length less than than 32 when
/// deriving [`aqc::UniSendPsk`]s.
pub fn test_aqc_derive_uni_send_psk_psk_too_short<E: Engine>(eng: &mut E) {
    let label = Id::random(eng);
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let mut ch1 = aqc::UniChannel {
        psk_length_in_bytes: 16,
        parent_cmd_id: Id::random(eng),
        our_sk: &sk1,
        seal_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("sender id should be valid"),
        their_pk: &sk2
            .public()
            .expect("receiver public encryption key should be valid"),
        open_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("receiver id should be valid"),
        label,
    };
    let ch2 = aqc::UniChannel {
        psk_length_in_bytes: 31,
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        seal_id: ch1.seal_id,
        their_pk: &sk1
            .public()
            .expect("receiver public encryption key should be valid"),
        open_id: ch1.open_id,
        label,
    };
    assert_ne!(ch1.info(), ch2.info());

    let aqc::UniSecrets { peer, .. } = {
        let err = aqc::UniSecrets::new(eng, &ch1)
            .err()
            .expect("should not be able to create `aqc::UniSecrets`");
        assert_eq!(err, Error::invalid_psk_length());

        ch1.psk_length_in_bytes = 32;
        aqc::UniSecrets::new(eng, &ch1).expect("unable to create `aqc::UniSecrets`")
    };

    let err = aqc::UniSecret::from_peer_encap(&ch2, peer)
        .expect_err("should not be able to decrypt `aqc::UniSecret`");
    assert_eq!(err, Error::invalid_psk_length());
}

/// It is an error to specify a PSK length less than than 32 when
/// deriving [`aqc::UniRecvPsk`]s.
pub fn test_aqc_derive_uni_recv_psk_psk_too_short<E: Engine>(eng: &mut E) {
    let label = Id::random(eng);
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let mut ch1 = aqc::UniChannel {
        psk_length_in_bytes: 16,
        parent_cmd_id: Id::random(eng),
        our_sk: &sk1,
        seal_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("sender id should be valid"),
        their_pk: &sk2
            .public()
            .expect("receiver public encryption key should be valid"),
        open_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("receiver id should be valid"),
        label,
    };
    let ch2 = aqc::UniChannel {
        psk_length_in_bytes: 31,
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        seal_id: ch1.seal_id,
        their_pk: &sk1
            .public()
            .expect("receiver public encryption key should be valid"),
        open_id: ch1.open_id,
        label,
    };
    assert_ne!(ch1.info(), ch2.info());

    let aqc::UniSecrets { peer, .. } = {
        let err = aqc::UniSecrets::new(eng, &ch1)
            .err()
            .expect("should not be able to create `aqc::UniSecrets`");
        assert_eq!(err, Error::invalid_psk_length());

        ch1.psk_length_in_bytes = 32;
        aqc::UniSecrets::new(eng, &ch1).expect("unable to create `aqc::UniSecrets`")
    };

    let err = aqc::UniSecret::from_peer_encap(&ch2, peer)
        .expect_err("should not be able to decrypt `aqc::UniSecret`");
    assert_eq!(err, Error::invalid_psk_length());
}

/// It is an error to specify a PSK length longer than than 32
/// when deriving [`aqc::UniSendPsk`]s.
pub fn test_aqc_derive_uni_send_psk_psk_too_long<E: Engine>(eng: &mut E) {
    let label = Id::random(eng);
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let mut ch1 = aqc::UniChannel {
        psk_length_in_bytes: u16::MAX,
        parent_cmd_id: Id::random(eng),
        our_sk: &sk1,
        seal_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("sender id should be valid"),
        their_pk: &sk2
            .public()
            .expect("receiver public encryption key should be valid"),
        open_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("receiver id should be valid"),
        label,
    };
    let ch2 = aqc::UniChannel {
        psk_length_in_bytes: 33,
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        seal_id: ch1.seal_id,
        their_pk: &sk1
            .public()
            .expect("receiver public encryption key should be valid"),
        open_id: ch1.open_id,
        label,
    };
    assert_ne!(ch1.info(), ch2.info());

    let aqc::UniSecrets { peer, .. } = {
        let err = aqc::UniSecrets::new(eng, &ch1)
            .err()
            .expect("should not be able to create `aqc::UniSecrets`");
        assert_eq!(err, Error::invalid_psk_length());

        ch1.psk_length_in_bytes = 32;
        aqc::UniSecrets::new(eng, &ch1).expect("unable to create `aqc::UniSecrets`")
    };

    let err = aqc::UniSecret::from_peer_encap(&ch2, peer)
        .expect_err("should not be able to decrypt `aqc::UniSecret`");
    assert_eq!(err, Error::invalid_psk_length());
}

/// It is an error to specify a PSK length longer than than 32
/// when deriving [`aqc::UniRecvPsk`]s.
pub fn test_aqc_derive_uni_recv_psk_psk_too_long<E: Engine>(eng: &mut E) {
    let label = Id::random(eng);
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let mut ch1 = aqc::UniChannel {
        psk_length_in_bytes: u16::MAX,
        parent_cmd_id: Id::random(eng),
        our_sk: &sk1,
        seal_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("sender id should be valid"),
        their_pk: &sk2
            .public()
            .expect("receiver public encryption key should be valid"),
        open_id: IdentityKey::<E::CS>::new(eng)
            .id()
            .expect("receiver id should be valid"),
        label,
    };
    let ch2 = aqc::UniChannel {
        psk_length_in_bytes: 33,
        parent_cmd_id: ch1.parent_cmd_id,
        our_sk: &sk2,
        seal_id: ch1.seal_id,
        their_pk: &sk1
            .public()
            .expect("receiver public encryption key should be valid"),
        open_id: ch1.open_id,
        label,
    };
    assert_ne!(ch1.info(), ch2.info());

    let aqc::UniSecrets { peer, .. } = {
        let err = aqc::UniSecrets::new(eng, &ch1)
            .err()
            .expect("should not be able to create `aqc::UniSecrets`");
        assert_eq!(err, Error::invalid_psk_length());

        ch1.psk_length_in_bytes = 32;
        aqc::UniSecrets::new(eng, &ch1).expect("unable to create `aqc::UniSecrets`")
    };

    let err = aqc::UniSecret::from_peer_encap(&ch2, peer)
        .expect_err("should not be able to decrypt `aqc::UniSecret`");
    assert_eq!(err, Error::invalid_psk_length());
}

/// Different cipher suites should create different
/// [`aqc::UniSendPsk`] and [`aqc::UniRecvPsk`]s.
///
/// E.g., derive(label, u1, u2, c1) != derive(label, u2, u1, c2).
pub fn test_aqc_derive_uni_psk_different_cipher_suites<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let label = Id::random(eng);
    let ch1 = aqc::UniChannel {
        psk_length_in_bytes: 32,
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
    let ch2 = aqc::UniChannel {
        psk_length_in_bytes: 32,
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

    let aqc::UniSecrets { author, peer } =
        aqc::UniSecrets::new(eng, &ch1).expect("unable to create `aqc::UniSecrets`");
    let psk1 = aqc::UniSecret::from_author_secret(&ch1, author)
        .expect("unable to decrypt author `aqc::UniSecret`")
        .generate_send_only_psk(aqc::CipherSuiteId::TlsAes128GcmSha256)
        .expect("unable to decrypt author `aqc::UniSendPsk`");
    let psk2 = aqc::UniSecret::from_peer_encap(&ch2, peer)
        .expect("unable to decrypt peer `aqc::UniSecret`")
        .generate_recv_only_psk(aqc::CipherSuiteId::TlsAes256GcmSha384)
        .expect("unable to decrypt peer `aqc::UniRecvPsk`");

    assert_ne!(psk1.identity(), psk2.identity());
    assert_ne!(psk1.raw_secret_bytes(), psk2.raw_secret_bytes());
}

/// Simple positive test for wrapping [`aqc::UniAuthorSecret`]s.
pub fn test_aqc_wrap_uni_author_secret<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::new(eng);
    let sk2 = EncryptionKey::new(eng);
    let ch = aqc::UniChannel {
        psk_length_in_bytes: 32,
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
        label: Id::random(eng),
    };

    let aqc::UniSecrets { author: want, .. } =
        aqc::UniSecrets::new(eng, &ch).expect("unable to create `aqc::UniSecrets`");
    let bytes = cbor::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `aqc::UniAuthorSecret`"),
    )
    .expect("should be able to encode wrapped `aqc::UniAuthorSecret`");
    let wrapped = cbor::from_bytes(&bytes)
        .expect("should be able to decode encoded wrapped `aqc::UniAuthorSecret`");
    let got: aqc::UniAuthorSecret<E::CS> = eng
        .unwrap(&wrapped)
        .expect("should be able to unwrap `aqc::UniAuthorSecret`");
    assert_ct_eq!(want, got);
}

/// Test that [`tls::PskSeed`] generates different PSKs for
/// different cipher suites.
pub fn test_tls_psk_different_suites<E: Engine>(eng: &mut E) {
    let seed = tls::PskSeed::<E::CS>::new(eng, &PolicyId::default());

    let mut ids = BTreeSet::new();
    let mut secrets = BTreeSet::new();

    for &cs in tls::CipherSuiteId::all() {
        let psk = seed.generate_psk(cs).unwrap();
        if !ids.insert(*psk.identity().as_bytes()) {
            panic!("duplicate PSK identity for {cs}: {}", psk.identity());
        }
        if !secrets.insert(psk.raw_secret_bytes().to_vec()) {
            panic!(
                "duplicate PSK secret for {cs}: {:?}",
                psk.raw_secret_bytes()
            );
        }
    }
}

/// Test that [`tls::PskSeed`] generates different PSKs for
/// different policy IDs, even if the cipher suites are the same.
pub fn test_tls_psk_different_policy_ids<E: Engine>(eng: &mut E) {
    let ikm = <[u8; 32]>::random(eng);
    let mut ids = BTreeSet::new();
    let mut secrets = BTreeSet::new();
    for &cs in tls::CipherSuiteId::all() {
        for i in 0..100 {
            // Same IKM, but different policy ID, so the PRK
            // (and therefore PSKs) should be different.
            let seed = tls::PskSeed::<E::CS>::from_ikm(&ikm, &Id::random(eng).into_id());

            let psk = seed.generate_psk(cs).unwrap();
            if !ids.insert(*psk.identity().as_bytes()) {
                panic!("duplicate PSK identity for {i},{cs}: {}", psk.identity());
            }
            if !secrets.insert(psk.raw_secret_bytes().to_vec()) {
                panic!(
                    "duplicate PSK secret for {i},{cs}: {:?}",
                    psk.raw_secret_bytes()
                );
            }
        }
    }
}

/// Simple positive test for wrapping [`tls::PskSeed`]s.
pub fn test_tls_psk_seed_simple_wrap<E: Engine>(eng: &mut E) {
    let want = tls::PskSeed::new(eng, &PolicyId::default());
    let bytes = cbor::to_allocvec(
        &eng.wrap(want.clone())
            .expect("should be able to wrap `tls::PskSeed`"),
    )
    .expect("should be able to encode wrapped `tls::PskSeed`");
    let wrapped =
        cbor::from_bytes(&bytes).expect("should be able to decode encoded wrapped `tls::PskSeed`");
    let got: tls::PskSeed<E::CS> = eng
        .unwrap(&wrapped)
        .expect("should be able to unwrap `tls::PskSeed`");
    assert_eq!(want.id(), got.id());
}

/// Simple positive test for encrypting/decrypting
/// [`tls::PskSeed`]s.
pub fn test_tls_psk_seed_seal_open<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let pk1 = sk1.public().expect("`sk1` public half should be valid");

    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let pk2 = sk2.public().expect("`sk2` public half should be valid");

    let group = GroupId::default();
    let seed = tls::PskSeed::new(eng, &PolicyId::default());

    let (enc, ct) = {
        let (enc, ct) = sk1
            .seal_psk_seed(eng, &seed, &pk2, &group)
            .expect("unable to encrypt `PskSeed`");

        // Make sure that we can encode and decode the encap and
        // ciphertext.
        let enc_buf = cbor::to_allocvec(&enc).expect("unable to encode `PskSeedEnc`");
        let ct_buf = cbor::to_allocvec(&ct).expect("unable to encode `PskSeedCt`");

        let enc = cbor::from_bytes(&enc_buf).expect("unable to decode `PskSeedEnc`");
        let ct = cbor::from_bytes(&ct_buf).expect("unable to decode `PskSeedCt`");
        (enc, ct)
    };

    let got = sk2
        .open_psk_seed(&enc, ct, &pk1, &group)
        .expect("unable to decrypt `PskSeed`");
    assert_ct_eq!(got, seed);
}

/// Negative test for decrypting a [`tls::PskSeed`] with the
/// wrong peer public key.
pub fn test_tls_psk_seed_open_wrong_peer_pk<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::<E::CS>::new(eng);

    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let pk2 = sk2.public().expect("`sk2` public half should be valid");

    let sk3 = EncryptionKey::<E::CS>::new(eng);
    let pk3 = sk3.public().expect("`sk3` public half should be valid");

    assert_ne!(pk2, pk3); // pedantic

    let group = GroupId::default();
    let seed = tls::PskSeed::new(eng, &PolicyId::default());
    let (enc, ct) = sk1
        .seal_psk_seed(eng, &seed, &pk2, &group)
        .expect("unable to encrypt `PskSeed`");
    // The peer is `pk1`, `pk3`.
    let err = sk2
        .open_psk_seed(&enc, ct, &pk3, &group)
        .expect_err("`PskSeed` decryption should fail");
    assert_eq!(err, Error::Hpke(HpkeError::Open(OpenError::Authentication)));
}

/// Negative test for decrypting a [`tls::PskSeed`] with the
/// wrong secret key (i.e., trying to open a PSK seed that was
/// encrypted for somebody else).
pub fn test_tls_psk_seed_open_wrong_sk<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let pk1 = sk1.public().expect("`pk1` public half should be valid");

    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let pk2 = sk2.public().expect("`sk2` public half should be valid");

    let sk3 = EncryptionKey::<E::CS>::new(eng);

    assert_ct_ne!(sk2.id().unwrap(), sk3.id().unwrap()); // pedantic

    let group = GroupId::default();
    let seed = tls::PskSeed::new(eng, &PolicyId::default());
    let (enc, ct) = sk1
        .seal_psk_seed(eng, &seed, &pk2, &group)
        .expect("unable to encrypt `PskSeed`");
    // `(enc, ct)` are for `(sk2, pk2)`, not `(sk3, pk3)`.
    let err = sk3
        .open_psk_seed(&enc, ct, &pk1, &group)
        .expect_err("`PskSeed` decryption should fail");
    assert_eq!(err, Error::Hpke(HpkeError::Open(OpenError::Authentication)));
}

/// Negative test for decrypting a [`tls::PskSeed`] with the
/// wrong group ID.
pub fn test_tls_psk_seed_open_wrong_group<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let pk1 = sk1.public().expect("`pk1` public half should be valid");

    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let pk2 = sk2.public().expect("`sk2` public half should be valid");

    let group1 = GroupId::random(eng);
    let group2 = GroupId::random(eng);
    assert_ne!(group1, group2); // pedantic

    let seed = tls::PskSeed::new(eng, &PolicyId::default());
    let (enc, ct) = sk1
        .seal_psk_seed(eng, &seed, &pk2, &group1)
        .expect("unable to encrypt `PskSeed`");
    let err = sk2
        .open_psk_seed(&enc, ct, &pk1, &group2)
        .expect_err("`PskSeed` decryption should fail");
    assert_eq!(err, Error::Hpke(HpkeError::Open(OpenError::Authentication)));
}

/// Negative test for decrypting a [`tls::PskSeed`] with
/// malformed ciphertext.
pub fn test_tls_psk_seed_open_wrong_ciphertext<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let pk1 = sk1.public().expect("`pk1` public half should be valid");

    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let pk2 = sk2.public().expect("`sk2` public half should be valid");

    let group = GroupId::default();

    let seed = tls::PskSeed::new(eng, &PolicyId::default());
    let (enc, mut ct) = sk1
        .seal_psk_seed(eng, &seed, &pk2, &group)
        .expect("unable to encrypt `PskSeed`");

    ct.ciphertext[0] = ct.ciphertext[0].wrapping_add(1);

    let err = sk2
        .open_psk_seed(&enc, ct, &pk1, &group)
        .expect_err("`PskSeed` decryption should fail");
    assert_eq!(err, Error::Hpke(HpkeError::Open(OpenError::Authentication)));
}

/// Negative test for decrypting a [`tls::PskSeed`] with
/// malformed auth tag.
pub fn test_tls_psk_seed_open_wrong_tag<E: Engine>(eng: &mut E) {
    let sk1 = EncryptionKey::<E::CS>::new(eng);
    let pk1 = sk1.public().expect("`pk1` public half should be valid");

    let sk2 = EncryptionKey::<E::CS>::new(eng);
    let pk2 = sk2.public().expect("`sk2` public half should be valid");

    let group = GroupId::default();

    let seed = tls::PskSeed::new(eng, &PolicyId::default());
    let (enc, mut ct) = sk1
        .seal_psk_seed(eng, &seed, &pk2, &group)
        .expect("unable to encrypt `PskSeed`");

    ct.tag[0] = ct.tag[0].wrapping_add(1);

    let err = sk2
        .open_psk_seed(&enc, ct, &pk1, &group)
        .expect_err("`PskSeed` decryption should fail");
    assert_eq!(err, Error::Hpke(HpkeError::Open(OpenError::Authentication)));
}
