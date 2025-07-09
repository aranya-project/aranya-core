//! Utilities for testing [`Ffi`] with different [`Engine`]s and
//! [`KeyStore`]s.

#![cfg(any(test, feature = "testing"))]

use core::marker::PhantomData;

use aranya_crypto::{
    DeviceId, EncryptionKey, Engine, GroupKey, HpkeError, Id, IdentityKey, KeyStore, OpenError,
    SigningKey, id::IdExt as _, subtle::ConstantTimeEq,
};
use aranya_policy_vm::{ActionContext, CommandContext, PolicyContext, ident, text};

use crate::{
    error::ErrorKind,
    ffi::{Ffi, StoredGroupKey},
};

/// Performs all of the unit tests.
///
/// This macro expands into a bunch of individual `#[test]`
/// functions.
///
/// # Example
///
/// ```
/// use aranya_crypto::{default::DefaultEngine, keystore::memstore::MemStore, Rng};
///
/// use aranya_idam_ffi::run_tests;
///
/// run_tests!(default_engine, || -> (DefaultEngine<_, _>, MemStore) {
///     let (eng, _) = DefaultEngine::<_>::from_entropy(Rng);
///     let store = MemStore::new();
///     (eng, store)
/// });
/// ```
#[macro_export]
macro_rules! run_tests {
    ($name:ident, || -> ($engine:ty, $store:ty) { $($args:tt)+ }) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            macro_rules! test {
                ($test:ident) => {
                    #[test]
                    fn $test() {
                        let (eng, store) = { $($args)+ };
                        $crate::testing::Tests::$test(eng, store);
                    }
                };
            }

            test!(test_generate_group_key);
            test!(test_generate_unique_group_key);
            test!(test_encrypt_decrypt_message);
            test!(test_decrypt_message_tampered_with);
            test!(test_decrypt_message_different_cmd_name);
            test!(test_decrypt_message_different_parent_cmd_id);
            test!(test_decrypt_message_different_author);
            test!(test_seal_open_group_key);
            test!(test_open_group_key_ciphertext_tampered_with);
            test!(test_open_group_key_encap_tampered_with);
            test!(test_open_group_key_wrong_group_id);
            test!(test_derive_enc_key_id);
            test!(test_derive_sign_key_id);
            test!(test_derive_device_id);
        }
    };
}
#[allow(unused_imports)]
pub(crate) use run_tests;

/// The unit tests.
pub struct Tests<E, S>(PhantomData<(E, S)>);

impl<E, S> Tests<E, S>
where
    E: Engine,
    S: KeyStore,
{
    const CTX: CommandContext = CommandContext::Policy(PolicyContext {
        name: ident!("dummy"),
        id: Id::default(),
        author: DeviceId::default(),
        version: Id::default(),
    });

    /// Test that we can unwrap `GroupKey`s.
    pub fn test_generate_group_key(mut eng: E, store: S) {
        let ffi = Ffi::new(store);

        let ctx = &Self::CTX;
        let StoredGroupKey { key_id, wrapped } = ffi
            .generate_group_key(ctx, &mut eng)
            .expect("should be able to create `GroupKey`");
        let wrapped =
            postcard::from_bytes(&wrapped).expect("should be able to decode wrapped `GroupKey`");
        let got = eng
            .unwrap::<GroupKey<_>>(&wrapped)
            .expect("should be able to unwrap `GroupKey`")
            .id()
            .expect("should be able to generate `GroupKey` ID");
        assert_eq!(got.into_id(), key_id);
    }

    /// Test that we generate unique `GroupKey`s.
    pub fn test_generate_unique_group_key(mut eng: E, store: S) {
        let ffi = Ffi::new(store);

        let ctx = &Self::CTX;
        let sk1 = ffi
            .generate_group_key(ctx, &mut eng)
            .expect("should be able to create `GroupKey`");
        let sk2 = ffi
            .generate_group_key(ctx, &mut eng)
            .expect("should be able to create `GroupKey`");
        assert_ne!(sk1, sk2);
    }

    /// Test that we can encrypt then decrypt data.
    pub fn test_encrypt_decrypt_message(mut eng: E, mut store: S) {
        let (pk, key_id) = {
            let sk = SigningKey::<E::CS>::new(&mut eng);
            let id = sk.id().expect("signing key ID should be valid");
            let wrapped = eng
                .wrap(sk.clone())
                .expect("should be able to wrap `SigningKey`");
            store
                .try_insert(id.into_id(), wrapped)
                .expect("should be able to insert `SigningKey`");
            let pk =
                postcard::to_allocvec(&sk.public().expect("public signing key should be valid"))
                    .expect("should be able to encode `VerifyingKey`");
            (pk, id)
        };

        let ffi = Ffi::new(store);
        let action_ctx = CommandContext::Action(ActionContext {
            name: ident!("dummy_action"),
            head_id: Id::default(),
        });
        let ctx = &Self::CTX;

        let StoredGroupKey { wrapped, .. } = ffi
            .generate_group_key(ctx, &mut eng)
            .expect("should be able to create `GroupKey`");

        const WANT: &[u8] = b"hello, world!";
        let ciphertext = ffi
            .encrypt_message(
                &action_ctx,
                &mut eng,
                WANT.to_vec(),
                wrapped.clone(),
                key_id.into_id(),
                text!("dummy"),
            )
            .expect("should be able to encrypt message");
        let got = ffi
            .decrypt_message(ctx, &mut eng, Id::default(), ciphertext, wrapped, pk)
            .expect("should be able to decrypt message");
        assert_eq!(got, WANT);
    }

    /// Test that we reject messages that have been tampered
    /// with.
    pub fn test_decrypt_message_tampered_with(mut eng: E, mut store: S) {
        let (pk, key_id) = {
            let sk = SigningKey::<E::CS>::new(&mut eng);
            let id = sk.id().expect("signing key ID should be valid");
            let wrapped = eng
                .wrap(sk.clone())
                .expect("should be able to wrap `SigningKey`");
            store
                .try_insert(id.into_id(), wrapped)
                .expect("should be able to insert `SigningKey`");
            let pk =
                postcard::to_allocvec(&sk.public().expect("public signing key should be valid"))
                    .expect("should be able to encode `VerifyingKey`");
            (pk, id)
        };

        let ffi = Ffi::new(store);
        let ctx = &Self::CTX;
        let StoredGroupKey { wrapped, .. } = ffi
            .generate_group_key(ctx, &mut eng)
            .expect("should be able to create `GroupKey`");

        let action_ctx = CommandContext::Action(ActionContext {
            name: ident!("dummy_action"),
            head_id: Id::default(),
        });

        let mut ciphertext = ffi
            .encrypt_message(
                &action_ctx,
                &mut eng,
                b"hello, world!".to_vec(),
                wrapped.clone(),
                key_id.into_id(),
                text!("dummy"),
            )
            .expect("should be able to encrypt message");

        ciphertext[0] = ciphertext[0].wrapping_add(1);

        let err = ffi
            .decrypt_message(ctx, &mut eng, Id::default(), ciphertext, wrapped, pk)
            .expect_err("should not be able to decrypt tampered with message");
        assert_eq!(err.kind(), ErrorKind::Crypto);

        assert_eq!(
            err.downcast_ref::<aranya_crypto::Error>(),
            Some(&aranya_crypto::Error::Open(OpenError::Authentication)),
        );
    }

    /// Test that we reject messages that are encrypted with
    /// a different command name.
    pub fn test_decrypt_message_different_cmd_name(mut eng: E, mut store: S) {
        let (pk, key_id) = {
            let sk = SigningKey::<E::CS>::new(&mut eng);
            let id = sk.id().expect("signing key ID should be valid");
            let wrapped = eng
                .wrap(sk.clone())
                .expect("should be able to wrap `SigningKey`");
            store
                .try_insert(id.into_id(), wrapped)
                .expect("should be able to insert `SigningKey`");
            let pk = postcard::to_allocvec(&sk.public().expect("signing key should be valid"))
                .expect("should be able to encode `VerifyingKey`");
            (pk, id)
        };
        let ffi = Ffi::new(store);

        let ctx = &Self::CTX;
        let StoredGroupKey { wrapped, .. } = ffi
            .generate_group_key(ctx, &mut eng)
            .expect("should be able to create `GroupKey`");

        let action_ctx = CommandContext::Action(ActionContext {
            name: ident!("dummy_action"),
            head_id: Id::default(),
        });

        let ciphertext = ffi
            .encrypt_message(
                &action_ctx,
                &mut eng,
                b"hello, world!".to_vec(),
                wrapped.clone(),
                key_id.into_id(),
                text!("dummy"),
            )
            .expect("should be able to encrypt message");

        let ctx = CommandContext::Policy(PolicyContext {
            name: ident!("different_name"),
            id: Id::default(),
            author: DeviceId::default(),
            version: Id::default(),
        });
        let err = ffi
            .decrypt_message(&ctx, &mut eng, Id::default(), ciphertext, wrapped, pk)
            .expect_err(
                "should not be able to decrypt message encrypted with different command name",
            );
        assert_eq!(err.kind(), ErrorKind::Crypto);
        assert_eq!(
            err.downcast_ref::<aranya_crypto::Error>(),
            Some(&aranya_crypto::Error::Open(OpenError::Authentication)),
        );
    }

    /// Test that we reject messages that are encrypted with
    /// a different parent command ID.
    pub fn test_decrypt_message_different_parent_cmd_id(mut eng: E, mut store: S) {
        let (pk, key_id) = {
            let sk = SigningKey::<E::CS>::new(&mut eng);
            let id = sk.id().expect("signing key ID should be valid");
            let wrapped = eng
                .wrap(sk.clone())
                .expect("should be able to wrap `SigningKey`");
            store
                .try_insert(id.into_id(), wrapped)
                .expect("should be able to insert `SigningKey`");
            let pk = postcard::to_allocvec(&sk.public().expect("signing key should be valid"))
                .expect("should be able to encode `VerifyingKey`");
            (pk, id)
        };

        let ffi = Ffi::new(store);

        let ctx = &Self::CTX;
        let StoredGroupKey { wrapped, .. } = ffi
            .generate_group_key(ctx, &mut eng)
            .expect("should be able to create `GroupKey`");

        let action_ctx = CommandContext::Action(ActionContext {
            name: ident!("dummy_action"),
            head_id: Id::random(&mut eng),
        });

        let ciphertext = ffi
            .encrypt_message(
                &action_ctx,
                &mut eng,
                b"hello, world!".to_vec(),
                wrapped.clone(),
                key_id.into_id(),
                text!("dummy"),
            )
            .expect("should be able to encrypt message");

        let err = ffi
            .decrypt_message(ctx, &mut eng, Id::default(), ciphertext, wrapped, pk)
            .expect_err(
                "should not be able to decrypt message encrypted with different parent command ID",
            );
        assert_eq!(err.kind(), ErrorKind::Crypto);
        assert_eq!(
            err.downcast_ref::<aranya_crypto::Error>(),
            Some(&aranya_crypto::Error::Open(OpenError::Authentication)),
        );
    }

    /// Test that we reject messages that are encrypted with
    /// a different author.
    pub fn test_decrypt_message_different_author(mut eng: E, mut store: S) {
        let key_id = {
            let sk = SigningKey::<E::CS>::new(&mut eng);
            let id = sk.id().expect("signing key ID should be valid");
            let wrapped = eng
                .wrap(sk.clone())
                .expect("should be able to wrap `SigningKey`");
            store
                .try_insert(id.into_id(), wrapped)
                .expect("should be able to insert `SigningKey`");
            id
        };

        let ffi = Ffi::new(store);
        let ctx = &Self::CTX;
        let StoredGroupKey { wrapped, .. } = ffi
            .generate_group_key(ctx, &mut eng)
            .expect("should be able to create `GroupKey`");

        let pk = {
            let sk = SigningKey::<E::CS>::new(&mut eng);
            postcard::to_allocvec(&sk.public().expect("verifying key should be valid"))
                .expect("should be able to encode `VerifyingKey`")
        };

        let action_ctx = CommandContext::Action(ActionContext {
            name: ident!("dummy_action"),
            head_id: Id::default(),
        });

        let ciphertext = ffi
            .encrypt_message(
                &action_ctx,
                &mut eng,
                b"hello, world!".to_vec(),
                wrapped.clone(),
                key_id.into_id(),
                text!("dummy"),
            )
            .expect("should be able to encrypt message");

        let err = ffi
            .decrypt_message(ctx, &mut eng, Id::default(), ciphertext, wrapped, pk)
            .expect_err("should not be able to decrypt message encrypted with different author");
        assert_eq!(err.kind(), ErrorKind::Crypto);
        assert_eq!(
            err.downcast_ref::<aranya_crypto::Error>(),
            Some(&aranya_crypto::Error::Open(OpenError::Authentication)),
        );
    }

    /// Tests that we can seal and open a `GroupKey`.
    pub fn test_seal_open_group_key(mut eng: E, mut store: S) {
        // TODO(eric): this test should really use two different
        // `Ffi`s.

        let (sk, pk) = {
            let sk = EncryptionKey::<E::CS>::new(&mut eng);
            let id = sk
                .id()
                .expect("encryption key ID should be valid")
                .into_id();
            let wrapped = eng
                .wrap(sk.clone())
                .expect("should be able to wrap `EncryptionKey`");
            store
                .try_insert(id, wrapped)
                .expect("should be able to insert `EncryptionKey`");
            let pk =
                postcard::to_allocvec(&sk.public().expect("encryption public key should be valid"))
                    .expect("should be able to encode `EncryptionPublicKey`");
            (sk, pk)
        };

        let ffi = Ffi::new(store);

        let ctx = &Self::CTX;
        let want = ffi
            .generate_group_key(ctx, &mut eng)
            .expect("should be able to create `GroupKey`");

        let group_id = Id::random(&mut eng);
        let sealed = ffi
            .seal_group_key(ctx, &mut eng, want.wrapped.clone(), pk, group_id)
            .expect("should be able to encrypt `GroupKey`");

        let got = ffi
            .open_group_key(
                ctx,
                &mut eng,
                sealed,
                sk.id()
                    .expect("encryption key ID should be valid")
                    .into_id(),
                group_id,
            )
            .expect("should be able to decrypt `GroupKey`");

        // NB: we can't just check `assert_eq!(want, got)`
        // because the `wrapped` field is ciphertext and might
        // have a different nonce, etc.
        assert_eq!(got.key_id, want.key_id);

        // Check the actual `GroupKey`s.
        let want: GroupKey<E::CS> = {
            let wrapped = postcard::from_bytes(&want.wrapped)
                .expect("should be able to decode wrapped `GroupKey`");
            eng.unwrap(&wrapped)
                .expect("should be able to unwrap `GroupKey`")
        };
        let got: GroupKey<E::CS> = {
            let wrapped = postcard::from_bytes(&got.wrapped)
                .expect("should be able to decode wrapped `GroupKey`");
            eng.unwrap(&wrapped)
                .expect("should be able to unwrap `GroupKey`")
        };
        assert!(
            bool::from(got.ct_eq(&want)),
            "`GroupKeys` differ, but have same ID"
        )
    }

    /// Tests that we reject encrypted `GroupKey`s where the
    /// ciphertext has been tampered with.
    pub fn test_open_group_key_ciphertext_tampered_with(mut eng: E, mut store: S) {
        // TODO(eric): this test should really use two different
        // `Ffi`s.

        let (sk, pk) = {
            let sk = EncryptionKey::<E::CS>::new(&mut eng);
            let id = sk
                .id()
                .expect("encryption key ID should be valid")
                .into_id();
            let wrapped = eng
                .wrap(sk.clone())
                .expect("should be able to wrap `EncryptionKey`");
            store
                .try_insert(id, wrapped)
                .expect("should be able to insert `EncryptionKey`");
            let pk =
                postcard::to_allocvec(&sk.public().expect("encryption public key should be valid"))
                    .expect("should be able to encode `EncryptionPublicKey`");
            (sk, pk)
        };

        let ffi = Ffi::new(store);

        let ctx = &Self::CTX;
        let want = ffi
            .generate_group_key(ctx, &mut eng)
            .expect("should be able to create `GroupKey`");

        let group_id = Id::random(&mut eng);
        let mut sealed = ffi
            .seal_group_key(ctx, &mut eng, want.wrapped.clone(), pk, group_id)
            .expect("should be able to encrypt `GroupKey`");

        sealed.ciphertext[0] = sealed.ciphertext[0].wrapping_add(1);

        let err = ffi
            .open_group_key(
                ctx,
                &mut eng,
                sealed,
                sk.id()
                    .expect("encryption key ID should be valid")
                    .into_id(),
                group_id,
            )
            .expect_err("should not be able to decrypt `GroupKey` with tampered ciphertext");
        assert_eq!(err.kind(), ErrorKind::Crypto);
        assert_eq!(
            err.downcast_ref::<aranya_crypto::Error>(),
            Some(&aranya_crypto::Error::Hpke(HpkeError::Open(
                OpenError::Authentication
            ))),
        );
    }

    /// Tests that we reject encrypted `GroupKey`s where the
    /// encapsulated key has been tampered with.
    pub fn test_open_group_key_encap_tampered_with(mut eng: E, mut store: S) {
        // TODO(eric): this test should really use two different
        // `Ffi`s.

        let (sk, pk) = {
            let sk = EncryptionKey::<E::CS>::new(&mut eng);
            let id = sk
                .id()
                .expect("encryption key ID should be valid")
                .into_id();
            let wrapped = eng
                .wrap(sk.clone())
                .expect("should be able to wrap `EncryptionKey`");
            store
                .try_insert(id, wrapped)
                .expect("should be able to insert `EncryptionKey`");
            let pk =
                postcard::to_allocvec(&sk.public().expect("encryption public key should be valid"))
                    .expect("should be able to encode `EncryptionPublicKey`");
            (sk, pk)
        };

        let ffi = Ffi::new(store);

        let ctx = &Self::CTX;
        let want = ffi
            .generate_group_key(ctx, &mut eng)
            .expect("should be able to create `GroupKey`");

        let group_id = Id::random(&mut eng);
        let mut sealed = ffi
            .seal_group_key(ctx, &mut eng, want.wrapped.clone(), pk, group_id)
            .expect("should be able to encrypt `GroupKey`");

        // We don't know the structure of `v`, so clobber the
        // entire thing to try and make sure it's unusable.
        for v in &mut sealed.encap {
            *v = v.wrapping_add(1);
        }

        ffi.open_group_key(
            ctx,
            &mut eng,
            sealed,
            sk.id()
                .expect("encryption key ID should be valid")
                .into_id(),
            group_id,
        )
        .expect_err("should not be able to decrypt `GroupKey` with tampered encap");
    }

    /// Tests that we reject `GroupKey`s encrypted with the wrong
    /// group ID.
    pub fn test_open_group_key_wrong_group_id(mut eng: E, mut store: S) {
        // TODO(eric): this test should really use two different
        // `Ffi`s.

        let (sk, pk) = {
            let sk = EncryptionKey::<E::CS>::new(&mut eng);
            let id = sk
                .id()
                .expect("encryption key ID should be valid")
                .into_id();
            let wrapped = eng
                .wrap(sk.clone())
                .expect("should be able to wrap `EncryptionKey`");
            store
                .try_insert(id, wrapped)
                .expect("should be able to insert `EncryptionKey`");
            let pk =
                postcard::to_allocvec(&sk.public().expect("encryption public key should be valid"))
                    .expect("should be able to encode `EncryptionPublicKey`");
            (sk, pk)
        };

        let ffi = Ffi::new(store);

        let ctx = &Self::CTX;
        let want = ffi
            .generate_group_key(ctx, &mut eng)
            .expect("should be able to create `GroupKey`");

        let group_id = Id::random(&mut eng);
        let sealed = ffi
            .seal_group_key(ctx, &mut eng, want.wrapped.clone(), pk, group_id)
            .expect("should be able to encrypt `GroupKey`");

        let wrong_group_id = Id::random(&mut eng);
        let err = ffi
            .open_group_key(
                ctx,
                &mut eng,
                sealed,
                sk.id()
                    .expect("encryption key ID should be valid")
                    .into_id(),
                wrong_group_id,
            )
            .expect_err(
                "should not be able to decrypt `GroupKey` encrypted with a different group ID",
            );
        assert_eq!(err.kind(), ErrorKind::Crypto);
        assert_eq!(
            err.downcast_ref::<aranya_crypto::Error>(),
            Some(&aranya_crypto::Error::Hpke(HpkeError::Open(
                OpenError::Authentication
            ))),
        );
    }

    /// Round trip tests `derive_enc_key_id`.
    pub fn test_derive_enc_key_id(mut eng: E, store: S) {
        let ffi = Ffi::new(store);
        let sk = EncryptionKey::<E::CS>::new(&mut eng);
        let want = sk
            .public()
            .expect("encryption public key should be valid")
            .id()
            .expect("encryption key ID should be valid")
            .into_id();
        let enc_pk =
            postcard::to_allocvec(&sk.public().expect("public encryption key should be valid"))
                .expect("should be able to encode `EncryptionPublicKey`");
        let got = ffi
            .derive_enc_key_id(&Self::CTX, &mut eng, enc_pk)
            .expect("should be able to derive `EncryptionPublicKey` ID");
        assert_eq!(want, got);
    }

    /// Round trip tests `derive_sign_key_id`.
    pub fn test_derive_sign_key_id(mut eng: E, store: S) {
        let ffi = Ffi::new(store);
        let sk = SigningKey::<E::CS>::new(&mut eng);
        let want = sk
            .public()
            .expect("verifying key should be valid")
            .id()
            .expect("signing key ID should be valid")
            .into_id();
        let sign_pk = postcard::to_allocvec(&sk.public().expect("verifying key should be valid"))
            .expect("should be able to encode `VerifyingKey`");
        let got = ffi
            .derive_sign_key_id(&Self::CTX, &mut eng, sign_pk)
            .expect("should be able to derive `VerifyingKey` ID");
        assert_eq!(want, got);
    }

    /// Round trip tests `derive_device_id`.
    pub fn test_derive_device_id(mut eng: E, store: S) {
        let ffi = Ffi::new(store);
        let sk = IdentityKey::<E::CS>::new(&mut eng);
        let want = sk
            .public()
            .expect("identity verifying key should be valid")
            .id()
            .expect("device ID should be valid")
            .into_id();
        let ident_pk =
            postcard::to_allocvec(&sk.public().expect("identity verifying key should be valid"))
                .expect("should be able to encode `IdentityVerifyingKey`");
        let got = ffi
            .derive_device_id(&Self::CTX, &mut eng, ident_pk)
            .expect("should be able to derive `VerifyingKey` ID");
        assert_eq!(want, got);
    }
}
