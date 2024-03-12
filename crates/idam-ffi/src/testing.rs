//! Utilities for testing [`Ffi`] with different [`Engine`]s and
//! [`KeyStore`]s.

#![cfg(any(test, feature = "testing"))]

use core::marker::PhantomData;

use crypto::{
    aead::OpenError, hpke::HpkeError, subtle::ConstantTimeEq, EncryptionKey, Engine, GroupKey, Id,
    IdentityKey, KeyStore, SigningKey, UserId,
};
use policy_vm::{CommandContext, PolicyContext};

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
/// use crypto::{default::DefaultEngine, keystore::memstore::MemStore, Rng};
///
/// use idam_ffi::run_tests;
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
            test!(test_derive_user_id);
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
    const CTX: CommandContext<'static> = CommandContext::Policy(PolicyContext {
        name: "dummy",
        id: Id::default(),
        author: UserId::default(),
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
        let got: GroupKey<_> = eng
            .unwrap(&wrapped)
            .expect("should be able to unwrap `GroupKey`");
        assert_eq!(got.id().into_id(), key_id);
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
    pub fn test_encrypt_decrypt_message(mut eng: E, store: S) {
        let ffi = Ffi::new(store);

        let ctx = &Self::CTX;
        let StoredGroupKey { wrapped, .. } = ffi
            .generate_group_key(ctx, &mut eng)
            .expect("should be able to create `GroupKey`");

        let pk = {
            let sk = SigningKey::<E::CS>::new(&mut eng);
            postcard::to_allocvec(&sk.public()).expect("should be able to encode `VerifyingKey`")
        };

        const WANT: &[u8] = b"hello, world!";
        let ciphertext = ffi
            .encrypt_message(
                ctx,
                &mut eng,
                Id::default(),
                WANT.to_vec(),
                wrapped.clone(),
                pk.clone(),
            )
            .expect("should be able to encrypt message");
        let got = ffi
            .decrypt_message(ctx, &mut eng, Id::default(), ciphertext, wrapped, pk)
            .expect("should be able to decrypt message");
        assert_eq!(got, WANT);
    }

    /// Test that we reject messages that have been tampered
    /// with.
    pub fn test_decrypt_message_tampered_with(mut eng: E, store: S) {
        let ffi = Ffi::new(store);

        let ctx = &Self::CTX;
        let StoredGroupKey { wrapped, .. } = ffi
            .generate_group_key(ctx, &mut eng)
            .expect("should be able to create `GroupKey`");

        let pk = {
            let sk = SigningKey::<E::CS>::new(&mut eng);
            postcard::to_allocvec(&sk.public()).expect("should be able to encode `VerifyingKey`")
        };

        let mut ciphertext = ffi
            .encrypt_message(
                ctx,
                &mut eng,
                Id::default(),
                b"hello, world!".to_vec(),
                wrapped.clone(),
                pk.clone(),
            )
            .expect("should be able to encrypt message");

        ciphertext[0] = ciphertext[0].wrapping_add(1);

        let err = ffi
            .decrypt_message(ctx, &mut eng, Id::default(), ciphertext, wrapped, pk)
            .expect_err("should not be able to decrypt tampered with message");
        assert_eq!(err.kind(), ErrorKind::Crypto);

        assert_eq!(
            err.downcast_ref::<crypto::Error>(),
            Some(&crypto::Error::Open(OpenError::Authentication)),
        );
    }

    /// Test that we reject messages that are encrypted with
    /// a different command name.
    pub fn test_decrypt_message_different_cmd_name(mut eng: E, store: S) {
        let ffi = Ffi::new(store);

        let ctx = CommandContext::Policy(PolicyContext {
            name: "ctx",
            id: Id::default(),
            author: UserId::default(),
            version: Id::default(),
        });
        let StoredGroupKey { wrapped, .. } = ffi
            .generate_group_key(&ctx, &mut eng)
            .expect("should be able to create `GroupKey`");

        let pk = {
            let sk = SigningKey::<E::CS>::new(&mut eng);
            postcard::to_allocvec(&sk.public()).expect("should be able to encode `VerifyingKey`")
        };

        let ciphertext = ffi
            .encrypt_message(
                &ctx,
                &mut eng,
                Id::default(),
                b"hello, world!".to_vec(),
                wrapped.clone(),
                pk.clone(),
            )
            .expect("should be able to encrypt message");

        let ctx = CommandContext::Policy(PolicyContext {
            name: "different name",
            id: Id::default(),
            author: UserId::default(),
            version: Id::default(),
        });
        let err = ffi
            .decrypt_message(&ctx, &mut eng, Id::default(), ciphertext, wrapped, pk)
            .expect_err(
                "should not be able to decrypt message encrypted with different command name",
            );
        assert_eq!(err.kind(), ErrorKind::Crypto);
        assert_eq!(
            err.downcast_ref::<crypto::Error>(),
            Some(&crypto::Error::Open(OpenError::Authentication)),
        );
    }

    /// Test that we reject messages that are encrypted with
    /// a different parent command ID.
    pub fn test_decrypt_message_different_parent_cmd_id(mut eng: E, store: S) {
        let ffi = Ffi::new(store);

        let ctx = CommandContext::Policy(PolicyContext {
            name: "ctx",
            id: Id::default(),
            author: UserId::default(),
            version: Id::default(),
        });
        let StoredGroupKey { wrapped, .. } = ffi
            .generate_group_key(&ctx, &mut eng)
            .expect("should be able to create `GroupKey`");

        let sk = SigningKey::<E::CS>::new(&mut eng);
        let pk =
            postcard::to_allocvec(&sk.public()).expect("should be able to encode `VerifyingKey`");

        let random_parent_id = Id::random(&mut eng);
        let ciphertext = ffi
            .encrypt_message(
                &ctx,
                &mut eng,
                random_parent_id,
                b"hello, world!".to_vec(),
                wrapped.clone(),
                pk.clone(),
            )
            .expect("should be able to encrypt message");

        let ctx = CommandContext::Policy(PolicyContext {
            name: "ctx",
            id: Id::default(),
            author: UserId::default(),
            version: Id::default(),
        });
        let err = ffi
            .decrypt_message(&ctx, &mut eng, Id::default(), ciphertext, wrapped, pk)
            .expect_err(
                "should not be able to decrypt message encrypted with different parent command ID",
            );
        assert_eq!(err.kind(), ErrorKind::Crypto);
        assert_eq!(
            err.downcast_ref::<crypto::Error>(),
            Some(&crypto::Error::Open(OpenError::Authentication)),
        );
    }

    /// Test that we reject messages that are encrypted with
    /// a different author.
    pub fn test_decrypt_message_different_author(mut eng: E, store: S) {
        let ffi = Ffi::new(store);

        let ctx = CommandContext::Policy(PolicyContext {
            name: "ctx",
            id: Id::default(),
            author: UserId::default(),
            version: Id::default(),
        });
        let StoredGroupKey { wrapped, .. } = ffi
            .generate_group_key(&ctx, &mut eng)
            .expect("should be able to create `GroupKey`");

        let pk = {
            let sk = SigningKey::<E::CS>::new(&mut eng);
            postcard::to_allocvec(&sk.public()).expect("should be able to encode `VerifyingKey`")
        };
        let ciphertext = ffi
            .encrypt_message(
                &ctx,
                &mut eng,
                Id::default(),
                b"hello, world!".to_vec(),
                wrapped.clone(),
                pk.clone(),
            )
            .expect("should be able to encrypt message");

        // Create a new `pk`.
        let pk = {
            let sk = SigningKey::<E::CS>::new(&mut eng);
            postcard::to_allocvec(&sk.public()).expect("should be able to encode `VerifyingKey`")
        };
        let err = ffi
            .decrypt_message(&ctx, &mut eng, Id::default(), ciphertext, wrapped, pk)
            .expect_err("should not be able to decrypt message encrypted with different author");
        assert_eq!(err.kind(), ErrorKind::Crypto);
        assert_eq!(
            err.downcast_ref::<crypto::Error>(),
            Some(&crypto::Error::Open(OpenError::Authentication)),
        );
    }

    /// Tests that we can seal and open a `GroupKey`.
    pub fn test_seal_open_group_key(mut eng: E, mut store: S) {
        // TODO(eric): this test should really use two different
        // `Ffi`s.

        let (sk, pk) = {
            let sk = EncryptionKey::<E::CS>::new(&mut eng);
            let id = sk.id().into_id();
            let wrapped = eng
                .wrap(sk.clone())
                .expect("should be able to wrap `EncryptionKey`");
            store
                .try_insert(id, wrapped)
                .expect("should be able to insert `EncryptionKey`");
            let pk = postcard::to_allocvec(&sk.public())
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
            .open_group_key(ctx, &mut eng, sealed, sk.id().into_id(), group_id)
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
            let id = sk.id().into_id();
            let wrapped = eng
                .wrap(sk.clone())
                .expect("should be able to wrap `EncryptionKey`");
            store
                .try_insert(id, wrapped)
                .expect("should be able to insert `EncryptionKey`");
            let pk = postcard::to_allocvec(&sk.public())
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
            .open_group_key(ctx, &mut eng, sealed, sk.id().into_id(), group_id)
            .expect_err("should not be able to decrypt `GroupKey` with tampered ciphertext");
        assert_eq!(err.kind(), ErrorKind::Crypto);
        assert_eq!(
            err.downcast_ref::<crypto::Error>(),
            Some(&crypto::Error::Hpke(HpkeError::Open(
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
            let id = sk.id().into_id();
            let wrapped = eng
                .wrap(sk.clone())
                .expect("should be able to wrap `EncryptionKey`");
            store
                .try_insert(id, wrapped)
                .expect("should be able to insert `EncryptionKey`");
            let pk = postcard::to_allocvec(&sk.public())
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

        ffi.open_group_key(ctx, &mut eng, sealed, sk.id().into_id(), group_id)
            .expect_err("should not be able to decrypt `GroupKey` with tampered encap");
    }

    /// Tests that we reject `GroupKey`s encrypted with the wrong
    /// group ID.
    pub fn test_open_group_key_wrong_group_id(mut eng: E, mut store: S) {
        // TODO(eric): this test should really use two different
        // `Ffi`s.

        let (sk, pk) = {
            let sk = EncryptionKey::<E::CS>::new(&mut eng);
            let id = sk.id().into_id();
            let wrapped = eng
                .wrap(sk.clone())
                .expect("should be able to wrap `EncryptionKey`");
            store
                .try_insert(id, wrapped)
                .expect("should be able to insert `EncryptionKey`");
            let pk = postcard::to_allocvec(&sk.public())
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
            .open_group_key(ctx, &mut eng, sealed, sk.id().into_id(), wrong_group_id)
            .expect_err(
                "should not be able to decrypt `GroupKey` encrypted with a different group ID",
            );
        assert_eq!(err.kind(), ErrorKind::Crypto);
        assert_eq!(
            err.downcast_ref::<crypto::Error>(),
            Some(&crypto::Error::Hpke(HpkeError::Open(
                OpenError::Authentication
            ))),
        );
    }

    /// Round trip tests `derive_enc_key_id`.
    pub fn test_derive_enc_key_id(mut eng: E, store: S) {
        let ffi = Ffi::new(store);
        let sk = EncryptionKey::<E::CS>::new(&mut eng);
        let want = sk.public().id().into_id();
        let enc_pk = postcard::to_allocvec(&sk.public())
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
        let want = sk.public().id().into_id();
        let sign_pk =
            postcard::to_allocvec(&sk.public()).expect("should be able to encode `VerifyingKey`");
        let got = ffi
            .derive_sign_key_id(&Self::CTX, &mut eng, sign_pk)
            .expect("should be able to derive `VerifyingKey` ID");
        assert_eq!(want, got);
    }

    /// Round trip tests `derive_user_id`.
    pub fn test_derive_user_id(mut eng: E, store: S) {
        let ffi = Ffi::new(store);
        let sk = IdentityKey::<E::CS>::new(&mut eng);
        let want = sk.public().id().into_id();
        let ident_pk = postcard::to_allocvec(&sk.public())
            .expect("should be able to encode `IdentityVerifyingKey`");
        let got = ffi
            .derive_user_id(&Self::CTX, &mut eng, ident_pk)
            .expect("should be able to derive `VerifyingKey` ID");
        assert_eq!(want, got);
    }
}
