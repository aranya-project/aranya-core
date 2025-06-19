//! Utilities for testing [`Ffi`] with different [`Engine`]s and
//! [`KeyStore`]s.

#![cfg(any(test, feature = "testing"))]

use core::marker::PhantomData;

use aranya_crypto::{DeviceId, EncryptionKey, Engine, Id, IdentityKey, KeyStore, SigningKey};
use aranya_policy_vm::{ident, CommandContext, PolicyContext};

use crate::ffi::Ffi;

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
