//! [`Signer`] tests.

extern crate alloc;

use alloc::vec::Vec;
use core::borrow::Borrow;

use super::{assert_ct_eq, assert_ct_ne};
use crate::{
    csprng::Csprng,
    keys::SecretKey,
    signer::{Signer, SigningKey, VerifyingKey},
};

/// Invokes `callback` for each signer test.
///
/// # Example
///
/// ```
/// use aranya_crypto::{Rng, rust::P256};
///
/// # aranya_crypto::__doctest_os_hardware_rand!();
/// macro_rules! run_test {
///     ($test:ident) => {
///         aranya_crypto::test_util::signer::$test::<P256, _>(&mut Rng);
///     };
/// }
/// aranya_crypto::for_each_signer_test!(run_test);
/// ```
#[macro_export]
macro_rules! for_each_signer_test {
    ($callback:ident) => {
        $crate::__apply! {
            $callback,
            test_default,
            test_pk_eq,
            test_sk_ct_eq,
            test_public,
            test_batch_simple_good,
            test_batch_simple_bad,
        }
    };
}
pub use for_each_signer_test;

/// Performs all of the tests in this module.
///
/// This macro expands into a bunch of individual `#[test]`
/// functions.
///
/// This is used by
/// [`test_ciphersuite`][super::test_ciphersuite], but can also
/// be used manually.
///
/// # Example
///
/// ```
/// use aranya_crypto::{test_signer, rust::P256};
///
/// // Without test vectors.
/// test_signer!(p256, P256);
///
/// // With test vectors.
/// test_signer!(p256_with_vecs, P256, EcdsaTest::Secp256r1Sha256);
/// ```
#[macro_export]
macro_rules! test_signer {
    (@test $signer:ty $(, $f:ident, $which:ident, $vectors:ident)? $(,)?) => {
        macro_rules! __signer_test {
            ($test:ident) => {
                #[test]
                fn $test() {
                    $crate::test_util::signer::$test::<$signer, _>(&mut $crate::Rng)
                }
            };
        }
        $crate::for_each_signer_test!(__signer_test);

        $(
            #[test]
            fn vectors() {
                $crate::test_util::vectors::$f::<$signer>(
                    $crate::test_util::vectors::$which::$vectors,
                );
            }
        )?
    };
    ($name:ident, $signer:ty) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            $crate::test_signer!($signer);
        }
    };
    ($signer:ty) => {
        $crate::test_signer!(@test $signer);
    };
    ($name:ident, $signer:ty, EcdsaTest::$vectors:ident $(,)?) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            $crate::test_signer!($signer, EcdsaTest::$vectors);
        }
    };
    ($signer:ty, EcdsaTest::$vectors:ident $(,)?) => {
        $crate::test_signer!(@test $signer, test_ecdsa, EcdsaTest, $vectors);
    };
    ($name:ident, $signer:ty, EddsaTest::$vectors:ident $(,)?) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            $crate::test_signer!($signer, EddsaTest::$vectors);
        }
    };
    ($signer:ty, EddsaTest::$vectors:ident $(,)?) => {
        $crate::test_signer!(@test $signer, test_eddsa, EddsaTest, $vectors);
    };
}
pub use test_signer;

/// The base positive test.
pub fn test_default<T: Signer, R: Csprng>(rng: &mut R) {
    const MSG: &[u8] = b"hello, world!";
    let sk = T::SigningKey::new(rng);
    let sig = sk.sign(MSG).expect("unable to create signature");
    sk.public()
        .expect("signing key should be valid")
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
        let sk1 = K::import(data.as_bytes()).expect("should be able to import key");
        let sk2 = K::import(data.as_bytes()).expect("should be able to import key");
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
    let pk1 = T::SigningKey::new(rng)
        .public()
        .expect("signing key should be valid");
    let pk2 = T::SigningKey::new(rng)
        .public()
        .expect("signing key should be valid");

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
            (sk.public().expect("signer key should be valid"), sig)
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
            (sk.public().expect("signing key should be valid"), sig)
        })
        .unzip();
    msgs[msgs.len() / 2] = b"AAAAAAAAAAAAA";
    T::verify_batch(msgs, &sigs[..], &pks[..]).expect_err("should fail");
}
