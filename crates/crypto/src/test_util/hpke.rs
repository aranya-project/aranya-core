//! [`Hpke`] tests.

extern crate alloc;

use alloc::vec;

use generic_array::GenericArray;
use typenum::U64;

use crate::{
    aead::{Aead, IndCca2},
    csprng::Csprng,
    hpke::{Hpke, Mode, OpenCtx, SealCtx},
    kdf::{Expand, Kdf, KdfError, Prk},
    kem::{DecapKey, Kem},
    keys::SecretKey,
};

/// Invokes `callback` for each HPKE test.
///
/// # Example
///
/// ```
/// use crypto::{
///     Rng,
///     rust::{
///         Aes256Gcm,
///         DhKemP256HkdfSha256,
///         HkdfSha256,
///     },
///     test_hpke,
/// };
///
/// # crypto::__doctest_os_hardware_rand!();
/// macro_rules! run_test {
///     ($test:ident) => {
///         crypto::test_util::hpke::$test::<
///             DhKemP256HkdfSha256,
///             HkdfSha256,
///             Aes256Gcm,
///             _,
///         >(&mut Rng);
///     };
/// }
/// crypto::for_each_hpke_test!(run_test);
/// ```
#[macro_export]
macro_rules! for_each_hpke_test {
    ($callback:ident) => {
        $crate::__apply! {
            $callback,
            test_round_trip,
            test_export,
        }
    };
}
pub use for_each_hpke_test;

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
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            $crate::test_hpke!($kem, $kdf, $aead $(, HpkeTest::$vectors)?);
        }
    };
    ($kem:ty, $kdf:ty, $aead:ty $(, HpkeTest::$vectors:ident)? $(,)?) => {
        macro_rules! __hpke_test {
            ($test:ident) => {
                #[test]
                fn $test() {
                    $crate::test_util::hpke::$test::<$kem, $kdf, $aead, _>(
                        &mut $crate::Rng,
                    )
                }
            };
        }
        $crate::for_each_hpke_test!(__hpke_test);

        $(
            #[test]
            fn vectors() {
                $crate::test_util::vectors::test_hpke::<$kem, $kdf, $aead>(
                    $crate::test_util::vectors::HpkeTest::$vectors,
                );
            }
        )?
    };
}
pub use test_hpke;

/// Tests the full encryption-decryption cycle.
#[allow(non_snake_case)]
pub fn test_round_trip<K: Kem, F: Kdf, A: Aead + IndCca2, R: Csprng>(rng: &mut R) {
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
        let mut dst = vec![0u8; GOLDEN.len() + SealCtx::<A>::OVERHEAD];
        send.seal(&mut dst, GOLDEN, AD).expect("encryption failed");
        dst
    };
    let plaintext = {
        let mut dst = vec![0u8; ciphertext.len() - OpenCtx::<A>::OVERHEAD];
        recv.open(&mut dst, &ciphertext, AD)
            .expect("decryption failed");
        dst
    };
    assert_eq!(plaintext, GOLDEN);
}

/// Tests that [`crate::hpke::SendCtx::export`] is the same as
/// [`crate::hpke::SendCtx::export_into`] is the same as
/// [`crate::hpke::RecvCtx::export`] is the same as
/// [`crate::hpke::RecvCtx::export_into`].
#[allow(non_snake_case)]
pub fn test_export<K: Kem, F: Kdf, A: Aead + IndCca2, R: Csprng>(rng: &mut R) {
    const INFO: &[u8] = b"some contextual binding";

    let skR = K::DecapKey::new(rng);
    let pkR = skR.public();

    let (enc, send) = Hpke::<K, F, A>::setup_send(rng, Mode::Base, &pkR, INFO)
        .expect("unable to create send context");
    let recv = Hpke::<K, F, A>::setup_recv(Mode::Base, &enc, &skR, INFO)
        .expect("unable to create recv context");

    #[derive(Debug, Default, Eq, PartialEq)]
    struct Key(GenericArray<u8, U64>);
    impl Expand for Key {
        type Size = U64;

        fn expand_multi<'a, K, I>(prk: &Prk<K::PrkSize>, info: I) -> Result<Self, KdfError>
        where
            K: Kdf,
            I: IntoIterator<Item = &'a [u8]>,
            I::IntoIter: Clone,
        {
            Ok(Self(Expand::expand_multi::<K, I>(prk, info)?))
        }
    }

    const CTX: &[u8] = b"test_export";
    let got1 = send.export::<Key>(CTX).expect("`SendCtx::export` failed");
    let got2 = {
        let mut key = Key::default();
        send.export_into(&mut key.0, CTX)
            .expect("`SendCtx::export_into` failed");
        key
    };
    let got3 = recv.export::<Key>(CTX).expect("`RecvCtx::export` failed");
    let got4 = {
        let mut key = Key::default();
        recv.export_into(&mut key.0, CTX)
            .expect("`RecvCtx::export_into` failed");
        key
    };

    assert_eq!(
        got1, got2,
        "`SendCtx::export` and `SendCtx::export_into` mismatch"
    );
    assert_eq!(
        got2, got3,
        "`SendCtx::export_into` and `RecvCtx::export` mismatch"
    );
    assert_eq!(
        got3, got4,
        "`RecvCtx::export` and `RecvCtx::export_into` mismatch"
    );
}
