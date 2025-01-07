//! [`Mac`] tests.

use super::{assert_ct_eq, assert_ct_ne};
use crate::{csprng::Csprng, keys::SecretKey, mac::Mac};

/// Invokes `callback` for each MAC test.
///
/// # Example
///
/// ```
/// use aranya_crypto_core::{default::Rng, rust::HmacSha256};
///
/// # aranya_crypto_core::__doctest_os_hardware_rand!();
/// macro_rules! run_test {
///     ($test:ident) => {
///         aranya_crypto_core::test_util::mac::$test::<HmacSha256, _>(&mut Rng);
///     }
/// }
/// aranya_crypto_core::for_each_mac_test!(run_test);
/// ```
#[macro_export]
macro_rules! for_each_mac_test {
    ($callback:ident) => {
        $crate::__apply! {
            $callback,
            test_default,
            test_update,
            test_verify,
            test_different_keys,
            test_different_data,
        }
    };
}

/// Performs all of the tests in this module.
///
/// This macro expands into a bunch of individual `#[test]`
/// functions.
///
/// # Example
///
/// ```
/// use aranya_crypto_core::{test_mac, rust::HmacSha256};
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
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            $crate::test_mac!($mac $(, MacTest::$vectors)?);
        }
    };
    ($mac:ty $(, MacTest::$vectors:ident)?) => {
        macro_rules! __mac_test {
            ($test:ident) => {
                #[test]
                fn $test() {
                    $crate::test_util::mac::$test::<$mac, _>(&mut $crate::default::Rng)
                }
            };
        }
        $crate::for_each_mac_test!(__mac_test);

        $(
            #[test]
            fn vectors() {
                $crate::test_util::vectors::test_mac::<$mac>(
                    $crate::test_util::vectors::MacTest::$vectors,
                );
            }
        )?
    };
}
pub use test_mac;

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
