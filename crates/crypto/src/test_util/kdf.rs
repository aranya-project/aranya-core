//! [`Kdf`] tests.

extern crate alloc;

use alloc::vec;

use more_asserts::assert_ge;

use super::assert_ct_eq;
use crate::kdf::{Kdf, KdfError};

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

/// Asserts the following:
///
/// - invoking [`Kdf::extract`] twice results in the same PRK
/// - invoking [`Kdf::expand`] twice results in the same key
/// - [`Kdf::extract_and_expand`] is the same as invoking
/// both [`Kdf::extract`] and [`Kdf::expand`].
fn check<T: Kdf>(out1: &mut [u8], out2: &mut [u8], ikm: &[u8], salt: &[u8], info: &[u8]) {
    // extract should return the same output
    assert_ct_eq!(
        T::extract(ikm, salt),
        T::extract(ikm, salt),
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
