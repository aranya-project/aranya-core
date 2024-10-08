//! [`Hash`] tests.

use crate::hash::Hash;

/// Invokes `callback` for each hash test.
///
/// # Example
///
/// ```
/// use aranya_crypto::rust::Sha256;
///
/// macro_rules! run_test {
///     ($test:ident) => {
///         aranya_crypto::test_util::hash::$test::<Sha256>();
///     };
/// }
/// aranya_crypto::for_each_hash_test!(run_test);
/// ```
#[macro_export]
macro_rules! for_each_hash_test {
    ($callback:ident) => {
        $crate::__apply! {
            $callback,
            test_basic,
        }
    };
}
pub use for_each_hash_test;

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
/// use aranya_crypto::{test_hash, rust::Sha256};
///
/// test_hash!(sha256, Sha256);
/// ```
#[macro_export]
macro_rules! test_hash {
    ($name:ident, $hash:ty) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            $crate::test_hash!($hash);
        }
    };
    ($hash:ty) => {
        macro_rules! __hash_test {
            ($test:ident) => {
                #[test]
                fn $test() {
                    $crate::test_util::hash::$test::<$hash>()
                }
            };
        }
        $crate::for_each_hash_test!(__hash_test);
    };
}
pub use test_hash;

/// A basic test for a `Hash`.
pub fn test_basic<T: Hash>() {
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
