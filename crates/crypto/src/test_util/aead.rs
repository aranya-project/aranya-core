//! [`Aead`] tests.

extern crate alloc;

use alloc::vec;

use more_asserts::assert_ge;

use super::{assert_all_zero, assert_ct_ne};
use crate::{
    aead::{Aead, Nonce, OpenError},
    csprng::Csprng,
    keys::SecretKey,
};

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
/// use crypto::{test_aead, rust::Aes256Gcm};
///
/// // Without test vectors.
/// test_aead!(aes256gcm, Aes256Gcm);
///
/// // With test vectors.
/// test_aead!(aes256gcm_with_vecs, Aes256Gcm, AeadTest::AesGcm);
/// ```
#[macro_export]
macro_rules! test_aead {
    ($name:ident, $aead:ty $(, AeadTest::$vectors:ident)?) => {
        macro_rules! test {
            ($test:ident) => {
                #[test]
                fn $test() {
                    $crate::test_util::aead::$test::<$aead, _>(&mut $crate::Rng)
                }
            };
        }

        mod $name {
            #[allow(unused_imports)]
            use super::*;

            test!(test_basic);
            test!(test_new_key);
            test!(test_round_trip);
            test!(test_in_place_round_trip);
            test!(test_bad_key);
            test!(test_bad_nonce);
            test!(test_bad_ciphertext);
            test!(test_bad_ad);
            test!(test_bad_tag);

            // TODO(eric): add tests for boundaries. E.g., nonce is
            // too long, tag is too short, etc.

            $(
                #[test]
                fn vectors() {
                    $crate::test_util::vectors::test_aead::<$aead>(
                        $crate::test_util::vectors::AeadTest::$vectors,
                    );
                }
            )?
        }
    };
}
pub use test_aead;

const GOLDEN: &[u8] = b"hello, world!";
const AD: &[u8] = b"some additional data";

/// Tests basic
pub fn test_basic<A: Aead, R: Csprng>(_rng: &mut R) {
    // The minimum key size is 128 bits.
    assert_ge!(A::KEY_SIZE, 16);
    // Must be at least 2^32-1.
    assert_ge!(A::MAX_PLAINTEXT_SIZE, u64::from(u32::MAX));
    // Must be `OVERHEAD` bytes larger than the plaintext.
    assert_eq!(
        A::MAX_CIPHERTEXT_SIZE,
        A::MAX_PLAINTEXT_SIZE + A::OVERHEAD as u64
    );
    // Must be at least 2^32-1.
    assert_ge!(A::MAX_ADDITIONAL_DATA_SIZE, u64::from(u32::MAX));
}

/// Tests that `Aead::Key::new` returns unique keys.
pub fn test_new_key<A: Aead, R: Csprng>(rng: &mut R) {
    let k1 = A::Key::new(rng);
    let k2 = A::Key::new(rng);
    assert_ct_ne!(k1, k2);
}

/// A round-trip positive test.
pub fn test_round_trip<A: Aead, R: Csprng>(rng: &mut R) {
    let key = A::Key::new(rng);
    let nonce = Nonce::<A::NonceSize>::default();
    assert_all_zero!(nonce);

    let ciphertext = {
        let mut dst = vec![0u8; GOLDEN.len() + A::OVERHEAD];
        A::new(&key)
            .seal(&mut dst[..], nonce.as_ref(), GOLDEN, AD)
            .expect("unable to encrypt data");
        dst
    };

    let plaintext = {
        let mut dst = vec![0u8; ciphertext.len() - A::OVERHEAD];
        A::new(&key)
            .open(&mut dst[..], nonce.as_ref(), &ciphertext, AD)
            .expect("unable to decrypt data");
        dst
    };
    assert_eq!(&plaintext, GOLDEN, "round trip test failed");
}

/// An in-place round-trip positive test.
pub fn test_in_place_round_trip<A: Aead, R: Csprng>(rng: &mut R) {
    let key = A::Key::new(rng);
    let nonce = Nonce::<A::NonceSize>::default();
    assert_all_zero!(nonce);

    let ciphertext = {
        let mut data = vec![0u8; GOLDEN.len() + A::OVERHEAD];
        let (out, tag) = data.split_at_mut(GOLDEN.len());
        out.clone_from_slice(GOLDEN);
        A::new(&key)
            .seal_in_place(nonce.as_ref(), out, tag, AD)
            .expect("unable to encrypt data in-place");
        data
    };

    let plaintext = {
        let mut data = ciphertext.to_vec();
        let (out, tag) = data.split_at_mut(GOLDEN.len());
        A::new(&key)
            .open_in_place(nonce.as_ref(), out, tag, AD)
            .expect("unable to decrypt data in-place");
        out.to_vec()
    };
    assert_eq!(&plaintext, GOLDEN, "in-place round trip test failed");
}

/// Decryption should fail with an incorrect key.
pub fn test_bad_key<A: Aead, R: Csprng>(rng: &mut R) {
    let nonce = Nonce::<A::NonceSize>::default();
    assert_all_zero!(nonce);

    let ciphertext = {
        let key = A::Key::new(rng);

        let mut dst = vec![0u8; GOLDEN.len() + A::OVERHEAD];
        A::new(&key)
            .seal(&mut dst[..], nonce.as_ref(), GOLDEN, AD)
            .expect("unable to encrypt data");
        dst
    };

    let key = A::Key::new(rng);
    let mut dst = vec![0u8; ciphertext.len() - A::OVERHEAD];
    let err = A::new(&key)
        .open(&mut dst[..], nonce.as_ref(), &ciphertext, AD)
        .expect_err("decryption should have failed due to a different key");
    assert_eq!(err, OpenError::Authentication);
}

/// Decryption should fail with an incorrect nonce.
pub fn test_bad_nonce<A: Aead, R: Csprng>(rng: &mut R) {
    let key = A::Key::new(rng);

    let ciphertext = {
        let mut nonce = Nonce::<A::NonceSize>::default();
        assert_all_zero!(nonce);
        nonce.as_mut().fill(b'A');

        let mut dst = vec![0u8; GOLDEN.len() + A::OVERHEAD];
        A::new(&key)
            .seal(&mut dst[..], nonce.as_ref(), GOLDEN, AD)
            .expect("unable to encrypt data");
        dst
    };

    let mut nonce = Nonce::<A::NonceSize>::default();
    assert_all_zero!(nonce);
    nonce.as_mut().fill(b'B');

    let mut dst = vec![0u8; ciphertext.len() - A::OVERHEAD];
    let err = A::new(&key)
        .open(&mut dst[..], nonce.as_ref(), &ciphertext, AD)
        .expect_err("decryption should have failed due to a modified nonce");
    assert_eq!(err, OpenError::Authentication);
}

/// Decryption should fail with a modified AD.
pub fn test_bad_ad<A: Aead, R: Csprng>(rng: &mut R) {
    let key = A::Key::new(rng);
    let nonce = Nonce::<A::NonceSize>::default();
    assert_all_zero!(nonce);

    let ciphertext = {
        let mut dst = vec![0u8; GOLDEN.len() + A::OVERHEAD];
        A::new(&key)
            .seal(&mut dst[..], nonce.as_ref(), GOLDEN, AD)
            .expect("unable to encrypt data");
        dst
    };

    let mut dst = vec![0u8; ciphertext.len() - A::OVERHEAD];
    let err = A::new(&key)
        .open(&mut dst[..], nonce.as_ref(), &ciphertext, b"some bad AD")
        .expect_err("decryption should have failed due to a modified AD");
    assert_eq!(err, OpenError::Authentication);
}

/// Decryption should fail with a modified ciphertext.
pub fn test_bad_ciphertext<A: Aead, R: Csprng>(rng: &mut R) {
    let key = A::Key::new(rng);
    let nonce = Nonce::<A::NonceSize>::default();
    assert_all_zero!(nonce);

    let mut ciphertext = {
        let mut dst = vec![0u8; GOLDEN.len() + A::OVERHEAD];
        A::new(&key)
            .seal(&mut dst[..], nonce.as_ref(), GOLDEN, AD)
            .expect("unable to encrypt data");
        dst
    };

    ciphertext[0] = ciphertext[0].wrapping_add(1);

    let mut dst = vec![0u8; ciphertext.len() - A::OVERHEAD];
    let err = A::new(&key)
        .open(&mut dst[..], nonce.as_ref(), &ciphertext, AD)
        .expect_err("decryption should have failed due to a modified ciphertext");
    assert_eq!(err, OpenError::Authentication);
}

/// Decryption should fail with a modified authentication
/// tag.
pub fn test_bad_tag<A: Aead, R: Csprng>(rng: &mut R) {
    let key = A::Key::new(rng);
    let nonce = Nonce::<A::NonceSize>::default();
    assert_all_zero!(nonce);

    let mut ciphertext = {
        let mut dst = vec![0u8; GOLDEN.len() + A::OVERHEAD];
        A::new(&key)
            .seal(&mut dst[..], nonce.as_ref(), GOLDEN, AD)
            .expect("unable to encrypt data");
        dst
    };

    // It's possible that the tag isn't at the end, but for
    // most AEADs it will be.
    let n = ciphertext.len() - 1;
    ciphertext[n] = ciphertext[n].wrapping_add(1);

    let mut dst = vec![0u8; ciphertext.len() - A::OVERHEAD];
    let err = A::new(&key)
        .open(&mut dst[..], nonce.as_ref(), &ciphertext, AD)
        .expect_err("decryption should have failed due to a modified auth tag");
    assert_eq!(err, OpenError::Authentication);
}
