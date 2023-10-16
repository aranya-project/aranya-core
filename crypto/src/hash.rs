//! Cryptographic hash functions.
//!
//! # Warning
//!
//! This is a low-level module. You should not be be directly
//! using it directly unless you are implementing an engine.

#![forbid(unsafe_code)]

use core::{
    borrow::{Borrow, BorrowMut},
    fmt::Debug,
};

use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};

/// Hash algorithm identifiers.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize, MaxSize)]
pub enum HashId {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512/256.
    Sha512_256,
    /// SHA-512.
    Sha512,
    /// Some other hash function.
    Other(u16),
}

impl HashId {
    pub(crate) const fn to_u16(self) -> u16 {
        match self {
            Self::Sha256 => 0x0001,
            Self::Sha384 => 0x0002,
            Self::Sha512_256 => 0x0003,
            Self::Sha512 => 0x0004,
            Self::Other(id) => id,
        }
    }
}

/// A cryptographic hash function.
///
/// # Requirements
///
/// The function must:
///
/// * Have pre-image resistance
/// * Be collision resistant (and thus second pre-image
///   resistance)
///
/// The function does not need to be resistant to
/// length-extension attacks.
///
/// Examples of cryptographic hash functions that fulfill
/// these requirements include SHA-256, SHA-512, and SHA3-512.
pub trait Hash: Clone {
    /// Uniquely identifies the hash algorithm.
    const ID: HashId;

    /// The size in bytes of a [`Self::Digest`].
    const DIGEST_SIZE: usize;

    /// The output of the hash function.
    type Digest: Borrow<[u8]> + Debug + Eq;

    /// The size in bytes of a [`Self::Block`].
    const BLOCK_SIZE: usize;

    /// An individual block.
    type Block: Borrow<[u8]> + BorrowMut<[u8]> + Default + Clone;

    /// Creates a new [`Hash`].
    fn new() -> Self;

    /// Adds `data` to the running hash.
    fn update(&mut self, data: &[u8]);

    /// Returns the current digest.
    fn digest(self) -> Self::Digest;

    /// Returns the digest of `data`.
    ///
    /// While this function is provided by default,
    /// implementations of [`Hash`] are encouraged to provide
    /// optimized "single-shot" implementations.
    fn hash(data: &[u8]) -> Self::Digest
    where
        Self: Sized,
    {
        let mut h = Self::new();
        h.update(data);
        h.digest()
    }
}

/// An hash function block.
#[derive(Clone)]
pub struct Block<const N: usize>([u8; N]);

impl<const N: usize> Default for Block<N> {
    #[inline]
    fn default() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> Borrow<[u8]> for Block<N> {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.0.borrow()
    }
}

impl<const N: usize> BorrowMut<[u8]> for Block<N> {
    #[inline]
    fn borrow_mut(&mut self) -> &mut [u8] {
        self.0.borrow_mut()
    }
}

/// A cryptographic hash over a set of strings such that each
/// element is unambiguously encoded per [NIST SP 800-185].
///
/// In short, this means that for some tuple hash `H`, `H("abc",
/// "d")` creates a different hash value from `H("abcd")`,
/// `H("a", "bcd")`, etc.
///
/// Note that this means that zero-length strings are
/// significant. For example, `H("", "a")` is distinct from
/// `H("a")`.
///
/// [NIST SP 800-185]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
pub fn tuple_hash<H: Hash, I: IntoIterator>(s: I) -> H::Digest
where
    I::Item: AsRef<[u8]>,
{
    // TupleHash(X, L, S)
    // 1. z = "".
    // 2. n = the number of input strings in the tuple X.
    // 3. for i = 1 to n:
    //        z = z || encode_string(X[i]).
    // 4. newX = z || right_encode(L).
    let mut h = H::new();
    for v in s {
        encode_string(&mut h, v.as_ref())
    }
    right_encode(&mut h, H::DIGEST_SIZE as u64);
    h.digest()
}

#[inline(always)]
fn encode_string<H: Hash>(h: &mut H, s: &[u8]) {
    left_encode(h, s.len() as u64);
    h.update(s);
}

#[inline(always)]
fn left_encode<H: Hash>(h: &mut H, v: u64) {
    let mut b = [0u8; 9];
    b[1..].copy_from_slice(&v.to_be_bytes());
    let mut i = 1;
    while i < 8 && b[i] == 0 {
        i += 1;
    }
    b[i - 1] = (9 - i) as u8;
    h.update(&b[i - 1..]);
}

#[inline(always)]
fn right_encode<H: Hash>(h: &mut H, v: u64) {
    let mut b = [0u8; 9];
    b[..8].copy_from_slice(&v.to_be_bytes());
    let mut i = 0;
    while i < 7 && b[i] == 0 {
        i += 1;
    }
    b[8] = (8 - i) as u8;
    h.update(&b[i - 1..]);
}

#[cfg(test)]
mod test {
    use super::*;

    macro_rules! test_tuple_hash {
        ($name:ident, $hash:ty) => {
            #[test]
            fn $name() {
                assert_eq!(
                    tuple_hash::<$hash, _>(["abc"].iter()),
                    tuple_hash::<$hash, _>(["abc"])
                );
                assert_eq!(tuple_hash::<$hash, _>([""]), tuple_hash::<$hash, _>([""]));

                assert_ne!(
                    tuple_hash::<$hash, _>(["a", "b", "c"]),
                    tuple_hash::<$hash, _>(["abc"])
                );
                assert_ne!(
                    tuple_hash::<$hash, _>(["a", ""]),
                    tuple_hash::<$hash, _>(["a"])
                );
            }
        };
    }
    macro_rules! tuple_hash_tests {
        () => {
            use super::*;
            test_tuple_hash!(test_sha256, Sha256);
            test_tuple_hash!(test_sha384, Sha384);
            test_tuple_hash!(test_sha512, Sha512);
        };
    }

    #[cfg(feature = "boringssl")]
    mod boringssl {
        use crate::boring::{Sha256, Sha384, Sha512};
        tuple_hash_tests!();
    }

    #[cfg(feature = "bearssl")]
    mod bearssl {
        use crate::bearssl::{Sha256, Sha384, Sha512};
        tuple_hash_tests!();
    }

    mod rust {
        use crate::rust::{Sha256, Sha384, Sha512};
        tuple_hash_tests!();
    }
}
