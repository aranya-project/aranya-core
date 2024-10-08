//! Cryptographic hash functions.
//!
//! # Warning
//!
//! This is a low-level module. You should not be be directly
//! using it directly unless you are implementing an engine.

#![forbid(unsafe_code)]

use core::{
    borrow::{Borrow, BorrowMut},
    fmt::{self, Debug},
    num::NonZeroU16,
    ops::{Deref, DerefMut},
};

use generic_array::{ArrayLength, GenericArray, IntoArrayLength};
use subtle::{Choice, ConstantTimeEq};
use typenum::{
    generic_const_mappings::Const,
    type_operators::{IsGreaterOrEqual, IsLess},
    Unsigned, U32, U65536,
};

use crate::AlgId;

/// Hash algorithm identifiers.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, AlgId)]
pub enum HashId {
    /// SHA-256.
    #[alg_id(0x0001)]
    Sha256,
    /// SHA-384.
    #[alg_id(0x0002)]
    Sha384,
    /// SHA-512/256.
    #[alg_id(0x0003)]
    Sha512_256,
    /// SHA-512.
    #[alg_id(0x0004)]
    Sha512,
    /// Some other hash function.
    #[alg_id(Other)]
    Other(NonZeroU16),
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

    /// The size in octets of a digest used by this [`Hash`].
    ///
    /// Must be at least 32 octets and less than 2¹⁶ octets.
    type DigestSize: ArrayLength + IsGreaterOrEqual<U32> + IsLess<U65536> + 'static;
    /// Shorthand for [`DigestSize`][Self::DigestSize].
    const DIGEST_SIZE: usize = Self::DigestSize::USIZE;

    /// The size in bytes of a [`Self::Block`].
    const BLOCK_SIZE: usize;

    /// An individual block.
    type Block: Borrow<[u8]> + BorrowMut<[u8]> + Default + Clone;

    /// Creates a new [`Hash`].
    fn new() -> Self;

    /// Adds `data` to the running hash.
    fn update(&mut self, data: &[u8]);

    /// Returns the current digest.
    fn digest(self) -> Digest<Self::DigestSize>;

    /// Returns the digest of `data`.
    ///
    /// While this function is provided by default,
    /// implementations of [`Hash`] are encouraged to provide
    /// optimized "single-shot" implementations.
    fn hash(data: &[u8]) -> Digest<Self::DigestSize>
    where
        Self: Sized,
    {
        let mut h = Self::new();
        h.update(data);
        h.digest()
    }
}

/// The output of a [`Hash`].
#[derive(Clone, Default)]
#[repr(transparent)]
pub struct Digest<N: ArrayLength>(GenericArray<u8, N>);

impl<N: ArrayLength> Digest<N> {
    /// Creates a new hash digest.
    #[inline]
    pub const fn new(digest: GenericArray<u8, N>) -> Self {
        Self(digest)
    }

    /// Creates a new hash digest from an array.
    #[inline]
    pub const fn from_array<const U: usize>(digest: [u8; U]) -> Self
    where
        Const<U>: IntoArrayLength<ArrayLength = N>,
    {
        Self::new(GenericArray::from_array(digest))
    }

    /// Returns the length of the hash digest.
    #[inline]
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        N::USIZE
    }

    /// Returns the hash digest as a byte slice.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns the hash digest as a byte slice.
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Converts itself to an array.
    #[inline]
    pub fn into_array(self) -> GenericArray<u8, N> {
        self.0
    }
}

impl<N: ArrayLength> Copy for Digest<N> where N::ArrayType<u8>: Copy {}

impl<N: ArrayLength> Deref for Digest<N> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<N: ArrayLength> DerefMut for Digest<N> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<N: ArrayLength> Debug for Digest<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Digest").field(&self.0).finish()
    }
}

// Gated for safety purposes; see the comment inside
// `PartialEq::Eq`.
#[cfg(any(test, feature = "test_util"))]
impl<N: ArrayLength> Eq for Digest<N> {}

// Gated for safety purposes; see the comment inside
// `PartialEq::Eq`.
#[cfg(any(test, feature = "test_util"))]
impl<N: ArrayLength> PartialEq for Digest<N> {
    fn eq(&self, other: &Self) -> bool {
        // While it's generally fine to compare digests with ==
        // (non-constant time), it has the potential to be
        // a footgun. For example, MACs must be compared in
        // constant time, but some MACs are simply hash digests
        // (see HMAC, etc.). A naive implementation of HMAC could
        // return `Digest` directly, opening it up to side
        // channel attacks.
        //
        // To protect against this, we only allow comparisons
        // with == while testing. Out of paranoia, we also use
        // a constant time comparison for the equality check.
        bool::from(ConstantTimeEq::ct_eq(self, other))
    }
}

impl<N: ArrayLength> ConstantTimeEq for Digest<N> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
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
pub fn tuple_hash<H, I>(s: I) -> Digest<H::DigestSize>
where
    H: Hash,
    I: IntoIterator,
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
    let i = b[..8]
        .iter()
        .enumerate()
        .position(|(pos, &n)| pos > 0 && n != 0)
        .unwrap_or(8);
    // The following cannot wrap because i is always 1-8.
    b[i.wrapping_sub(1)] = (9_usize.wrapping_sub(i)) as u8;
    h.update(&b[i.wrapping_sub(1)..]);
}

#[inline(always)]
fn right_encode<H: Hash>(h: &mut H, v: u64) {
    let mut b = [0u8; 9];
    b[..8].copy_from_slice(&v.to_be_bytes());
    let i = b[..7].iter().position(|&n| n != 0).unwrap_or(7);
    // The following cannot wrap because i is always 1-7.
    b[8] = 8_usize.wrapping_sub(i) as u8;
    h.update(&b[i.wrapping_sub(1)..]);
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
