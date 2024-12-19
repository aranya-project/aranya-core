//! TupleHash per NIST [SP 800-185].
//!
//! The code in this module is taken from [`tuple-hash`].
//!
//! [SP 800-185]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
//! [`tuple-hash`]: https://docs.rs/tuple-hash/0.5.0/tuple_hash/

use generic_array::{ArrayLength, GenericArray};
use sha3_utils::{encode_string, right_encode_bytes};

use crate::xof::{Xof, XofReader};

/// A cryptographic hash over a set of strings such that each
/// string is unambiguously encoded.
///
/// For example, the TupleHash of `("abc", "d")` will produce
/// a different hash value than the TupleHash of `("ab", "cd")`.
///
/// For the XOF variant, see [`TupleHashXof`].
///
/// # Warning
///
/// `TupleHash` is only defined for cSHAKE128 and cSHAKE256.
/// Using this with a different XOF might have worse security
/// properties.
#[derive(Clone, Debug, Default)]
pub struct TupleHash<X> {
    xof: X,
}

impl<X: Xof> TupleHash<X> {
    /// Creates a `TupleHash` with the customization string `s`.
    pub fn new(s: &[u8]) -> Self {
        Self { xof: X::new(s) }
    }

    /// Writes the string `s` to the hash.
    pub fn update(&mut self, s: &[u8]) {
        for x in &encode_string(s) {
            self.xof.update(x);
        }
    }

    /// Returns a fixed-size output.
    pub fn finalize_into(mut self, out: &mut [u8]) {
        self.xof.update(right_encode_bytes(out.len()).as_bytes());
        self.xof.finalize_xof_into(out)
    }

    /// Returns a fixed-size output.
    pub fn finalize<N: ArrayLength>(self) -> GenericArray<u8, N> {
        let mut out = GenericArray::default();
        self.finalize_into(&mut out);
        out
    }
}

/// A cryptographic hash over a set of strings such that each
/// string is unambiguously encoded.
///
/// For example, the TupleHash of `("abc", "d")` will produce
/// a different hash value than the TupleHash of `("ab", "cd")`.
///
/// # Warning
///
/// `TupleHash` is only defined for cSHAKE128 and cSHAKE256.
/// Using this with a different XOF might have worse security
/// properties.
#[derive(Clone, Debug, Default)]
pub struct TupleHashXof<X> {
    xof: X,
}

impl<X: Xof> TupleHashXof<X> {
    /// Creates a `TupleHash` with the customization string `s`.
    pub fn new(s: &[u8]) -> Self {
        Self { xof: X::new(s) }
    }

    /// Writes the string `s` to the hash.
    pub fn update(&mut self, s: &[u8]) {
        for x in &encode_string(s) {
            self.xof.update(x);
        }
    }

    /// Returns a variable-size output.
    pub fn finalize_xof(mut self) -> TupleHashXofReader<X::Reader> {
        self.xof.update(right_encode(0).as_bytes());
        TupleHashXofReader(self.xof.finalize_xof())
    }
}

/// An [`XofReader`] for [`TupleHashXof`].
#[derive(Clone, Debug)]
pub struct TupleHashXofReader<R>(R);

impl<R: XofReader> XofReader for TupleHashXofReader<R> {
    #[inline]
    fn read(&mut self, out: &mut [u8]) {
        self.0.read(out);
    }
}

/// `TupleHash` over a fixed-size set of inputs.
///
/// # Warning
///
/// `TupleHash` is only defined for cSHAKE128 and cSHAKE256.
/// Using this with a different XOF might have worse security
/// properties.
pub fn tuple_hash<X, I, N>(s: &[u8], x: I) -> GenericArray<u8, N>
where
    X: Xof,
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
    N: ArrayLength,
{
    let mut h = TupleHash::<X>::new(s);
    for xi in x {
        h.update(xi.as_ref());
    }
    h.finalize()
}

/// `TupleHashXof` over a fixed-size set of inputs.
///
/// # Warning
///
/// `TupleHashXof` is only defined for cSHAKE128 and cSHAKE256.
/// Using this with a different XOF might have worse security
/// properties.
pub fn tuple_hash_xof<X, I>(s: &[u8], x: I) -> impl XofReader
where
    X: Xof,
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    let mut h = TupleHashXof::<X>::new(s);
    for xi in x {
        h.update(xi.as_ref());
    }
    h.finalize_xof()
}
