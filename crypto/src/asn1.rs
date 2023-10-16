//! ASN.1 utility routines.
//!
//! # Warning
//!
//! This is a low-level module. You should not be using it
//! directly unless you are implementing an engine.

#![forbid(unsafe_code)]

use core::{
    borrow::Borrow,
    fmt::{self, Debug},
    marker::PhantomData,
    result::Result,
};

use cfg_if::cfg_if;
use der::{asn1::UintRef, Decode, Encode, Header, Reader, SliceReader, SliceWriter, Tag};

use crate::{
    import::{Import, ImportError},
    signer::{Signature, Signer},
    util::copy,
};

cfg_if! {
    if #[cfg(feature = "error_in_core")] {
        use core::error;
    } else if #[cfg(feature = "std")] {
        use std::error;
    }
}

/// An error returned when a signature's encoding is invalid.
#[derive(Debug, Eq, PartialEq)]
pub enum EncodingError {
    /// An unknown or internal error has occurred.
    Other(&'static str),
    /// Either `r` or `s` are too large.
    OutOfRange,
    /// Unable to parse an ASN.1 DER encoded signature.
    Der(der::Error),
    /// The input is too large.
    TooLarge,
}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(msg) => write!(f, "{}", msg),
            Self::OutOfRange => write!(f, "integer out of range"),
            Self::Der(err) => write!(f, "{}", err),
            Self::TooLarge => write!(f, "DER input too large"),
        }
    }
}

#[cfg_attr(docs, doc(cfg(any(feature = "error_in_core", feature = "std"))))]
#[cfg(any(feature = "error_in_core", feature = "std"))]
impl error::Error for EncodingError {}

impl From<der::Error> for EncodingError {
    fn from(err: der::Error) -> Self {
        Self::Der(err)
    }
}

impl From<EncodingError> for ImportError {
    fn from(_err: EncodingError) -> Self {
        Self::InvalidSyntax
    }
}

/// An ASN.1 DER encoded ECDSA signature.
///
/// `N` should be the maximum number of bytes required by the
/// signature. This figure can be determined with
/// [`max_sig_len`].
pub struct Sig<S: Signer + ?Sized, const N: usize> {
    /// The ASN.1 DER encoded signature.
    ///
    /// Do not use this field directly; use `Self::as_bytes`
    /// instead. Signatures do not have a fixed size, only
    /// a maximum. Only `len` bytes are valid; the remaining
    /// bytes are undefined.
    sig: [u8; N],
    /// The number of bytes used in `sig`.
    len: usize,
    _s: PhantomData<S>,
}

impl<S: Signer + ?Sized, const N: usize> Clone for Sig<S, N> {
    fn clone(&self) -> Self {
        Self {
            sig: self.sig,
            len: self.len,
            _s: PhantomData,
        }
    }
}

impl<S: Signer + ?Sized, const N: usize> Sig<S, N> {
    // Validates the encoding of `der`.
    fn check(der: &[u8]) -> Result<(), EncodingError> {
        // sig := SEQUENCE || R || S
        let mut rd = SliceReader::new(der)?;
        let hdr = Header::decode(&mut rd)?;
        hdr.tag.assert_eq(Tag::Sequence)?;

        rd.read_nested(hdr.length, |rd| {
            UintRef::decode(rd)?;
            UintRef::decode(rd)?;
            Ok(())
        })?;
        Ok(rd.finish(())?)
    }

    /// Creates a [`Sig`] from the DER-encoded signature `der`.
    pub fn new(der: &[u8]) -> Result<Self, EncodingError> {
        if der.len() > N {
            Err(EncodingError::TooLarge)
        } else {
            Self::check(der)?;
            let mut sig = [0u8; N];
            let len = copy(&mut sig, der);
            Ok(Self {
                sig,
                len,
                _s: PhantomData,
            })
        }
    }

    /// Converts the DER-encoded signature to a 'raw' signature.
    pub fn to_raw<const M: usize>(&self) -> Result<RawSig<M>, EncodingError> {
        RawSig::from_der(self.borrow())
    }

    /// Converts a raw signature to a DER-encoded signature.
    pub fn from_raw<const R: usize>(raw: RawSig<R>) -> Result<Self, EncodingError> {
        let (r, s) = raw.integers();

        let mut sig = [0u8; N];
        let mut w = SliceWriter::new(&mut sig);
        w.sequence((r.encoded_len()? + s.encoded_len()?)?, |seq| {
            seq.encode(&r)?;
            seq.encode(&s)
        })?;
        let len = w.finish()?.len();
        Ok(Sig {
            sig,
            len,
            _s: PhantomData,
        })
    }

    /// Returns the signature as bytes.
    ///
    /// The length of the result will be in `[0, N)`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.sig[..self.len]
    }
}

impl<S: Signer + ?Sized, const N: usize> Signature<S> for Sig<S, N> {
    type Data = Self;

    fn export(&self) -> Self::Data {
        self.clone()
    }
}

impl<S: Signer + ?Sized, const N: usize> Borrow<[u8]> for Sig<S, N> {
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<S: Signer + ?Sized, const N: usize> Debug for Sig<S, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: &[u8] = Sig::borrow(self);
        s.fmt(f)
    }
}

impl<'a, S: Signer + ?Sized, const N: usize> Import<&'a [u8]> for Sig<S, N> {
    fn import(data: &'a [u8]) -> Result<Self, ImportError> {
        Self::check(data)?;

        let mut sig = [0u8; N];
        let len = copy(&mut sig, data);
        Ok(Self {
            sig,
            len,
            _s: PhantomData,
        })
    }
}

/// A 'raw' ECDSA signature.
///
/// `N` should be the maximum number of bytes required by the
/// signature. This figure can be determined with
/// [`raw_sig_len`].
///
/// `N` must be a power of two in the range `[2, 2^31]`.
#[derive(Copy, Clone, Debug)]
pub struct RawSig<const N: usize>([u8; N]);

impl<const N: usize> RawSig<N> {
    const VALID_N: () = assert!(
        // Obvious case.
        N > 0  &&
        // It is impossible to have an odd-length raw ECDSA
        // signature since it would mean that the integers have
        // different lengths.
        N % 2 == 0  &&
        // There aren't any curves with integers this short that
        // also have at least 128 bits of security.
        N/2 >= 32 &&
        // This ensures that we can convert `r` and `s` to DER
        // `INTEGER`s, which have an upper bound of 2^32 octets.
        // There aren't any curves with integers this long, so it
        // won't affect any implementations.
        N / 2 <= (u32::MAX as usize),
        "`N` is not a power of two in [2, 2^31]",
    );

    /// Forces a compilation error when `N` is out of range.
    ///
    /// Associated constants are only evaluated when evaluated, so
    /// `check` simply evaluates [`Self::VALID_N`].
    #[allow(path_statements, clippy::no_effect)]
    const fn check() {
        Self::VALID_N;
    }

    #[cfg(any(feature = "bearssl", feature = "boringssl"))]
    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        Self::check();

        self.0.as_mut_ptr()
    }

    #[cfg(any(feature = "bearssl", feature = "boringssl"))]
    pub(crate) fn as_ptr(&self) -> *const u8 {
        Self::check();

        self.0.as_ptr()
    }

    #[cfg(any(feature = "bearssl", feature = "boringssl"))]
    pub(crate) fn len(&self) -> usize {
        Self::check();

        self.0.len()
    }

    /// Returns `(r, s)`.
    fn integers(&self) -> (UintRef<'_>, UintRef<'_>) {
        Self::check();

        let (r, s) = self.0.split_at(self.0.len() / 2);
        let r = UintRef::new(r).expect("should not occur given the bounds on `N`");
        let s = UintRef::new(s).expect("should not occur given the bounds on `N`");
        (r, s)
    }

    /// Creates a [`RawSig`] from its ASN.1 DER encoding.
    fn from_der(der: &[u8]) -> Result<Self, EncodingError> {
        Self::check();

        // sig := SEQUENCE || R || S
        let mut rd = SliceReader::new(der)?;
        let hdr = Header::decode(&mut rd)?;
        hdr.tag.assert_eq(Tag::Sequence)?;

        let ret = rd.read_nested(hdr.length, |rd| {
            let r = UintRef::decode(rd)?;
            let s = UintRef::decode(rd)?;
            Ok((r, s))
        })?;

        let (r, s) = rd.finish(ret)?;
        RawSig::from_integers(r, s)
    }

    /// Creates a [`RawSig`] from `(r, s)`.
    fn from_integers(r: UintRef<'_>, s: UintRef<'_>) -> Result<Self, EncodingError> {
        Self::check();

        let r = r.as_bytes();
        let s = s.as_bytes();
        if r.len() > N / 2 || s.len() > N / 2 {
            Err(EncodingError::OutOfRange)
        } else {
            let mut raw = [0u8; N];
            // Left pad with zeros since these are big-endian
            // integers.
            copy(&mut raw[(N / 2) - r.len()..], r);
            copy(&mut raw[N - s.len()..], s);
            Ok(Self(raw))
        }
    }
}

impl<const N: usize> Default for RawSig<N> {
    fn default() -> Self {
        Self::check();

        Self([0u8; N])
    }
}

/// Returns the maximum size in bytes of a DER-encoded ECDSA
/// signature for a curve with a `bits` long field element
/// (scalar).
pub const fn max_sig_len(bits: usize) -> usize {
    // Length of an integer
    //    tag || DER(len) || len
    let n = 1 + der_len(bits + 1) + 1 + bits;
    // ECDSA signatures are two integers
    //    r || s
    let v = 2 * n;
    // DER header
    //    tag || DER(len) || len
    1 + der_len(v) + v
}

/// Returns the number of bits necessary to DER encode `n`.
const fn der_len(n: usize) -> usize {
    if n < 0x80 {
        1
    } else {
        ((n.ilog2() as usize) + 7) / 8
    }
}

/// Returns the maximum size in bytes of a 'raw' ECDSA signature
/// for a curve with a `bits` long field element (scalar).
pub const fn raw_sig_len(bits: usize) -> usize {
    let bytes = (bits + 7) / 8;
    // r || s
    bytes * 2
}
