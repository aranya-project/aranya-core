//! Constant time hexadecimal encoding and decoding.

use {
    crate::hybrid_array::{
        typenum::{
            consts::{U128, U133, U2, U32, U33, U48, U49, U64, U65, U66, U67, U97},
            Double, Integer, PartialQuot, Unsigned, B1, Z0,
        },
        ArrayOps, ArraySize, ByteArray,
    },
    cfg_if::cfg_if,
    core::{
        borrow::Borrow,
        fmt,
        ops::{Div, Rem, Shl},
        result::Result,
        str,
    },
    subtle::{Choice, ConditionallySelectable},
};

cfg_if! {
    if #[cfg(feature = "error_in_core")] {
        use core::error;
    } else if #[cfg(feature = "std")] {
        use std::error;
    }
}

/// Implemented by types that can encode themselves as hex.
pub trait ToHex {
    /// A hexadecimal string.
    type Output: Borrow<str>;

    /// Encodes itself as a hexadecimal string.
    fn to_hex(&self) -> Self::Output;
}

macro_rules! hex_impl {
    ($($len:ty),+ $(,)?) => {
        $(
            impl ToHex for [u8; <$len>::USIZE] {
                type Output = HexString<$len>;

                fn to_hex(&self) -> Self::Output {
                    HexString::from(ByteArray::from_core_array(*self))
                }
            }
        )+
    };
}
pub(crate) use hex_impl;

hex_impl! {
    U32, // P-256, X25519, ...
    U33, // X9.62 compressed P-256
    U48, // P-384
    U49, // X9.62 compressed P-384
    U64,
    U65, // X9.62 uncompressed P-256, Ed25519, ...
    U66, // P-521
    U67, // X9.62 compressed P-521
    U97, // X9.62 uncompressed P-384
    U128,
    U133, // X9.62 uncompressed P-521
}

impl<N: ArraySize> ToHex for ByteArray<N>
where
    N: ArraySize + Shl<B1>,
    Double<N>: ArraySize,
{
    type Output = HexString<N>;

    fn to_hex(&self) -> Self::Output {
        HexString::from_bytes(self)
    }
}

impl<N: ArraySize> From<ByteArray<N>> for HexString<N>
where
    N: ArraySize + Shl<B1>,
    Double<N>: ArraySize,
{
    fn from(v: ByteArray<N>) -> HexString<N> {
        HexString::from_bytes(&v)
    }
}

/// A hexadecimal string.
pub struct HexString<N: ArraySize>(ByteArray<Double<N>>)
where
    N: ArraySize + Shl<B1>,
    Double<N>: ArraySize;

impl<N: ArraySize> HexString<N>
where
    N: ArraySize + Shl<B1>,
    Double<N>: ArraySize,
{
    /// Returns a string slice containing the entire
    /// [`HexString`].
    pub fn as_str(&self) -> &str {
        // SAFETY: `ct_encode` only generates valid UTF-8.
        unsafe { str::from_utf8_unchecked(self.0.as_ref()) }
    }

    /// Creates a hexadecimal string from `data`.
    pub fn from_bytes<T>(data: T) -> Self
    where
        T: Borrow<ByteArray<N>>,
        N: ArraySize + Shl<B1>,
        Double<N>: ArraySize,
    {
        let mut out = ByteArray::default();
        let n = ct_encode(&mut out, data.borrow()).expect("sizes should be correct");
        assert_eq!(n, out.len(), "sizes should be exact");
        Self(out)
    }

    /// Converts the hexadecimal string to raw bytes.
    pub fn to_bytes(&self) -> ByteArray<PartialQuot<N, U2>>
    where
        N: ArraySize + Div<U2> + Rem<U2, Output = Z0> + Integer,
        PartialQuot<N, U2>: ArraySize,
    {
        let mut out = ByteArray::default();
        let n = ct_decode(&mut out, self.0.borrow())
            .expect("should be valid hexadecimal and sizes correct");
        assert_eq!(n, out.len(), "sizes should be exact");
        out
    }
}

impl<N> Copy for HexString<N>
where
    N: ArraySize + Shl<B1>,
    Double<N>: ArraySize,
    <Double<N> as ArraySize>::ArrayType<u8>: Copy,
{
}

impl<N> Clone for HexString<N>
where
    N: ArraySize + Shl<B1>,
    Double<N>: ArraySize,
    <Double<N> as ArraySize>::ArrayType<u8>: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<N: ArraySize> Borrow<str> for HexString<N>
where
    N: ArraySize + Shl<B1>,
    Double<N>: ArraySize,
{
    #[inline]
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl<N: ArraySize> fmt::Display for HexString<N>
where
    N: ArraySize + Shl<B1>,
    Double<N>: ArraySize,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl<N: ArraySize> fmt::LowerHex for HexString<N>
where
    N: ArraySize + Shl<B1>,
    Double<N>: ArraySize,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<N: ArraySize> fmt::UpperHex for HexString<N>
where
    N: ArraySize + Shl<B1>,
    Double<N>: ArraySize,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Convert ASCII lowercase to uppercase.
        let s = Self(ByteArray::from_fn(|i| self.0[i] - 32));
        fmt::Display::fmt(&s, f)
    }
}

/// The hexadecimal string could not be decoded.
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// Either `dst` was too short or the length of `src` was not
    /// a multiple of two.
    InvalidLength,
    /// The input was not a valid hexadecimal string.
    InvalidEncoding,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "invalid `dst` length"),
            Self::InvalidEncoding => write!(f, "invalid hexadecimal encoding"),
        }
    }
}

#[cfg_attr(docs, doc(cfg(any(feature = "error_in_core", feature = "std"))))]
#[cfg(any(feature = "error_in_core", feature = "std"))]
impl error::Error for Error {}

/// Encodes `src` into `dst` as hexadecimal in constant time and
/// returns the number of bytes written.
///
/// `dst` must be at least twice as long as `src`.
pub fn ct_encode(dst: &mut [u8], src: &[u8]) -> Result<usize, Error> {
    // The implementation is taken from
    // https://github.com/ericlagergren/subtle/blob/890d697da01053c79157a7fdfbed548317eeb0a6/hex/constant_time.go

    if dst.len() / 2 < src.len() {
        return Err(Error::InvalidLength);
    }
    for (v, chunk) in src.iter().zip(dst.chunks_mut(2)) {
        chunk[0] = enc_nibble(v >> 4);
        chunk[1] = enc_nibble(v & 0x0f);
    }
    Ok(src.len() * 2)
}

#[inline(always)]
const fn enc_nibble(c: u8) -> u8 {
    let c = c as u16;
    (87 + c + ((c.wrapping_sub(10) >> 8) & !38)) as u8
}

/// Decodes `src` into `dst` from hexadecimal in constant time
/// and returns the number of bytes written.
///
/// * The length of `src` must be a multiple of two.
/// * `dst` must be half as long (or longer) as `src`.
pub fn ct_decode(dst: &mut [u8], src: &[u8]) -> Result<usize, Error> {
    // The implementation is taken from
    // https://github.com/ericlagergren/subtle/blob/890d697da01053c79157a7fdfbed548317eeb0a6/hex/constant_time.go

    if src.len() % 2 != 0 {
        return Err(Error::InvalidLength);
    }
    if src.len() / 2 > dst.len() {
        return Err(Error::InvalidLength);
    }

    let mut valid = Choice::from(1u8);
    for (chunk, v) in src.chunks_exact(2).zip(dst.iter_mut()) {
        let (hi, hi_ok) = dec_nibble(chunk[0]);
        let (lo, lo_ok) = dec_nibble(chunk[1]);

        valid &= hi_ok & lo_ok;

        let val = (hi << 4) | (lo & 0x0f);
        // Out of paranoia, do not update `dst` if `valid` is
        // false.
        *v = u8::conditional_select(v, &val, valid);
    }
    if bool::from(valid) {
        Ok(src.len() / 2)
    } else {
        Err(Error::InvalidEncoding)
    }
}

/// Decode a nibble from a hexadecimal character.
#[inline(always)]
fn dec_nibble(c: u8) -> (u8, Choice) {
    let c = u16::from(c);
    // Is c in '0' ... '9'?
    //
    // This is equivalent to
    //
    //    let mut n = c ^ b'0';
    //    if n < 10 {
    //        val = n;
    //    }
    //
    // which is correct because
    //     y^(16*i) < 10 ∀ y ∈ [y, y+10)
    // and '0' == 48.
    let num = c ^ u16::from(b'0');
    // If `num` < 10, subtracting 10 produces the two's
    // complement which flips the bits in [15:4] (which are all
    // zero because `num` < 10) to all one. Shifting by 8 then
    // ensures that bits [7:0] are all set to one, resulting
    // in 0xff.
    //
    // If `num` >= 10, subtracting 10 doesn't set any bits in
    // [15:8] (which are all zero because `c` < 256) and shifting
    // by 8 shifts off any set bits, resulting in 0x00.
    let num_ok = num.wrapping_sub(10) >> 8;

    // Is c in 'a' ... 'f' or 'A' ... 'F'?
    //
    // This is equivalent to
    //
    //    const MASK: u32 = ^(1<<5); // 0b11011111
    //    let a = c&MASK;
    //    if a >= b'A' && a < b'F' {
    //        val = a-55;
    //    }
    //
    // The only difference between each uppercase and
    // lowercase ASCII pair ('a'-'A', 'e'-'E', etc.) is 32,
    // or bit #5. Masking that bit off folds the lowercase
    // letters into uppercase. The the range check should
    // then be obvious. Subtracting 55 converts the
    // hexadecimal character to binary by making 'A' = 10,
    // 'B' = 11, etc.
    let alpha = (c & !32).wrapping_sub(55);
    // If `alpha` is in [10, 15], subtracting 10 results in the
    // correct binary number, less 10. Notably, the bits in
    // [15:4] are all zero.
    //
    // If `alpha` is in [10, 15], subtracting 16 returns the
    // two's complement, flipping the bits in [15:4] (which
    // are all zero because `alpha` <= 15) to one.
    //
    // If `alpha` is in [10, 15], `(alpha-10)^(alpha-16)` sets
    // the bits in [15:4] to one. Otherwise, if `alpha` <= 9 or
    // `alpha` >= 16, both halves of the XOR have the same bits
    // in [15:4], so the XOR sets them to zero.
    //
    // We shift away the irrelevant bits in [3:0], leaving only
    // the interesting bits from the XOR.
    let alpha_ok = (alpha.wrapping_sub(10) ^ alpha.wrapping_sub(16)) >> 8;

    // Bits [3:0] are either 0xf or 0x0.
    let ok = Choice::from(((num_ok ^ alpha_ok) & 1) as u8);

    // For both `num_ok` and `alpha_ok` the bits in [3:0] are
    // either 0xf or 0x0. Therefore, the bits in [3:0] are either
    // `num` or `alpha`. The bits in [7:4] are (as mentioned
    // above), either 0xf or 0x0.
    //
    // Bits [15:4] are irrelevant and should be all zero.
    let result = ((num_ok & num) | (alpha_ok & alpha)) & 0xf;

    (result as u8, ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex_char(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
            b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
            b'A'..=b'F' => Some(c.wrapping_sub(b'A').wrapping_add(10)),
            _ => None,
        }
    }

    fn valid_hex_char(c: u8) -> bool {
        from_hex_char(c).is_some()
    }

    fn must_from_hex_char(c: u8) -> u8 {
        from_hex_char(c).expect("should be a valid hex char")
    }

    /// Test every single byte.
    #[test]
    fn test_encode_exhaustive() {
        for i in 0..256 {
            const TABLE: &[u8] = b"0123456789abcdef";
            let want = [TABLE[i >> 4], TABLE[i & 0x0f]];
            let got = [enc_nibble((i as u8) >> 4), enc_nibble((i as u8) & 0x0f)];
            assert_eq!(want, got, "#{i}");
        }
    }

    /// Test every single hex character pair (fe, bb, a1, ...).
    #[test]
    fn test_decode_exhaustive() {
        for i in u16::MIN..=u16::MAX {
            let ci = i as u8;
            let cj = (i >> 8) as u8;
            let mut dst = [0u8; 1];
            let src = &[ci, cj];
            let res = ct_decode(&mut dst, src);
            if valid_hex_char(ci) && valid_hex_char(cj) {
                #[allow(clippy::panic)]
                let n = res.unwrap_or_else(|_| {
                    panic!("#{i}: should be able to decode pair '{ci:x}{cj:x}'")
                });
                assert_eq!(n, 1, "#{i}: {ci:x}{cj:x}");
                let want = must_from_hex_char(ci) << 4 | must_from_hex_char(cj);
                assert_eq!(&dst, &[want], "#{i}: {ci:x}{cj:x}");
            } else {
                res.expect_err(&format!("#{i}: should not have decoded pair '{src:?}'"));
                assert_eq!(&dst, &[0], "#{i}: {src:?}");
            }
        }
    }
}
