//! Elliptic curve utilities.
//!
//! # Warning
//!
//! This is a low-level module. You should not be using it
//! directly unless you are implementing an engine.

use {
    crate::{
        hex::{HexString, ToHex},
        hybrid_array::{
            typenum::{Double, Unsigned, B1, U133, U32, U33, U48, U49, U65, U66, U67, U97},
            ArrayOps, ArraySize, ByteArray,
        },
        import::{Import, ImportError},
        zeroize::{Zeroize, ZeroizeOnDrop},
    },
    core::{
        borrow::{Borrow, BorrowMut},
        fmt::Debug,
        ops::Shl,
    },
    subtle::{Choice, ConstantTimeEq},
};

// TODO(eric): validate the input for `Uncompressed`,
// `Compressed`, and `Scalar`?

/// An elliptic curve.
pub trait Curve: Copy + Clone + Eq + PartialEq {
    /// The size in bytes of a scalar.
    type ScalarSize: ArraySize + Unsigned + Copy + Clone + Eq + PartialEq;

    /// The size in bytes of a compressed point.
    type CompressedSize: ArraySize + Unsigned + Copy + Clone + Eq + PartialEq;

    /// The size in bytes of a uncompressed point.
    type UncompressedSize: ArraySize + Unsigned + Copy + Clone + Eq + PartialEq;
}

macro_rules! curve_impl {
    (
        $name:ident,
        $doc:expr,
        $bytes:ty,
        $comp_len:ty,
        $uncomp_len:ty $(,)?
    ) => {
        #[doc = concat!($doc, ".")]
        #[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
        pub struct $name;

        impl Curve for $name {
            type ScalarSize = $bytes;
            type CompressedSize = $comp_len;
            type UncompressedSize = $uncomp_len;
        }
    };
}
curve_impl!(Secp256r1, "NIST Curve P-256", U32, U33, U65);
curve_impl!(Secp384r1, "NIST Curve P-384", U48, U49, U97);
curve_impl!(Secp521r1, "NIST Curve P-521", U66, U67, U133);
curve_impl!(Curve25519, "Curve25519", U32, U32, U32);

macro_rules! pk_impl {
    ($name:ident, $size:ident) => {
        #[doc = concat!(stringify!($name), " elliptic curve point per [SEC] section 2.3.3.\n\n")]
        #[doc = "This is equivalent to X9.62 encoding.\n\n"]
        #[doc = "[SEC]: https://www.secg.org/sec1-v2.pdf"]
        #[derive(Default, Zeroize)]
        pub struct $name<C: Curve>(pub ByteArray<C::$size>);

        impl<C: Curve> $name<C> {
            /// Returns a raw pointer to the point.
            pub fn as_ptr(&self) -> *const u8 {
                self.0.as_ptr()
            }

            /// Returns a raw pointer to the point.
            pub fn as_mut_ptr(&mut self) -> *mut u8 {
                self.0.as_mut_ptr()
            }

            /// Returns the length of the point.
            #[allow(clippy::len_without_is_empty)]
            pub const fn len(&self) -> usize {
                C::$size::USIZE
            }
        }

        impl<C: Curve> Copy for $name<C> where <C::$size as ArraySize>::ArrayType<u8>: Copy {}
        impl<C: Curve> Clone for $name<C>
        where
            <C::$size as ArraySize>::ArrayType<u8>: Clone,
        {
            fn clone(&self) -> Self {
                Self(self.0.clone())
            }
        }

        impl<C: Curve> Eq for $name<C> where <C::$size as ArraySize>::ArrayType<u8>: PartialEq {}
        impl<C: Curve> PartialEq for $name<C>
        where
            <C::$size as ArraySize>::ArrayType<u8>: PartialEq,
        {
            fn eq(&self, other: &Self) -> bool {
                PartialEq::eq(&self.0, &other.0)
            }
        }

        impl<C: Curve> AsRef<[u8]> for $name<C> {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl<C: Curve> AsMut<[u8]> for $name<C> {
            #[inline]
            fn as_mut(&mut self) -> &mut [u8] {
                self.0.as_mut()
            }
        }

        impl<C: Curve> Borrow<[u8]> for $name<C> {
            #[inline]
            fn borrow(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl<C: Curve> BorrowMut<[u8]> for $name<C> {
            #[inline]
            fn borrow_mut(&mut self) -> &mut [u8] {
                self.0.as_mut()
            }
        }

        impl<C: Curve> ToHex for $name<C>
        where
            <C as Curve>::$size: ArraySize + Shl<B1>,
            Double<C::$size>: ArraySize,
        {
            type Output = HexString<C::$size>;

            fn to_hex(&self) -> Self::Output {
                self.0.to_hex()
            }
        }

        impl<C: Curve, const N: usize> From<$name<C>> for [u8; N]
        where
            C::$size: ArraySize,
            ByteArray<C::$size>: ArrayOps<u8, N>,
        {
            fn from(v: $name<C>) -> Self {
                *v.0.as_core_array()
            }
        }

        impl<C: Curve, const N: usize> From<[u8; N]> for $name<C>
        where
            C::$size: ArraySize,
            ByteArray<C::$size>: ArrayOps<u8, N>,
        {
            fn from(data: [u8; N]) -> Self {
                Self(data.into())
            }
        }

        impl<C: Curve> TryFrom<&[u8]> for $name<C> {
            type Error = ImportError;

            fn try_from(data: &[u8]) -> Result<Self, ImportError> {
                Self::import(data)
            }
        }

        impl<C: Curve, const N: usize> Import<[u8; N]> for $name<C>
        where
            C::$size: ArraySize,
            ByteArray<C::$size>: ArrayOps<u8, N>,
        {
            fn import(data: [u8; N]) -> Result<Self, ImportError> {
                Ok(Self::from(data))
            }
        }

        impl<C: Curve> Import<&[u8]> for $name<C> {
            fn import(data: &[u8]) -> Result<Self, ImportError> {
                let v = data.try_into().map_err(|_| ImportError::InvalidSize {
                    got: data.len(),
                    want: C::$size::USIZE..C::$size::USIZE,
                })?;
                Ok(Self(v))
            }
        }
    };
}
pk_impl!(Compressed, CompressedSize);
pk_impl!(Uncompressed, UncompressedSize);

/// An elliptic curve scalar.
#[derive(Default, ZeroizeOnDrop)]
pub struct Scalar<C: Curve>(pub ByteArray<C::ScalarSize>);

impl<C: Curve> Scalar<C> {
    /// Returns a raw pointer to the scalar.
    pub fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    /// Returns a raw pointer to the scalar.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    /// Returns the length of the scalar.
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        C::ScalarSize::USIZE
    }
}

impl<C: Curve> Clone for Scalar<C>
where
    <C::ScalarSize as ArraySize>::ArrayType<u8>: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<C: Curve> ConstantTimeEq for Scalar<C> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_ref().ct_eq(other.as_ref())
    }
}

impl<C: Curve> AsRef<[u8]> for Scalar<C> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<C: Curve> AsMut<[u8]> for Scalar<C> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<C: Curve> Borrow<[u8]> for Scalar<C> {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<C: Curve> BorrowMut<[u8]> for Scalar<C> {
    #[inline]
    fn borrow_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<C: Curve, const N: usize> From<Scalar<C>> for [u8; N]
where
    C::ScalarSize: ArraySize,
    ByteArray<C::ScalarSize>: ArrayOps<u8, N>,
{
    fn from(v: Scalar<C>) -> Self {
        *v.0.as_core_array()
    }
}

impl<C: Curve, const N: usize> From<[u8; N]> for Scalar<C>
where
    C::ScalarSize: ArraySize,
    ByteArray<C::ScalarSize>: ArrayOps<u8, N>,
{
    fn from(v: [u8; N]) -> Self {
        Self(v.into())
    }
}

impl<C: Curve> TryFrom<&[u8]> for Scalar<C> {
    type Error = ImportError;

    fn try_from(data: &[u8]) -> Result<Self, ImportError> {
        Self::import(data)
    }
}

impl<C: Curve, const N: usize> Import<[u8; N]> for Scalar<C>
where
    C::ScalarSize: ArraySize,
    ByteArray<C::ScalarSize>: ArrayOps<u8, N>,
{
    fn import(data: [u8; N]) -> Result<Self, ImportError> {
        Ok(Self::from(data))
    }
}

impl<C: Curve> Import<&[u8]> for Scalar<C> {
    fn import(data: &[u8]) -> Result<Self, ImportError> {
        let v = data.try_into().map_err(|_| ImportError::InvalidSize {
            got: data.len(),
            want: C::ScalarSize::USIZE..C::ScalarSize::USIZE,
        })?;
        Ok(Self(v))
    }
}

#[cfg(test)]
impl<C: Curve> ToHex for Scalar<C>
where
    <C as Curve>::ScalarSize: ArraySize + Shl<B1>,
    Double<C::ScalarSize>: ArraySize,
{
    type Output = HexString<C::ScalarSize>;

    fn to_hex(&self) -> Self::Output {
        self.0.to_hex()
    }
}
