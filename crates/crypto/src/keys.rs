//! Basic keys and key material.
//!
//! # Warning
//!
//! This is a low-level module. You should not be using it
//! directly unless you are implementing an engine.

use core::{borrow::Borrow, fmt::Debug, mem, result::Result};

use generic_array::{ArrayLength, GenericArray, IntoArrayLength};
use subtle::{Choice, ConstantTimeEq};
use typenum::{generic_const_mappings::Const, Unsigned};

use crate::{
    csprng::{Csprng, Random},
    import::{ExportError, Import},
    kdf::{Derive, Kdf, KdfError},
    zeroize::ZeroizeOnDrop,
};

/// A fixed-length secret key.
///
/// Secret keys are either symmetric keys (e.g., for AES) or
/// asymmetric private keys (e.g., for ECDH).
pub trait SecretKey: Clone + ConstantTimeEq + for<'a> Import<&'a [u8]> + ZeroizeOnDrop {
    /// Creates a random key, possibly using entropy from `rng`.
    ///
    /// Implementations are free to ignore `rng` and callers must
    /// not rely on this function reading from `rng`.
    fn new<R: Csprng>(rng: &mut R) -> Self;

    /// The size of the key.
    type Size: ArrayLength + 'static;
    /// Shorthand for [`Size`][Self::Size];
    const SIZE: usize = Self::Size::USIZE;

    /// Attempts to export the key's secret data.
    fn try_export_secret(&self) -> Result<SecretKeyBytes<Self::Size>, ExportError>;
}

/// A fixed-length byte encoding of a [`SecretKey`]'s data.
#[derive(Clone, Default, ZeroizeOnDrop)]
#[repr(transparent)]
pub struct SecretKeyBytes<N: ArrayLength>(GenericArray<u8, N>);

impl<N: ArrayLength> SecretKeyBytes<N> {
    pub(crate) const SIZE: usize = N::USIZE;

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Converts the secret key bytes to an array.
    pub fn into_bytes(mut self) -> GenericArray<u8, N> {
        // This is fine since we're consuming the receiver. If
        // the receiver were an exclusive reference this would be
        // very wrong since it'd be replacing the secret key with
        // all-zeros.
        mem::take(&mut self.0)
    }
}

impl<N: ArrayLength> ConstantTimeEq for SecretKeyBytes<N> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<N: ArrayLength> From<GenericArray<u8, N>> for SecretKeyBytes<N> {
    fn from(v: GenericArray<u8, N>) -> Self {
        Self(v)
    }
}

impl<'a, N: ArrayLength> From<&'a GenericArray<u8, N>> for &'a SecretKeyBytes<N> {
    fn from(v: &'a GenericArray<u8, N>) -> Self {
        // SAFETY: `SecretKeyBytes` and `GenericArray` have the
        // same memory layout.
        unsafe { mem::transmute(v) }
    }
}

impl<N: ArrayLength> From<SecretKeyBytes<N>> for GenericArray<u8, N> {
    fn from(sk: SecretKeyBytes<N>) -> Self {
        sk.into_bytes()
    }
}

impl<N: ArrayLength, const U: usize> From<[u8; U]> for SecretKeyBytes<N>
where
    Const<U>: IntoArrayLength<ArrayLength = N>,
{
    fn from(v: [u8; U]) -> Self {
        Self(v.into())
    }
}

impl<N: ArrayLength> Derive for SecretKeyBytes<N> {
    type Size = N;
    type Error = KdfError;
    fn expand_multi<K: Kdf>(prk: &K::Prk, info: &[&[u8]]) -> Result<Self, Self::Error> {
        let mut v = GenericArray::default();
        K::expand_multi(&mut v, prk, info)?;
        Ok(Self(v))
    }
}

impl<N: ArrayLength> Random for SecretKeyBytes<N> {
    fn random<R: Csprng>(rng: &mut R) -> Self {
        Self(Random::random(rng))
    }
}

/// A fixed-length asymmetric public key.
pub trait PublicKey: Clone + Debug + Eq + for<'a> Import<&'a [u8]> {
    /// The fixed-length byte encoding of the key.
    type Data: Borrow<[u8]> + Clone + Sized;

    /// Returns the byte representation of the public key.
    fn export(&self) -> Self::Data;
}

raw_key! {
    /// A generic secret key.
    pub RawKey,
}

/// Creates a "raw" (i.e., a byte array) key.
///
/// # Example
///
/// ```
/// use crypto::raw_key;
///
/// raw_key! {
///     /// Some documentation.
///     pub MyRawKey,
///     /// Some more documentation.
///     pub AnotherKey,
/// }
/// ```
#[macro_export]
macro_rules! raw_key {
    () => {};
    (
        $(#[$meta:meta])*
        $vis:vis $name:ident,
        $($tail:tt)*
    ) => {
        $(#[$meta])*
        #[derive(Clone, $crate::zeroize::Zeroize, $crate::zeroize::ZeroizeOnDrop)]
        #[repr(transparent)]
        $vis struct $name<const N: usize>([u8; N]);

        impl<const N: usize> $name<N> {
            /// Returns itself as a byte array.
            #[inline]
            pub const fn as_bytes(&self) -> &[u8; N] {
                &self.0
            }

            /// Returns a raw pointer to the key data.
            ///
            /// Should only be used for FFI purposes.
            #[inline]
            pub const fn as_ptr(&self) -> *const u8 {
                self.0.as_ptr()
            }

            /// Returns the length of the key.
            ///
            /// Will always be exactly `N`.
            #[allow(clippy::len_without_is_empty)]
            #[inline]
            pub const fn len(&self) -> usize {
                self.0.len()
            }
        }

        impl<const N: usize> $crate::keys::SecretKey for $name<N>
        where
            ::generic_array::typenum::Const<N>: ::generic_array::IntoArrayLength,
        {
            type Size = ::generic_array::ConstArrayLength<N>;

            #[inline]
            fn new<R: $crate::csprng::Csprng>(rng: &mut R) -> Self {
                let mut out = [0u8; N];
                rng.fill_bytes(&mut out);
                Self(out)
            }

            #[inline]
            fn try_export_secret(&self) -> Result<$crate::keys::SecretKeyBytes<Self::Size>, $crate::import::ExportError> {
                Ok(self.0.into())
            }
        }

        impl<const N: usize> $crate::kdf::Derive for $name<N>
        where
            ::generic_array::typenum::Const<N>: ::generic_array::IntoArrayLength,
        {
            type Size = ::generic_array::ConstArrayLength<N>;
            type Error = $crate::kdf::KdfError;

            fn expand_multi<K: $crate::kdf::Kdf>(prk: &K::Prk, info: &[&[u8]]) ->
                    ::core::result::Result<Self, Self::Error> {
                let mut secret = [0u8; N];
                K::expand_multi(&mut secret, prk, info)?;
                Ok(Self(secret))
            }
        }

        impl<const N: usize> ::core::default::Default for $name<N> {
            fn default() -> Self {
                Self([0u8; N])
            }
        }

        impl<const N: usize> ::core::convert::AsRef<[u8]> for $name<N> {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl<const N: usize> ::core::convert::AsMut<[u8]> for $name<N> {
            #[inline]
            fn as_mut(&mut self) -> &mut [u8] {
                self.0.as_mut()
            }
        }

        impl<const N: usize> ::core::convert::AsRef<[u8; N]> for $name<N> {
            #[inline]
            fn as_ref(&self) -> &[u8; N] {
                &self.0
            }
        }

        impl<const N: usize> ::core::convert::AsMut<[u8; N]> for $name<N> {
            #[inline]
            fn as_mut(&mut self) -> &mut [u8; N] {
                &mut self.0
            }
        }

        impl<const N: usize> ::core::borrow::Borrow<[u8]> for $name<N> {
            #[inline]
            fn borrow(&self) -> &[u8] {
                self.0.borrow()
            }
        }

        impl<const N: usize>
            ::core::borrow::Borrow<
                ::generic_array::GenericArray<u8, ::generic_array::ConstArrayLength<N>>,
            > for $name<N>
        where
            ::generic_array::typenum::Const<N>: ::generic_array::IntoArrayLength,
        {
            #[inline]
            fn borrow(&self) -> &::generic_array::GenericArray<u8, ::generic_array::ConstArrayLength<N>> {
                (&self.0).into()
            }
        }

        impl<const N: usize> ::core::borrow::BorrowMut<[u8]> for $name<N> {
            #[inline]
            fn borrow_mut(&mut self) -> &mut [u8] {
                self.0.borrow_mut()
            }
        }

        impl<const N: usize>
            ::core::borrow::BorrowMut<
                ::generic_array::GenericArray<u8, ::generic_array::ConstArrayLength<N>>,
            > for $name<N>
        where
            ::generic_array::typenum::Const<N>: ::generic_array::IntoArrayLength,
        {
            #[inline]
            fn borrow_mut(&mut self) -> &mut ::generic_array::GenericArray<u8, ::generic_array::ConstArrayLength<N>> {
                (&mut self.0).into()
            }
        }

        impl<const N: usize> ::subtle::ConstantTimeEq for $name<N> {
            #[inline]
            fn ct_eq(&self, other: &Self) -> ::subtle::Choice {
                self.0.ct_eq(&other.0)
            }
        }

        impl<const N: usize> ::core::convert::From<&[u8; N]> for $name<N> {
            #[inline]
            fn from(key: &[u8; N]) -> Self {
                Self(*key)
            }
        }

        impl<const N: usize> ::core::convert::From<[u8; N]> for $name<N> {
            #[inline]
            fn from(key: [u8; N]) -> Self {
                Self(key)
            }
        }

        impl<const N: usize> ::core::convert::From<$name<N>> for [u8; N] {
            #[inline]
            fn from(key: $name<N>) -> Self {
                key.0
            }
        }

        impl<'a, const N: usize> ::core::convert::From<&'a $name<N>> for &'a [u8; N] {
            #[inline]
            fn from(key: &'a $name<N>) -> Self {
                &key.0
            }
        }

        impl<const N: usize> ::core::convert::From<$name<N>> for
                ::generic_array::GenericArray<u8, ::generic_array::ConstArrayLength<N>>
        where
            ::generic_array::typenum::Const<N>: ::generic_array::IntoArrayLength,
        {
            #[inline]
            fn from(key: $name<N>) -> Self {
                key.0.into()
            }
        }

        impl<const N: usize> ::core::convert::From<
                ::generic_array::GenericArray<u8, ::generic_array::ConstArrayLength<N>>> for $name<N>
        where
            ::generic_array::typenum::Const<N>: ::generic_array::IntoArrayLength,
        {
            #[inline]
            fn from(key: ::generic_array::GenericArray<u8, ::generic_array::ConstArrayLength<N>>) -> Self {
                Self(key.into())
            }
        }

        impl<const N: usize> ::core::convert::TryFrom<&[u8]> for $name<N> {
            type Error = $crate::import::InvalidSizeError;

            #[inline]
            fn try_from(data: &[u8]) -> ::core::result::Result<Self, Self::Error> {
                Ok(Self(*$crate::import::try_from_slice(data)?))
            }
        }

        impl<const N: usize> $crate::import::Import<Self> for $name<N> {
            #[inline]
            fn import(data: Self) -> ::core::result::Result<Self, $crate::import::ImportError> {
                ::core::result::Result::Ok(data)
            }
        }

        impl<const N: usize> $crate::import::Import<&[u8; N]> for $name<N> {
            #[inline]
            fn import(key: &[u8; N]) -> ::core::result::Result<Self, $crate::import::ImportError> {
                ::core::result::Result::Ok(Self(*key))
            }
        }

        impl<const N: usize> $crate::import::Import<[u8; N]> for $name<N> {
            #[inline]
            fn import(key: [u8; N]) -> ::core::result::Result<Self, $crate::import::ImportError> {
                ::core::result::Result::Ok(Self(key))
            }
        }

        impl<const N: usize> $crate::import::Import<&[u8]> for $name<N> {
            #[inline]
            fn import(data: &[u8]) -> ::core::result::Result<Self, $crate::import::ImportError> {
                $crate::import::try_import(data)
            }
        }

        raw_key!{ $($tail)* }
    };
}
pub(crate) use raw_key;
