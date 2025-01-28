//! Basic keys and key material.

use core::{borrow::Borrow, fmt::Debug, iter::IntoIterator, mem, result::Result};

use generic_array::{ArrayLength, GenericArray, IntoArrayLength};
use subtle::{Choice, ConstantTimeEq};
use typenum::{generic_const_mappings::Const, IsLess, Unsigned, U65536};

use crate::{
    csprng::{Csprng, Random},
    import::{ExportError, Import},
    kdf::{Expand, Kdf, KdfError, Prk},
    zeroize::ZeroizeOnDrop,
};

pub trait KeyDeref {
    type KeyTarget<'k>
    where
        Self: 'k;
    fn key_deref(&self) -> Self::KeyTarget<'_>;
}

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
    /// The size in bytes of the secret key.
    pub const SIZE: usize = N::USIZE;

    /// Creates a new secret.
    #[inline]
    pub const fn new(secret: GenericArray<u8, N>) -> Self {
        Self(secret)
    }

    /// Returns the size in bytes of the secret key.
    #[allow(clippy::len_without_is_empty)]
    #[inline]
    pub const fn len(&self) -> usize {
        N::USIZE
    }

    /// Returns a reference to the secret key bytes as an array.
    pub(crate) fn as_array<const U: usize>(&self) -> &[u8; U]
    where
        Const<U>: IntoArrayLength<ArrayLength = N>,
    {
        self.0.as_ref()
    }

    /// Returns the secret key bytes as a byte slice.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns the secret as a mutable byte slice.
    pub(crate) fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Converts the secret key bytes to an array.
    #[inline]
    pub fn into_bytes(mut self) -> GenericArray<u8, N> {
        // This is fine since we're consuming the receiver. If
        // the receiver were an exclusive reference this would be
        // very wrong since it'd be replacing the secret key with
        // all zeros.
        mem::take(&mut self.0)
    }
}

impl<N: ArrayLength> ConstantTimeEq for SecretKeyBytes<N> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<N: ArrayLength> Random for SecretKeyBytes<N> {
    fn random<R: Csprng>(rng: &mut R) -> Self {
        Self(Random::random(rng))
    }
}

impl<N: ArrayLength> Expand for SecretKeyBytes<N>
where
    N: IsLess<U65536>,
{
    type Size = N;

    fn expand_multi<'a, K, I>(prk: &Prk<K::PrkSize>, info: I) -> Result<Self, KdfError>
    where
        K: Kdf,
        I: IntoIterator<Item = &'a [u8]>,
        I::IntoIter: Clone,
    {
        Ok(Self(Expand::expand_multi::<K, I>(prk, info)?))
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
/// use aranya_crypto_core::raw_key;
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
        #[derive(::core::clone::Clone, $crate::zeroize::ZeroizeOnDrop)]
        #[repr(transparent)]
        $vis struct $name<N: ::generic_array::ArrayLength>($crate::keys::SecretKeyBytes<N>);

        impl<N: ::generic_array::ArrayLength> $crate::keys::KeyDeref for $name<N> {
            type KeyTarget<'k> = &'k Self;
            fn key_deref(&self) -> &Self {
                &self
            }
        }

        impl<N: ::generic_array::ArrayLength> $name<N> {
            /// Creates a new raw key.
            #[inline]
            pub const fn new(key: $crate::keys::SecretKeyBytes<N>) -> Self {
                Self(key)
            }

            /// Returns the length in bytes of the key.
            ///
            /// Will always be exactly `N`.
            #[allow(clippy::len_without_is_empty)]
            #[inline]
            pub const fn len(&self) -> usize {
                self.0.len()
            }

            /// Returns the raw key bytes.
            #[inline]
            pub const fn as_slice(&self) -> &[u8] {
                self.0.as_bytes()
            }

            /// Returns the raw key bytes.
            #[inline]
            pub const fn as_bytes(&self) -> &$crate::keys::SecretKeyBytes<N> {
                &self.0
            }

            /// Converts the key into its raw key bytes.
            #[inline]
            pub fn into_bytes(mut self) -> $crate::keys::SecretKeyBytes<N> {
                // This is fine since we're consuming the
                // receiver. If the receiver were an exclusive
                // reference this would be very wrong since it'd
                // be replacing the secret key with all zeros.
                ::core::mem::take(&mut self.0)
            }
        }

        impl<N: ::generic_array::ArrayLength> $crate::keys::SecretKey for $name<N>
        {
            type Size = N;

            #[inline]
            fn new<R: $crate::csprng::Csprng>(rng: &mut R) -> Self {
                Self($crate::csprng::Random::random(rng))
            }

            #[inline]
            fn try_export_secret(&self) -> ::core::result::Result<
                $crate::keys::SecretKeyBytes<Self::Size>,
                $crate::import::ExportError,
            > {
                ::core::result::Result::Ok(self.0.clone())
            }
        }

        impl<N: ::generic_array::ArrayLength> $crate::csprng::Random for $name<N> {
            fn random<R: $crate::csprng::Csprng>(rng: &mut R) -> Self {
                let sk = <$crate::keys::SecretKeyBytes<N> as $crate::csprng::Random>::random(rng);
                Self(sk)
            }
        }


        impl<N: ::generic_array::ArrayLength> $crate::kdf::Expand for $name<N>
        where
            N: ::typenum::IsLess<::typenum::U65536>
        {
            type Size = N;

            fn expand_multi<'a, K, I>(
                prk: &$crate::kdf::Prk<K::PrkSize>,
                info: I,
            ) -> ::core::result::Result<Self, $crate::kdf::KdfError>
            where
                K: $crate::kdf::Kdf,
                I: ::core::iter::IntoIterator<Item = &'a [u8]>,
                I::IntoIter: ::core::clone::Clone,
            {
                ::core::result::Result::Ok(Self($crate::kdf::Expand::expand_multi::<K, I>(prk, info)?))
            }
        }

        impl<N: ::generic_array::ArrayLength> ::subtle::ConstantTimeEq for $name<N> {
            #[inline]
            fn ct_eq(&self, other: &Self) -> ::subtle::Choice {
                self.0.ct_eq(&other.0)
            }
        }

        impl<N, const U: usize> $crate::import::Import<[u8; U]> for $name<N>
        where
            N: ::generic_array::ArrayLength,
            ::typenum::generic_const_mappings::Const<U>: ::generic_array::IntoArrayLength<ArrayLength = N>,
        {
            #[inline]
            fn import(key: [u8; U]) -> ::core::result::Result<Self, $crate::import::ImportError> {
                let sk = $crate::keys::SecretKeyBytes::new(key.into());
                ::core::result::Result::Ok(Self(sk))
            }
        }

        impl<N: ::generic_array::ArrayLength> $crate::import::Import<&[u8]> for $name<N> {
            #[inline]
            fn import(data: &[u8]) -> ::core::result::Result<Self, $crate::import::ImportError> {
                let bytes = $crate::import::Import::<_>::import(data)?;
                let sk = $crate::keys::SecretKeyBytes::new(bytes);
                ::core::result::Result::Ok(Self(sk))
            }
        }

        raw_key!{ $($tail)* }
    };
}
pub(crate) use raw_key;
