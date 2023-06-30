//! Basic keys and key material.
//!
//! # Warning
//!
//! This is a low-level module. You should not be using it
//! directly unless you are implementing an engine.

#![forbid(unsafe_code)]

use {
    crate::{
        csprng::Csprng,
        import::{ExportError, Import},
        zeroize::ZeroizeOnDrop,
    },
    core::{
        borrow::{Borrow, BorrowMut},
        fmt::Debug,
        result::Result,
    },
    subtle::ConstantTimeEq,
};

/// A fixed-length secret key.
///
/// Secret keys are either symmetric keys (e.g., for AES) or
/// asymmetric private keys (e.g., for ECDH).
pub trait SecretKey:
    Clone + ConstantTimeEq + for<'a> Import<&'a [u8]> + Import<Self::Data> + ZeroizeOnDrop
{
    /// Creates a random key, possibly using entropy from `rng`.
    ///
    /// Implementations are free to ignore `rng` and callers must
    /// not rely on this function reading from `rng`.
    fn new<R: Csprng>(rng: &mut R) -> Self;

    /// The fixed-length byte encoding of the key's secret data.
    ///
    /// This should be `[u8; N]` or similar (e.g., [`RawKey`]).
    type Data: Borrow<[u8]> + BorrowMut<[u8]> + Default + Sized + ZeroizeOnDrop;

    /// Attempts to export the key's secret data.
    fn try_export_secret(&self) -> Result<Self::Data, ExportError>;
}

/// A fixed-length asymmetric public key.
pub trait PublicKey: Clone + Debug + Eq + for<'a> Import<&'a [u8]> + Import<Self::Data> {
    /// The fixed-length byte encoding of the key.
    type Data: Borrow<[u8]> + Sized;

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
            /// Returns a raw pointer to the key data.
            ///
            /// Should only be used for FFI purposes.
            pub const fn as_ptr(&self) -> *const u8 {
                self.0.as_ptr()
            }

            /// Returns the length of the key.
            ///
            /// Will always be exactly `N`.
            #[allow(clippy::len_without_is_empty)]
            pub const fn len(&self) -> usize {
                self.0.len()
            }
        }

        impl<const N: usize> $crate::keys::SecretKey for $name<N> {
            #[inline]
            fn new<R: $crate::csprng::Csprng>(rng: &mut R) -> Self {
                let mut out = [0u8; N];
                rng.fill_bytes(&mut out);
                Self(out)
            }

            type Data = Self;

            #[inline]
            fn try_export_secret(&self) -> Result<Self::Data, $crate::import::ExportError> {
                Ok(self.clone())
            }
        }

        impl<const N: usize> ::core::default::Default for $name<N> {
            fn default() -> Self {
                Self([0u8; N])
            }
        }

        impl<const N: usize> AsRef<[u8]> for $name<N> {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl<const N: usize> AsMut<[u8]> for $name<N> {
            #[inline]
            fn as_mut(&mut self) -> &mut [u8] {
                self.0.as_mut()
            }
        }

        impl<const N: usize> AsRef<[u8; N]> for $name<N> {
            #[inline]
            fn as_ref(&self) -> &[u8; N] {
                &self.0
            }
        }

        impl<const N: usize> AsMut<[u8; N]> for $name<N> {
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

        impl<const N: usize> ::core::borrow::BorrowMut<[u8]> for $name<N> {
            #[inline]
            fn borrow_mut(&mut self) -> &mut [u8] {
                self.0.borrow_mut()
            }
        }

        impl<const N: usize> ::subtle::ConstantTimeEq for $name<N> {
            #[inline]
            fn ct_eq(&self, other: &Self) -> ::subtle::Choice {
                self.0.ct_eq(&other.0)
            }
        }

        impl<const N: usize> From<[u8; N]> for $name<N> {
            #[inline]
            fn from(key: [u8; N]) -> Self {
                Self(key)
            }
        }

        impl<const N: usize> From<$name<N>> for [u8; N] {
            #[inline]
            fn from(key: $name<N>) -> Self {
                key.0
            }
        }

        impl<const N: usize> $crate::import::Import<Self> for $name<N> {
            #[inline]
            fn import(data: Self) -> ::core::result::Result<Self, $crate::import::ImportError> {
                Ok(data)
            }
        }

        impl<const N: usize> $crate::import::Import<[u8; N]> for $name<N> {
            #[inline]
            fn import(key: [u8; N]) -> ::core::result::Result<Self, $crate::import::ImportError> {
                Ok(Self(key))
            }
        }

        impl<const N: usize> $crate::import::Import<&[u8]> for $name<N> {
            #[inline]
            fn import(data: &[u8]) -> ::core::result::Result<Self, $crate::import::ImportError> {
                $crate::import::try_import(data)
            }
        }

        impl<const N: usize> TryFrom<&[u8]> for $name<N> {
            type Error = $crate::import::ImportError;

            #[inline]
            fn try_from(data: &[u8]) -> ::core::result::Result<Self, $crate::import::ImportError> {
                $crate::import::try_import(data)
            }
        }

        raw_key!{ $($tail)* }
    };
}
pub(crate) use raw_key;
