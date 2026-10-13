//! The cryptography engine.
//!
//! # Warning
//!
//! This is a low-level module. You should not be using it
//! directly unless you are implementing an engine.

#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, rc::Rc, sync::Arc};
use core::{convert::Infallible, fmt::Debug, hash::Hash, result::Result};

use buggy::Bug;
use serde::{Serialize, de::DeserializeOwned};
use spideroak_crypto::{
    aead::{Aead, OpenError, SealError},
    csprng::Csprng,
    import::{ExportError, ImportError},
    kdf::{Kdf, Prk},
    kem::Kem,
    mac::Mac,
    oid::{self, Identified as _, Oid},
    signer::Signer,
};

use crate::{
    ciphersuite::CipherSuite,
    id::{IdError, Identified},
};

/// The core trait used by the cryptography engine APIs.
pub trait Engine: Csprng + RawSecretWrap<Self> + Sized {
    /// The engine's [`CipherSuite`].
    type CS: CipherSuite;

    /// An encrypted, authenticated key that can only be
    /// decrypted with [`Engine::unwrap`].
    type WrappedKey: WrappedKey;

    /// Encrypts and authenticates an unwrapped key.
    fn wrap<T>(&self, key: T) -> Result<Self::WrappedKey, WrapError>
    where
        T: UnwrappedKey<Self::CS>,
    {
        let id = key.id()?;
        let secret = key.into_secret();
        self.wrap_secret::<T>(&id, secret.0)
    }

    /// Decrypts and authenticates the wrapped key.
    fn unwrap<T>(&self, key: &Self::WrappedKey) -> Result<T, UnwrapError>
    where
        T: UnwrappedKey<Self::CS>,
    {
        let secret = self.unwrap_secret::<T>(key)?;
        Ok(T::try_from_secret(UnwrappedSecret(secret))?)
    }
}

/// An encrypted, authenticated key created by [`Engine::wrap`]
/// that can only be decrypted by [`Engine::unwrap`].
///
/// It need not directly contain the ciphertext. For example,
/// it might only contain an identifier used to look up the
/// key in an HSM.
pub trait WrappedKey: Identified + Serialize + DeserializeOwned + Sized {}

/// A key that an [`Engine`] can wrap.
pub trait UnwrappedKey<CS: CipherSuite>: Sized + Identified {
    /// The key's algorithm identifier.
    const ID: AlgId;

    /// Converts itself into the underlying [`Secret`].
    fn into_secret(self) -> Secret<CS>;

    /// Converts itself from a [`UnwrappedSecret`].
    fn try_from_secret(key: UnwrappedSecret<CS>) -> Result<Self, WrongKeyType>;
}

/// A cryptographic secret underlying an [`UnwrappedKey`].
///
/// It is intentionally opaque; only [`Engine::wrap`] can access
/// the internal [`RawSecret`].
pub struct Secret<CS: CipherSuite>(RawSecret<CS>);

impl<CS: CipherSuite> Secret<CS> {
    /// Creates a new [`Secret`].
    pub const fn new(secret: RawSecret<CS>) -> Self {
        Self(secret)
    }
}

/// A cryptographic secret as unwrapped by an [`Engine`].
///
/// It is intentionally opaque; only [`Engine::unwrap`] can
/// construct this type.
pub struct UnwrappedSecret<CS: CipherSuite>(RawSecret<CS>);

impl<CS: CipherSuite> UnwrappedSecret<CS> {
    /// Returns the underlying [`RawSecret`].
    pub fn into_raw(self) -> RawSecret<CS> {
        self.0
    }
}

/// Encrypts and authenticates [`RawSecret`]s from
/// [`UnwrappedKey`]s.
pub trait RawSecretWrap<E: Engine> {
    /// Encrypts and authenticates an unwrapped key.
    ///
    /// # Warning
    ///
    /// This method is used by [`Engine::wrap`] and should not be
    /// called manually.
    fn wrap_secret<T>(
        &self,
        id: &<T as Identified>::Id,
        secret: RawSecret<E::CS>,
    ) -> Result<E::WrappedKey, WrapError>
    where
        T: UnwrappedKey<E::CS>;

    /// Decrypts and authenticates the wrapped key.
    ///
    /// # Warning
    ///
    /// This method is used by [`Engine::unwrap`] and should not
    /// be called manually.
    fn unwrap_secret<T>(&self, key: &E::WrappedKey) -> Result<RawSecret<E::CS>, UnwrapError>
    where
        T: UnwrappedKey<E::CS>;
}

/// A raw, unwrapped secret.
pub enum RawSecret<CS: CipherSuite> {
    /// A symmetric AEAD key.
    Aead(<CS::Aead as Aead>::Key),
    /// An asymmetric decapsulation key.
    Decap(<CS::Kem as Kem>::DecapKey),
    /// A MAC key.
    Mac(<CS::Mac as Mac>::Key),
    /// A PRK.
    Prk(Prk<<CS::Kdf as Kdf>::PrkSize>),
    /// Cryptographic seeds.
    Seed([u8; 64]),
    /// An asymmetric signing key.
    Signing(<CS::Signer as Signer>::SigningKey),
}

impl<CS: CipherSuite> RawSecret<CS> {
    /// Returns the string name of the key.
    pub const fn name(&self) -> &'static str {
        self.alg_id().name()
    }

    /// Returns the secret's algorithm identifier.
    pub const fn alg_id(&self) -> AlgId {
        match self {
            Self::Aead(_) => AlgId::Aead(CS::Aead::OID),
            Self::Decap(_) => AlgId::Decap(CS::Kem::OID),
            Self::Mac(_) => AlgId::Mac(CS::Mac::OID),
            Self::Prk(_) => AlgId::Prk(CS::Kdf::OID),
            Self::Seed(_) => AlgId::Seed(()),
            Self::Signing(_) => AlgId::Signing(CS::Signer::OID),
        }
    }
}

/// An algorithm identifier for [`UnwrappedKey`].
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub enum AlgId {
    /// See [`RawSecret::Aead`].
    Aead(&'static Oid),
    /// See [`RawSecret::Decap`].
    Decap(&'static Oid),
    /// See [`RawSecret::Mac`].
    Mac(&'static Oid),
    /// See [`RawSecret::Prk`].
    Prk(&'static Oid),
    /// See [`RawSecret::Seed`].
    Seed(()),
    /// See [`RawSecret::Signing`].
    Signing(&'static Oid),
}

impl AlgId {
    /// Returns the string name of the key.
    #[inline]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Aead(_) => "Aead",
            Self::Decap(_) => "Decap",
            Self::Mac(_) => "Mac",
            Self::Prk(_) => "Prk",
            Self::Seed(()) => "Seed",
            Self::Signing(_) => "Signing",
        }
    }

    pub(crate) const fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Aead(id)
            | Self::Decap(id)
            | Self::Mac(id)
            | Self::Prk(id)
            | Self::Signing(id) => id.as_bytes(),
            Self::Seed(()) => b"64 byte Seed",
        }
    }
}

macro_rules! alg_id_from_impl {
    ($($name:ident => $ty:ident),* $(,)?) => {
        $(impl AlgId {
            #[doc(hidden)]
            // Not part of the public API. Do not use.
            pub const fn $name<CS: CipherSuite>() -> &'static Oid {
                <CS::$ty as oid::Identified>::OID
            }
        })*
    }
}
alg_id_from_impl! {
    _from_aead => Aead,
    _from_kem => Kem,
    _from_mac => Mac,
    _from_kdf => Kdf,
    _from_signer => Signer,
}

/// Implements [`UnwrappedKey`] for `$name`.
///
/// - `$type` identifies which variant should be used.
/// - `$into` is a function that takes `Self` and returns the
///   inner value for the `$type` variant.
/// - `$from` is a function that takes the inner value for the
///   `$type` variant and returns `Self`.
#[macro_export]
macro_rules! unwrapped {
    { name: $name:ident; type: Aead; into: $into:expr; from: $from:expr $(;)? } => {
        $crate::__unwrapped_inner!(Aead, $crate::engine::AlgId::_from_aead::<CS>(), $name, $into, $from);
    };
    { name: $name:ident; type: Decap; into: $into:expr; from: $from:expr $(;)? } => {
        $crate::__unwrapped_inner!(Decap, $crate::engine::AlgId::_from_kem::<CS>(), $name, $into, $from);
    };
    { name: $name:ident; type: Mac; into: $into:expr; from: $from:expr $(;)? } => {
        $crate::__unwrapped_inner!(Mac, $crate::engine::AlgId::_from_mac::<CS>(), $name, $into, $from);
    };
    { name: $name:ident; type: Prk; into: $into:expr; from: $from:expr $(;)? } => {
        $crate::__unwrapped_inner!(Prk, $crate::engine::AlgId::_from_kdf::<CS>(), $name, $into, $from);
    };
    { name: $name:ident; type: Seed; into: $into:expr; from: $from:expr $(;)? } => {
        $crate::__unwrapped_inner!(Seed, (), $name, $into, $from);
    };
    { name: $name:ident; type: Signing; into: $into:expr; from: $from:expr $(;)? } => {
        $crate::__unwrapped_inner!(Signing, $crate::engine::AlgId::_from_signer::<CS>(), $name, $into, $from);
    };
    ($($fallthrough:tt)*) => {
        ::core::compile_error!("unknown variant");
    };
}
pub(crate) use unwrapped;

#[doc(hidden)]
#[macro_export]
macro_rules! __unwrapped_inner {
    ($enum:ident, $id:expr, $name:ident, $into:expr, $from:expr) => {
        impl<CS: $crate::CipherSuite> $crate::engine::UnwrappedKey<CS> for $name<CS> {
            const ID: $crate::engine::AlgId = $crate::engine::AlgId::$enum($id);

            #[inline]
            fn into_secret(self) -> $crate::engine::Secret<CS> {
                $crate::engine::Secret::new($crate::engine::RawSecret::$enum(
                    #[allow(clippy::redundant_closure_call)]
                    $into(self),
                ))
            }

            #[inline]
            fn try_from_secret(
                key: $crate::engine::UnwrappedSecret<CS>,
            ) -> ::core::result::Result<Self, $crate::engine::WrongKeyType> {
                match key.into_raw() {
                    $crate::engine::RawSecret::$enum(key) => ::core::result::Result::Ok(
                        #[allow(clippy::redundant_closure_call)]
                        $from(key),
                    ),
                    got => ::core::result::Result::Err($crate::engine::WrongKeyType {
                        got: got.name(),
                        expected: ::core::stringify!($name),
                    }),
                }
            }
        }
    };
}

/// Returned when converting [`UnwrappedKey`]s to concrete key
/// types.
#[derive(Copy, Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("wrong key type: got {got}, expected {expected}")]
pub struct WrongKeyType {
    /// The type of key received.
    pub got: &'static str,
    /// The expected key type.
    pub expected: &'static str,
}

/// An error from [`Engine::wrap`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum WrapError {
    /// An unknown or internal error has occurred.
    #[error("unable to wrap key: {0}")]
    Other(&'static str),
    /// The secret key data cannot be exported.
    #[error("unable to wrap key: {0}")]
    Export(#[from] ExportError),
    /// The encoded secret key cannot be encrypted.
    #[error("unable to wrap key: {0}")]
    Seal(#[from] SealError),
    /// A bug was discovered.
    #[error("unable to wrap key: {0}")]
    Bug(#[from] Bug),
    /// An error occurred accessing the unique ID.
    #[error("unable to wrap key: {0}")]
    Id(#[from] IdError),
}

impl From<Infallible> for WrapError {
    fn from(err: Infallible) -> Self {
        match err {}
    }
}

/// An error from [`Engine::unwrap`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum UnwrapError {
    /// An unknown or internal error has occurred.
    #[error("unable to unwrap key: {0}")]
    Other(&'static str),
    /// The wrapped key could not be decrypted.
    #[error("unable to unwrap key: {0}")]
    Open(#[from] OpenError),
    /// The unwrapped secret key data cannot be imported.
    #[error("unable to unwrap key: {0}")]
    Import(#[from] ImportError),
    /// Could not convert the [`UnwrappedKey`] to `T`.
    #[error("unable to unwrap key: {0}")]
    WrongKeyType(#[from] WrongKeyType),
    /// A bug was discovered.
    #[error("unable to unwrap key: {0}")]
    Bug(#[from] Bug),
}

impl From<Infallible> for UnwrapError {
    fn from(err: Infallible) -> Self {
        match err {}
    }
}

macro_rules! blanket_impl {
    ($e:ident => $ty:ty) => {
        impl<$e: Engine> Engine for $ty {
            type CS = $e::CS;
            type WrappedKey = $e::WrappedKey;
        }

        impl<$e: Engine> RawSecretWrap<Self> for $ty {
            fn unwrap_secret<T>(
                &self,
                key: &$e::WrappedKey,
            ) -> Result<RawSecret<$e::CS>, UnwrapError>
            where
                T: UnwrappedKey<$e::CS>,
            {
                $e::unwrap_secret::<T>(self, key)
            }

            fn wrap_secret<T>(
                &self,
                id: &<T as Identified>::Id,
                secret: RawSecret<$e::CS>,
            ) -> Result<$e::WrappedKey, WrapError>
            where
                T: UnwrappedKey<$e::CS>,
            {
                $e::wrap_secret::<T>(self, id, secret)
            }
        }
    };
}

blanket_impl! { E => &E }
blanket_impl! { E => &mut E }

#[cfg(feature = "alloc")]
blanket_impl! { E => Box<E> }
#[cfg(feature = "alloc")]
blanket_impl! { E => Rc<E> }
#[cfg(feature = "alloc")]
blanket_impl! { E => Arc<E> }
