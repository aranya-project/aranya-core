//! The cryptography engine.
//!
//! # Warning
//!
//! This is a low-level module. You should not be using it
//! directly unless you are implementing an engine.

#![forbid(unsafe_code)]

use core::{
    borrow::Borrow,
    fmt::{self, Debug, Display},
    result::Result,
};

use serde::{Deserialize, Serialize};

use crate::{
    aead::{Aead, AeadId, OpenError, SealError},
    apq::{ReceiverSecretKey, SenderSecretKey, SenderSigningKey},
    aranya::{EncryptionKey, IdentityKey, SigningKey},
    ciphersuite::CipherSuite,
    csprng::Csprng,
    groupkey::GroupKey,
    id::Id,
    import::{ExportError, Import, ImportError},
    kem::{Kem, KemId},
    keys::{SecretKey, SecretKeyBytes},
    mac::{Mac, MacId},
    signer::{Signer, SignerId},
};

/// An error from [`Engine::wrap`].
#[derive(Debug, Eq, PartialEq)]
pub enum WrapError {
    /// An unknown or internal error has occurred.
    Other(&'static str),
    /// The secret key data cannot be exported.
    Export(ExportError),
    /// The encoded secret key cannot be encrypted.
    Seal(SealError),
}

impl Display for WrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unable to wrap key: ")?;
        match self {
            Self::Other(msg) => write!(f, "{}", msg),
            Self::Export(err) => write!(f, "{}", err),
            Self::Seal(err) => write!(f, "{}", err),
        }
    }
}

impl trouble::Error for WrapError {
    fn source(&self) -> Option<&(dyn trouble::Error + 'static)> {
        match self {
            Self::Export(err) => Some(err),
            Self::Seal(err) => Some(err),
            _ => None,
        }
    }
}

impl From<SealError> for WrapError {
    fn from(err: SealError) -> Self {
        Self::Seal(err)
    }
}

impl From<ExportError> for WrapError {
    fn from(err: ExportError) -> Self {
        Self::Export(err)
    }
}

/// An error from [`Engine::unwrap`].
#[derive(Debug, Eq, PartialEq)]
pub enum UnwrapError {
    /// An unknown or internal error has occurred.
    Other(&'static str),
    /// The wrapped key could not be decrypted.
    Open(OpenError),
    /// The unwrapped secret key data cannot be imported.
    Import(ImportError),
}

impl Display for UnwrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unable to unwrap key: ")?;
        match self {
            Self::Other(msg) => write!(f, "{}", msg),
            Self::Open(err) => write!(f, "{}", err),
            Self::Import(err) => write!(f, "{}", err),
        }
    }
}

impl trouble::Error for UnwrapError {
    fn source(&self) -> Option<&(dyn trouble::Error + 'static)> {
        match self {
            Self::Import(err) => Some(err),
            _ => None,
        }
    }
}

impl From<OpenError> for UnwrapError {
    fn from(err: OpenError) -> Self {
        Self::Open(err)
    }
}

impl From<ImportError> for UnwrapError {
    fn from(err: ImportError) -> Self {
        Self::Import(err)
    }
}

/// Identifies each discriminant in [`UnwrappedKey`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum KeyType {
    /// See [`UnwrappedKey::Aead`].
    Aead(AeadId),
    /// See [`UnwrappedKey::Encryption`].
    Encryption(KemId),
    /// See [`UnwrappedKey::Group`].
    Group,
    /// See [`UnwrappedKey::Identity`].
    Identity(SignerId),
    /// See [`UnwrappedKey::Mac`].
    Mac(MacId),
    /// See [`UnwrappedKey::ReceiverSecret`].
    ReceiverSecret(SignerId),
    /// See [`UnwrappedKey::SenderSecret`].
    SenderSecret(SignerId),
    /// See [`UnwrappedKey::SenderSigning`].
    SenderSigning(SignerId),
    /// See [`UnwrappedKey::Signing`].
    Signing(SignerId),
}

/// An encrypted, authenticated key.
///
/// It can only be decrypted by [`Engine::unwrap`].
pub trait WrappedKey: Sized {
    /// Identifies the type of that was wrapped.
    fn id(&self) -> KeyType;

    /// The output of [`encode`][Self::encode].
    type Output: Borrow<[u8]>;
    /// The error returned by [`encode`][Self::encode] and
    /// [`decode`][Self::decode].
    type Error: Debug + Display;

    /// Encodes itself as bytes.
    fn encode(&self) -> Result<Self::Output, Self::Error>;
    /// Decodes itself from bytes.
    fn decode(data: &[u8]) -> Result<Self, Self::Error>;
}

/// Keys that can be wrapped by an [`Engine`].
///
/// In general, unless you are implementing an [`Engine`] you
/// should not need to use this type directly. The keys that
/// commonly need to be wrapped---like [`EncryptionKey`], for
/// example---implement [`Into<UnwrappedKey<E>>`] and can be used
/// directly with [`Engine::wrap`].
pub enum UnwrappedKey<E: Engine + ?Sized> {
    /// An [`Aead::Key`].
    Aead(<E::Aead as Aead>::Key),
    /// A [`EncryptionKey`].
    Encryption(EncryptionKey<E>),
    /// A [`GroupKey`].
    Group(GroupKey<E>),
    /// An [`IdentityKey`].
    Identity(IdentityKey<E>),
    /// A [`Mac::Key`].
    Mac(<E::Mac as Mac>::Key),
    /// A [`ReceiverSecretKey`].
    ReceiverSecret(ReceiverSecretKey<E>),
    /// A [`SenderSecretKey`].
    SenderSecret(SenderSecretKey<E>),
    /// A [`SenderSigningKey`].
    SenderSigning(SenderSigningKey<E>),
    /// A [`SigningKey`].
    Signing(SigningKey<E>),
}

impl<E: Engine + ?Sized> UnwrappedKey<E> {
    /// Identifies the discriminant.
    pub fn id(&self) -> KeyType {
        match self {
            Self::Aead(_) => KeyType::Aead(E::Aead::ID),
            Self::Encryption(_) => KeyType::Encryption(E::Kem::ID),
            Self::Group(_) => KeyType::Group,
            Self::Identity(_) => KeyType::Identity(E::Signer::ID),
            Self::Mac(_) => KeyType::Mac(E::Mac::ID),
            Self::ReceiverSecret(_) => KeyType::ReceiverSecret(E::Signer::ID),
            Self::SenderSecret(_) => KeyType::SenderSecret(E::Signer::ID),
            Self::SenderSigning(_) => KeyType::SenderSigning(E::Signer::ID),
            Self::Signing(_) => KeyType::Signing(E::Signer::ID),
        }
    }
}

impl<E: Engine> Import<(KeyType, &[u8])> for UnwrappedKey<E> {
    fn import(data: (KeyType, &[u8])) -> Result<Self, ImportError> {
        let (kt, secret) = data;
        let v = match kt {
            KeyType::Aead(_) => Self::Aead(<E::Aead as Aead>::Key::import(secret)?),
            KeyType::Encryption(_) => Self::Encryption(EncryptionKey::import(secret)?),
            KeyType::Group => Self::Group(GroupKey::try_from(secret)?),
            KeyType::Identity(_) => Self::Identity(IdentityKey::import(secret)?),
            KeyType::Mac(_) => Self::Mac(<E::Mac as Mac>::Key::import(secret)?),
            KeyType::ReceiverSecret(_) => Self::ReceiverSecret(ReceiverSecretKey::import(secret)?),
            KeyType::SenderSecret(_) => Self::SenderSecret(SenderSecretKey::import(secret)?),
            KeyType::SenderSigning(_) => Self::SenderSigning(SenderSigningKey::import(secret)?),
            KeyType::Signing(_) => Self::Signing(SigningKey::import(secret)?),
        };
        Ok(v)
    }
}

/// Returned when converting [`UnwrappedKey`]s to concrete key
/// types via [`TryFrom`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WrongKeyTypeError;

impl Display for WrongKeyTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wrong key type")
    }
}

impl trouble::Error for WrongKeyTypeError {}

macro_rules! conv_key {
    ($name:ident, $enum:ident) => {
        impl<E: Engine + ?Sized> From<$name<E>> for UnwrappedKey<E> {
            fn from(key: $name<E>) -> Self {
                Self::$enum(key)
            }
        }

        impl<E: Engine + ?Sized> From<&$name<E>> for UnwrappedKey<E> {
            fn from(key: &$name<E>) -> Self {
                Self::$enum(key.clone())
            }
        }

        impl<E: Engine + ?Sized> TryFrom<UnwrappedKey<E>> for $name<E> {
            type Error = WrongKeyTypeError;

            fn try_from(key: UnwrappedKey<E>) -> Result<Self, Self::Error> {
                match key {
                    UnwrappedKey::$enum(key) => Ok(key),
                    _ => Err(WrongKeyTypeError),
                }
            }
        }
    };
}
conv_key!(EncryptionKey, Encryption);
conv_key!(GroupKey, Group);
conv_key!(IdentityKey, Identity);
conv_key!(ReceiverSecretKey, ReceiverSecret);
conv_key!(SenderSecretKey, SenderSecret);
conv_key!(SenderSigningKey, SenderSigning);
conv_key!(SigningKey, Signing);

/// The secret data from an [`UnwrappedKey`].
pub enum SecretData<'a, E: Engine + ?Sized> {
    /// See [`UnwrappedKey::Aead`].
    Aead(SecretKeyBytes<<<E::Aead as Aead>::Key as SecretKey>::Size>),
    /// See [`UnwrappedKey::Encryption`].
    Encryption(SecretKeyBytes<<<E::Kem as Kem>::DecapKey as SecretKey>::Size>),
    /// See [`UnwrappedKey::Group`].
    Group(&'a [u8; 64]),
    /// See [`UnwrappedKey::Identity`].
    Identity(SecretKeyBytes<<<E::Signer as Signer>::SigningKey as SecretKey>::Size>),
    /// See [`UnwrappedKey::Mac`].
    Mac(SecretKeyBytes<<<E::Mac as Mac>::Key as SecretKey>::Size>),
    /// See [`UnwrappedKey::ReceiverSecret`].
    ReceiverSecret(SecretKeyBytes<<<E::Kem as Kem>::DecapKey as SecretKey>::Size>),
    /// See [`UnwrappedKey::SenderSecret`].
    SenderSecret(SecretKeyBytes<<<E::Kem as Kem>::DecapKey as SecretKey>::Size>),
    /// See [`UnwrappedKey::SenderSigning`].
    SenderSigning(SecretKeyBytes<<<E::Signer as Signer>::SigningKey as SecretKey>::Size>),
    /// See [`UnwrappedKey::Signing`].
    Signing(SecretKeyBytes<<<E::Signer as Signer>::SigningKey as SecretKey>::Size>),
}

impl<'a, E: Engine + ?Sized> SecretData<'a, E> {
    /// Attempts to return the key's secret data.
    ///
    /// # Warning
    ///
    /// Do NOT use this function unless you are implementing an
    /// [`Engine`].
    pub fn from_unwrapped(key: &'a UnwrappedKey<E>) -> Result<SecretData<'a, E>, ExportError> {
        // This is a method on `SecretData` not `UnwrappedKey`
        // because `UnwrappedKey` is part of the crate's default
        // API and we do not allow users to see secret data in
        // that API.
        let data = match key {
            UnwrappedKey::Aead(key) => Self::Aead(key.try_export_secret()?),
            UnwrappedKey::Encryption(key) => Self::Encryption(key.try_export_secret()?),
            UnwrappedKey::Group(key) => Self::Group(key.raw_seed()),
            UnwrappedKey::Identity(key) => Self::Identity(key.try_export_secret()?),
            UnwrappedKey::Mac(key) => Self::Mac(key.try_export_secret()?),
            UnwrappedKey::ReceiverSecret(key) => Self::ReceiverSecret(key.try_export_secret()?),
            UnwrappedKey::SenderSecret(key) => Self::SenderSecret(key.try_export_secret()?),
            UnwrappedKey::SenderSigning(key) => Self::SenderSigning(key.try_export_secret()?),
            UnwrappedKey::Signing(key) => Self::Signing(key.try_export_secret()?),
        };
        Ok(data)
    }
}

impl<E: Engine + ?Sized> AsRef<[u8]> for SecretData<'_, E> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Aead(key) => key.as_bytes(),
            Self::Encryption(sk) => sk.as_bytes(),
            Self::Group(seed) => seed.as_ref(),
            Self::Identity(sk) => sk.as_bytes(),
            Self::Mac(key) => key.as_bytes(),
            Self::ReceiverSecret(sk) => sk.as_bytes(),
            Self::SenderSecret(sk) => sk.as_bytes(),
            Self::SenderSigning(sk) => sk.as_bytes(),
            Self::Signing(sk) => sk.as_bytes(),
        }
    }
}

/// The core trait used by the cryptography engine APIs.
pub trait Engine: CipherSuite + Csprng + Sized {
    /// Uniquely identifies the [`Engine`].
    const ID: Id;

    /// An encrypted, authenticated key.
    ///
    /// It can only be decrypted by [`Engine::unwrap`].
    type WrappedKey: WrappedKey;

    /// Encrypts and authenticates `key` and returns the wrapped
    /// key.
    fn wrap<T>(&mut self, key: T) -> Result<Self::WrappedKey, WrapError>
    where
        T: Into<UnwrappedKey<Self>>;

    /// Decrypts and authenticates the wrapped key, returning the
    /// unwrapped key.
    fn unwrap(&self, key: &Self::WrappedKey) -> Result<UnwrappedKey<Self>, UnwrapError>;

    /// Makes a best-effort attempt to render irrecoverable all
    /// key material protected by the [`Engine`].
    ///
    /// This is usually implemented by destroying the key
    /// wrapping keys.
    fn destroy(self) {}
}
