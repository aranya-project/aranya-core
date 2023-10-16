//! This module contains the [IDAM Crypto APIs][idam].
//!
//! [idam]: https://github.com/spideroak-inc/flow3-docs/blob/main/src/idam_crypto.md

#![forbid(unsafe_code)]
#![cfg_attr(docs, doc(cfg(feature = "alloc")))]
#![cfg(feature = "alloc")]
extern crate alloc;

use alloc::{vec, vec::Vec};
use core::{
    borrow::Borrow,
    fmt::{self, Display},
    ops::Add,
};

use cfg_if::cfg_if;
use generic_array::ArrayLength;
use postcard::from_bytes;
use typenum::{operator_aliases::Sum, U64};

use crate::{
    aead::Aead,
    aranya::{
        Encap, EncryptedGroupKey, EncryptionKey, EncryptionPublicKey, IdentityKey, SigningKey,
        VerifyingKey,
    },
    engine::{Engine, UnwrappedKey, WrappedKey, WrongKeyTypeError},
    error::Error,
    groupkey::{Context, GroupKey},
    id::Id,
    import::InvalidSizeError,
};

cfg_if! {
    if #[cfg(feature = "error_in_core")] {
        use core::error;
    } else if #[cfg(feature = "std")] {
        use std::error;
    }
}

/// Error resulting from decoding a public key certificate
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodePublicKeyCertError(postcard::Error);

impl Display for DecodePublicKeyCertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg_attr(docs, doc(cfg(any(feature = "error_in_core", feature = "std"))))]
#[cfg(any(feature = "error_in_core", feature = "std"))]
impl error::Error for DecodePublicKeyCertError {}

/// An error from wrapping a [`GroupKey`] for FactDB
#[derive(Debug, Eq, PartialEq)]
pub enum KeyConversionError {
    /// An unknown or internal error has occurred.
    Other(&'static str),
    /// Unable to convert [`UnwrappedKey`] into the key object.
    WrongKeyType(WrongKeyTypeError),
    /// Cannot obtain [`EncryptedGroupKey`] from provided bytes.
    InvalidCiphertext(InvalidSizeError),
    /// Cannot deserialize or validate the public key certificate.
    DecodePublicKeyCert(DecodePublicKeyCertError),
    /// Cannot encode [`WrappedKey`] into bytes.
    EncodeWrappedKey,
    /// Cannot decode [`WrappedKey`] from bytes.
    DecodeWrappedKey,
}

impl Display for KeyConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(msg) => write!(f, "{}", msg),
            Self::WrongKeyType(err) => write!(f, "{}", err),
            Self::InvalidCiphertext(err) => write!(f, "{}", err),
            Self::DecodePublicKeyCert(err) => write!(f, "{}", err),
            Self::EncodeWrappedKey => write!(f, "error encoding `WrappedKey` to bytes"),
            Self::DecodeWrappedKey => write!(f, "error decoding `WrappedKey` from bytes"),
        }
    }
}

#[cfg_attr(docs, doc(cfg(any(feature = "error_in_core", feature = "std"))))]
#[cfg(any(feature = "error_in_core", feature = "std"))]
impl error::Error for KeyConversionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::WrongKeyType(err) => Some(err),
            Self::InvalidCiphertext(err) => Some(err),
            Self::DecodePublicKeyCert(err) => Some(err),
            _ => None,
        }
    }
}

impl From<WrongKeyTypeError> for Error {
    fn from(err: WrongKeyTypeError) -> Self {
        Self::KeyConversion(KeyConversionError::WrongKeyType(err))
    }
}

impl From<InvalidSizeError> for Error {
    fn from(err: InvalidSizeError) -> Self {
        Self::KeyConversion(KeyConversionError::InvalidCiphertext(err))
    }
}

/// Derives the keyId for a user's public EncryptionKey
pub fn encryption_key_id<E: Engine + ?Sized>(pub_key_cert: &[u8]) -> Result<Id, Error> {
    let pub_key: EncryptionPublicKey<E> = from_bytes(pub_key_cert)
        .map_err(|e| KeyConversionError::DecodePublicKeyCert(DecodePublicKeyCertError(e)))?;
    Ok(pub_key.id().into())
}

/// Derives the keyId for a user's public SigningKey
pub fn signing_key_id<E: Engine + ?Sized>(pub_key_cert: &[u8]) -> Result<Id, Error> {
    let pub_key: VerifyingKey<E> = from_bytes(pub_key_cert)
        .map_err(|e| KeyConversionError::DecodePublicKeyCert(DecodePublicKeyCertError(e)))?;
    Ok(pub_key.id().into())
}

/// GroupKey struct expected by Policy
pub struct WrappedGroupKey {
    /// Unique identifier for the GroupKey
    pub key_id: Id,
    /// Byte serialization of the wrapped GroupKey
    pub key_wrap: Vec<u8>,
}

fn group_key_for_fact<E: Engine + ?Sized>(
    group_key: GroupKey<E>,
    eng: &mut E,
) -> Result<WrappedGroupKey, Error> {
    // Compute the keyId of the GroupKey
    let group_key_id = group_key.id();
    // Convert to UnwrappedKey and wrap for FactDB storage
    let unwrapped_key = UnwrappedKey::from(group_key);
    let wrapped_key = E::wrap(eng, unwrapped_key)?;

    // Encode the wrapped key into bytes and return WrappedGroupKey struct
    let group_key_wrap = wrapped_key
        .encode()
        .map_err(|_| KeyConversionError::EncodeWrappedKey)?;
    Ok(WrappedGroupKey {
        key_id: group_key_id.into(),
        key_wrap: group_key_wrap.borrow().to_vec(),
    })
}

/// Creates a new GroupKey and returns its wrapped form and keyId for FactDB storage
pub fn generate_group_key<E: Engine + ?Sized>(eng: &mut E) -> Result<WrappedGroupKey, Error> {
    // Randomly generate 512 bits
    let group_key: GroupKey<E> = GroupKey::new(eng);
    // Prepare the GroupKey for FactDb storage
    group_key_for_fact(group_key, eng)
}

// Helper function to deserialize and unwrap the keyWrap of GroupKey
fn unwrap_group_key<E: Engine + ?Sized>(
    group_key_wrap: &[u8],
    eng: &mut E,
) -> Result<GroupKey<E>, Error> {
    // Decode the provided bytes into WrappedKey
    let wrapped_group_key =
        WrappedKey::decode(group_key_wrap).map_err(|_| KeyConversionError::DecodeWrappedKey)?;

    // Unwrap and return the GroupKey object
    let unwrapped_group_key = eng.unwrap(&wrapped_group_key)?;
    Ok(unwrapped_group_key.try_into()?)
}

/// GroupKey sealed for a peer
pub struct SealedGroupKey {
    /// Encapsulated secret needed to decrypt the key
    pub encap: Vec<u8>,
    /// Ciphertext for the encrypted GroupKey
    pub ciphertext: Vec<u8>,
}

/// Encrypt the GroupKey with the public EncryptionKey of the intended receiver
pub fn seal_group_key<E: Engine + ?Sized>(
    group_key_wrap: &[u8],
    peer_enc_key: &[u8],
    group_id: Id,
    eng: &mut E,
) -> Result<SealedGroupKey, Error>
where
    <E::Aead as Aead>::Overhead: Add<U64>,
    Sum<<E::Aead as Aead>::Overhead, U64>: ArrayLength,
{
    // Obtain a GroupKey object for the provided key
    let group_key = unwrap_group_key(group_key_wrap, eng)?;

    // Deserialize and validate the peer's public EncryptionKey cert
    let pub_key: EncryptionPublicKey<E> = from_bytes(peer_enc_key)
        .map_err(|e| KeyConversionError::DecodePublicKeyCert(DecodePublicKeyCertError(e)))?;

    // Seal GroupKey to the peer's public encryption key with the associated GroupID
    let (enc, ct) = pub_key.seal_group_key(eng, &group_key, group_id)?;

    // Return the byte representations of ciphertext and encapsulated secret
    Ok(SealedGroupKey {
        encap: enc.as_bytes().to_vec(),
        ciphertext: ct.as_bytes().to_vec(),
    })
}

/// Decrypt a received GroupKey
pub fn unseal_group_key<E: Engine + ?Sized>(
    sealed_group_key: SealedGroupKey,
    priv_enc_key: &E::WrappedKey,
    group_id: Id,
    eng: &mut E,
) -> Result<WrappedGroupKey, Error>
where
    <E::Aead as Aead>::Overhead: Add<U64>,
    Sum<<E::Aead as Aead>::Overhead, U64>: ArrayLength,
{
    // Get encapsulated secret and ciphertext from sealed_group_key
    let SealedGroupKey {
        encap: enc,
        ciphertext: ct,
    } = sealed_group_key;
    let encap = Encap::from_bytes(enc.as_slice())?;
    let ciphertext = EncryptedGroupKey::from_bytes(ct.as_slice())?;

    // Obtain the user's unwrapped private EncryptionKey
    let unwrapped_enc_key = eng.unwrap(priv_enc_key)?;
    let encryption_key: EncryptionKey<E> = unwrapped_enc_key.try_into()?;

    let group_key = encryption_key.open_group_key(&encap, &ciphertext, group_id)?;

    // Return the GroupKey prepared for FactDB storage
    group_key_for_fact(group_key, eng)
}

/// Encrypt a message for a group using its GroupKey
pub fn encrypt_message<E: Engine + ?Sized>(
    group_key_wrap: &[u8],
    plaintext: &[u8],
    parent_id: Id,
    pub_sign_key: &[u8],
    command_name: &'static str,
    eng: &mut E,
) -> Result<Vec<u8>, Error> {
    let group_key = unwrap_group_key(group_key_wrap, eng)?;
    let mut dst = vec![0u8; plaintext.len() + group_key.overhead()];

    let author: VerifyingKey<E> = from_bytes(pub_sign_key)
        .map_err(|e| KeyConversionError::DecodePublicKeyCert(DecodePublicKeyCertError(e)))?;
    let ctx = Context {
        label: command_name,
        parent: parent_id,
        author: &author,
    };

    group_key.seal(eng, &mut dst, plaintext, ctx)?;
    Ok(dst)
}

/// Decrypt a message sent within the group
pub fn decrypt_message<E: Engine + ?Sized>(
    group_key_wrap: &[u8],
    ciphertext: &[u8],
    parent_id: Id,
    peer_sign_key: &[u8],
    command_name: &'static str,
    eng: &mut E,
) -> Result<Vec<u8>, Error> {
    let group_key = unwrap_group_key(group_key_wrap, eng)?;
    let mut dst = vec![0u8; ciphertext.len() - group_key.overhead()];

    let author: VerifyingKey<E> = from_bytes(peer_sign_key)
        .map_err(|e| KeyConversionError::DecodePublicKeyCert(DecodePublicKeyCertError(e)))?;
    let ctx = Context {
        label: command_name,
        parent: parent_id,
        author: &author,
    };

    group_key.open(&mut dst, ciphertext, ctx)?;
    Ok(dst)
}

/// Compute the updated ChangeID for the given event
pub fn compute_change_id<E: Engine + ?Sized>(new_event: Id, current_change_id: Id) -> Id {
    // ChangeID = H("ID-v1" || eng_id || suites || data || tag)
    Id::new::<E>(current_change_id.as_ref(), new_event.as_bytes())
}

/// Locally kept secret keys accessible through the KeyStore
pub enum KeyStoreSecret {
    /// A wrapped [`IdentityKey`].
    Identify,
    /// A wrapped [`EncryptionKey`].
    Encrypt,
    /// A wrapped [`SigningKey`].
    Sign,
    /// A wrapped [`GroupKey`].
    Group,
}

/// Checks that the locally stored secret matches its KeyStore locator.
pub fn verify_stored_secret<E: Engine + ?Sized>(
    key_type: KeyStoreSecret,
    locator: &[u8],
    wrapped_secret: E::WrappedKey,
    eng: &mut E,
) -> Result<bool, Error> {
    match key_type {
        KeyStoreSecret::Identify => {
            let unwrapped_key = eng.unwrap(&wrapped_secret)?;
            let key_id = (IdentityKey::try_from(unwrapped_key)?).id();
            Ok(key_id.as_bytes() == locator)
        }
        KeyStoreSecret::Encrypt => {
            let unwrapped_key: EncryptionKey<E> = (eng.unwrap(&wrapped_secret)?).try_into()?;
            let key_id = unwrapped_key.id();
            Ok(key_id.as_bytes() == locator)
        }
        KeyStoreSecret::Sign => {
            let unwrapped_key = eng.unwrap(&wrapped_secret)?;
            let key_id = (SigningKey::try_from(unwrapped_key)?).id();
            Ok(key_id.as_bytes() == locator)
        }
        KeyStoreSecret::Group => {
            let unwrapped_key: GroupKey<E> = (eng.unwrap(&wrapped_secret)?).try_into()?;
            let key_id = unwrapped_key.id();
            Ok(key_id.as_ref() == locator)
        }
    }
}
