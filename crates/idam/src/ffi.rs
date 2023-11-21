/*
The crypto FFI for IDAM is initialized with the underlying crypto engine
and access to a key store for wrapped secret keying material, including:
- IdentityKey
- SigningKey
- EncryptionKey
- GroupKeys

In our FactDB, we store the public portion of each asymmetric user key
as the byte serialization of its certificate and also an encrypted form
of every GroupKey that the user receives.

The secret material noted above, however, is assumed to have an opaque
type that is left to the user to determine the format. So, while we can
work with items from the FactDB as sequences of bytes that are converted
appropriately as needed, the secret material must be taken in its opaque
form first.
*/

#![cfg_attr(docs, doc(cfg(feature = "alloc")))]
#![cfg(feature = "alloc")]
// TODO: Remove when fields and methods are used.
#![allow(unused)]

extern crate alloc;

use alloc::vec::Vec;
use core::{
    fmt::{self, Display},
    ops::Add,
};

use crypto::{
    aead::Aead,
    engine::Engine,
    idam::{self, KeyStoreSecret, SealedGroupKey, WrappedGroupKey},
    Error, Id,
};
use generic_array::ArrayLength;
use policy_vm::CommandContext;
use typenum::{operator_aliases::Sum, U64};

/// Error resulting from a bad query to KeyStore
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyStoreError;

impl Display for KeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bad KeyStore query")
    }
}

#[cfg_attr(docs, doc(cfg(any(feature = "error_in_core", feature = "std"))))]
#[cfg(any(feature = "error_in_core", feature = "std"))]
impl error::Error for KeyStoreError {}

impl From<KeyStoreError> for Error {
    fn from(_err: KeyStoreError) -> Self {
        Self::InvalidArgument("no value in KeyStore for provided public key")
    }
}

/// Handle to secret keying material relating to the Aranya user.
///
/// All data is assumed to be cryptographically wrapped and must
/// never be exposed in its unwrapped form outside the crypto
/// engine or other secure module.
pub trait KeyStore {
    /// Returns a WrappedKey from the KeyStore
    fn get<E: Engine + ?Sized>(
        &self,
        key_type: KeyStoreSecret,
        public_key: &[u8],
    ) -> Result<E::WrappedKey, Error>;
}

/// The cryptography foreign function interface for IDAM.
pub struct IdamCrypto<K> {
    key_store: K,
}

impl<K: KeyStore> IdamCrypto<K> {
    /// Derive keyId for a public EncryptionKey
    fn encryption_key_id<E: Engine + ?Sized>(&self, pub_key_cert: &[u8]) -> Result<Id, Error> {
        idam::encryption_key_id::<E>(pub_key_cert)
    }

    /// Derive keyId for a public SigningKey
    fn signing_key_id<E: Engine + ?Sized>(&self, pub_key_cert: &[u8]) -> Result<Id, Error> {
        idam::signing_key_id::<E>(pub_key_cert)
    }

    /// Generate a new GroupKey
    fn generate_group_key<E: Engine + ?Sized>(
        &self,
        eng: &mut E,
    ) -> Result<WrappedGroupKey, Error> {
        idam::generate_group_key(eng)
    }

    /// Seal the GroupKey for a peer
    fn seal_group_key<E: Engine + ?Sized>(
        &mut self,
        group_key_wrap: &[u8],
        peer_enc_key: &[u8],
        group_id: Id,
        ctx: &mut CommandContext<'_, E>,
    ) -> Result<SealedGroupKey, Error>
    where
        <E::Aead as Aead>::Overhead: Add<U64>,
        Sum<<E::Aead as Aead>::Overhead, U64>: ArrayLength,
    {
        idam::seal_group_key(group_key_wrap, peer_enc_key, group_id, ctx.engine)
    }

    /// Unseal a received GroupKey
    fn unseal_group_key<E: Engine + ?Sized>(
        &mut self,
        sealed_group_key: SealedGroupKey,
        pub_enc_key: &[u8],
        group_id: Id,
        ctx: &mut CommandContext<'_, E>,
    ) -> Result<WrappedGroupKey, Error>
    where
        <E::Aead as Aead>::Overhead: Add<U64>,
        Sum<<E::Aead as Aead>::Overhead, U64>: ArrayLength,
    {
        // get private EncryptionKey corresponding to the given public key cert
        let priv_enc_key = self
            .key_store
            .get::<E>(KeyStoreSecret::Encrypt, pub_enc_key)?;
        idam::unseal_group_key(sealed_group_key, &priv_enc_key, group_id, ctx.engine)
    }

    /// Encrypt a message using the GroupKey
    pub fn encrypt_message<E: Engine + ?Sized>(
        &mut self,
        plaintext: &[u8],
        group_key_wrap: &[u8],
        parent_id: Id,
        pub_sign_key: &[u8],
        ctx: &mut CommandContext<'_, E>,
    ) -> Result<Vec<u8>, Error> {
        idam::encrypt_message(
            group_key_wrap,
            plaintext,
            parent_id,
            pub_sign_key,
            ctx.name,
            ctx.engine,
        )
    }

    /// Decrypt a received message using the GroupKey
    pub fn decrypt_message<E: Engine + ?Sized>(
        &mut self,
        ciphertext: &[u8],
        group_key_wrap: &[u8],
        parent_id: Id,
        peer_sign_key: &[u8],
        ctx: &mut CommandContext<'_, E>,
    ) -> Result<Vec<u8>, Error> {
        idam::decrypt_message(
            group_key_wrap,
            ciphertext,
            parent_id,
            peer_sign_key,
            ctx.name,
            ctx.engine,
        )
    }

    /// Calculate the updated hash chain of ChangeIDs with the added value
    pub fn compute_change_id<E: Engine + ?Sized>(new_event: Id, current_change_id: Id) -> Id {
        idam::compute_change_id::<E>(new_event, current_change_id)
    }
}

#[cfg(test)]
mod tests;
