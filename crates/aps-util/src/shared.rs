use crypto::{EncryptionPublicKey, Engine};

/// Decodes a [`EncryptionPublicKey`].
pub(crate) fn decode_enc_pk<E: Engine>(bytes: &[u8]) -> postcard::Result<EncryptionPublicKey<E>> {
    postcard::from_bytes(bytes)
}
