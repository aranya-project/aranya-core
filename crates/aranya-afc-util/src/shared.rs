use aranya_crypto::{CipherSuite, EncryptionPublicKey};

/// Decodes a [`EncryptionPublicKey`].
pub fn decode_enc_pk<CS: CipherSuite>(bytes: &[u8]) -> postcard::Result<EncryptionPublicKey<CS>> {
    postcard::from_bytes(bytes)
}
