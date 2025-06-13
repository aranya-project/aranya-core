use aranya_crypto::{CipherSuite, EncryptionPublicKey, custom_id};

/// Decodes a [`EncryptionPublicKey`].
pub(crate) fn decode_enc_pk<CS: CipherSuite>(
    bytes: &[u8],
) -> postcard::Result<EncryptionPublicKey<CS>> {
    postcard::from_bytes(bytes)
}

custom_id! {
    /// Associates an AQC channel with Aranya policy rules that
    /// govern communication in the channel.
    pub struct LabelId;
}
