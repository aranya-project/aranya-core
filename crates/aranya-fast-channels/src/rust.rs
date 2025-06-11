//! RustCrypto cryptography.

pub use aranya_crypto::dangerous::spideroak_crypto::rust::HkdfSha256;

/// AES-256-GCM.
pub type Aes256Gcm = aranya_crypto::dangerous::spideroak_crypto::rust::Aes256Gcm;
