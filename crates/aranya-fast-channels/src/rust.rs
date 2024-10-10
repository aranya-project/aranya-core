//! RustCrypto cryptography.

pub use aranya_crypto::rust::HkdfSha256;

/// AES-256-GCM.
pub type Aes256Gcm = aranya_crypto::rust::Aes256Gcm;
