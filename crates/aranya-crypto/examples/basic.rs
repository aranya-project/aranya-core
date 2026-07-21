//! Basic usage of the aranya-crypto engine.

use aranya_crypto::{
    dangerous::spideroak_crypto::{ed25519, rust},
    default::DefaultEngine,
    CipherSuite, Engine, Rng,
};

/// Custom cipher suite example.
struct MyCipherSuite;

impl CipherSuite for MyCipherSuite {
    type Aead = rust::Aes256Gcm;
    type Hash = rust::Sha256;
    type Kdf = rust::HkdfSha512;
    type Kem = rust::DhKemP256HkdfSha256;
    type Mac = rust::HmacSha512;
    type Signer = ed25519::Ed25519;
}

fn main() {
    // Create engine with default cipher suite
    let (mut engine, _key) = DefaultEngine::from_entropy(Rng);

    // Generate random bytes
    let mut buf = [0u8; 32];
    engine.fill_bytes(&mut buf);

    println!("Generated {} random bytes", buf.len());
}