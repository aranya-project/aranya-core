# aranya-crypto

[![Crates.io](https://img.shields.io/crates/v/aranya-crypto.svg)](https://crates.io/crates/aranya-crypto)
[![Documentation](https://docs.rs/aranya-crypto/badge.svg)](https://docs.rs/aranya-crypto)

The Aranya Cryptography Engine.

## What's Contained

Rather than scattered cryptographic operations throughout the codebase,
Aranya centralizes all cryptography within the *cryptography engine*.
This engine provides a consistent interface while allowing algorithm
flexibility through cipher suites.

The engine requires cryptographic primitives (e.g., 128-bit AEAD) rather
than specific algorithms (e.g., AES-GCM). This design enables users to
select preferred implementations while maintaining security guarantees.

## Key Components

- **Engine**: Main cryptographic interface with pluggable cipher suites
- **Key Management**: Secure storage via filesystem or in-memory stores
- **Protocol Support**: AFC, AQC, APQ, and TLS integration
- **HSM Integration**: Extensible architecture for hardware security
  modules
- **No-std Support**: Compatible with embedded and constrained
  environments

## Get Started

Add to your `Cargo.toml`:

```toml
[dependencies]
aranya-crypto = "0.7"
```

### Basic Usage

```rust
use aranya_crypto::{Engine, default::DefaultEngine, Rng};

// Create engine with default cipher suite
let mut engine = DefaultEngine::new();

// Generate random bytes
let mut buf = [0u8; 32];
Rng.fill_bytes(&mut buf);
```

### Custom Engine Implementation

See [`examples/hsm/`](examples/hsm/) for a complete HSM-backed engine:

```rust
use aranya_crypto::{Engine, CipherSuite};

struct MyEngine;

impl CipherSuite for MyEngine {
    type Aead = rust::Aes256Gcm;
    type Hash = rust::Sha256;
    type Kdf = rust::HkdfSha512;
    type Kem = rust::DhKemP256HkdfSha256;
    type Mac = rust::HmacSha512;
    type Signer = rust::Ed25519;
}

impl Engine for MyEngine {
    type CS = Self;
    type WrappedKey = MyWrappedKey;
}
```

## Feature Configuration

Essential features:

- `std` - Standard library (includes `alloc` and `getrandom`)
- `alloc` - Dynamic allocation support
- `getrandom` - Random number generation (enabled by default)

Protocol support:

- `afc` - Aranya Fast Channels
- `aqc` - Aranya QUIC 
- `apq` - APQ protocol
- `tls` - TLS utilities

Key storage:

- `fs-keystore` - Filesystem-backed key store
- `memstore` - In-memory key store

Advanced options:

- `bearssl` - BearSSL backend support
- `committing-aead` - Committing AEAD implementations
- `ed25519_batch` - Batch signature verification (little-endian only)
- `hazmat` - Cryptographically hazardous operations
- `trng` - System TRNG for default CSPRNG
- `test_util` - Testing utilities and mock implementations

## Architecture Notes

Every cryptographic operation includes the cipher suite identifier for
domain separation and contextual binding. This prevents cross-version
attacks and ensures operations are bound to their cryptographic context.

The engine abstracts key management through the `KeyStore` trait,
supporting both encrypted persistence and in-memory storage. Keys are
wrapped/unwrapped transparently based on the storage backend.

## Documentation

- [API docs](https://docs.rs/aranya-crypto)
- [Changelog](CHANGELOG.md)
- [Examples](examples/)

## License

AGPL-3.0 - see [LICENSE.md](../../LICENSE.md)