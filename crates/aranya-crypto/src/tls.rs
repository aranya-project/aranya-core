//! TLS utilities.

#![cfg(feature = "tls")]
#![cfg_attr(docsrs, doc(cfg(feature = "tls")))]

mod psk;
mod suite;

pub use psk::{EncryptedPskSeed, Psk, PskId, PskSeed, PskSeedId};
pub use suite::CipherSuiteId;
