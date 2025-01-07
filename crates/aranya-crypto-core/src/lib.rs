//! Low level Aranya cryptography

#![allow(unstable_name_collisions)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![warn(missing_docs)]

pub(crate) use aranya_crypto_derive::AlgId;
pub mod aead;
pub mod asn1;
pub mod bearssl;
pub mod csprng;
pub mod default;
pub mod ec;
pub mod ed25519;
mod error;
pub mod hash;
pub mod hex;
pub mod hkdf;
pub mod hmac;
pub mod hpke;
pub mod import;
pub mod kdf;
pub mod kem;
pub mod keys;
pub mod mac;
pub mod rust;
pub mod signer;
pub mod test_util;
mod util;
pub mod zeroize;

pub use aead::{BufferTooSmallError, OpenError, SealError};
pub use aranya_buggy;
pub use csprng::{Csprng, Random};
pub use default::Rng;
pub use error::*;
pub use generic_array;
pub use hpke::HpkeError;
pub use import::{ExportError, ImportError};
pub use kdf::KdfError;
pub use kem::{EcdhError, KemError};
pub use mac::MacError;
pub use signer::SignerError;
pub use subtle;
pub use typenum;
