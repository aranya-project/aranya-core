//! Cryptography code for [AQC].
//!
//! [AQC]: https://github.com/aranya-project/aranya-docs/tree/2-quic-channels

#![cfg(feature = "aqc")]
#![cfg_attr(docsrs, doc(cfg(feature = "aqc")))]

mod bidi;
mod shared;
mod uni;

pub use bidi::*;
pub use uni::*;

pub use crate::tls::CipherSuiteId;

// This is different from the rest of the `crypto` API in that it
// allows users to directly access key material. Unfortunately,
// we have to allow this since AQC needs to store the raw PSK
// secret.

impl crate::error::Error {
    pub(crate) const fn invalid_psk_length() -> Self {
        Self::InvalidArgument("invalid `psk_length_in_bytes` valid")
    }
}
