use core::fmt;

use aranya_crypto::{CipherSuite, EncryptionPublicKey};
use serde::{Deserialize, Serialize};

/// Decodes a [`EncryptionPublicKey`].
pub(crate) fn decode_enc_pk<CS: CipherSuite>(
    bytes: &[u8],
) -> postcard::Result<EncryptionPublicKey<CS>> {
    postcard::from_bytes(bytes)
}

/// Associates a [`Channel`] with Aranya policy rules that govern
/// communication in the channel.
///
/// Labels are defined inside Aranya policy.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct Label(i64);

impl Label {
    /// Creates a label from its corresponding policy ID.
    pub const fn new(label: i64) -> Self {
        Self(label)
    }

    /// Creates a label from its byte representation.
    pub const fn from_bytes(b: [u8; 8]) -> Self {
        Self(i64::from_le_bytes(b))
    }

    /// Converts the label to its byte representation.
    pub const fn to_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Converts the label to a `i64`.
    pub const fn to_i64(self) -> i64 {
        self.0
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_i64().fmt(f)
    }
}

impl From<Label> for i64 {
    #[inline]
    fn from(label: Label) -> i64 {
        label.to_i64()
    }
}

impl From<i64> for Label {
    #[inline]
    fn from(id: i64) -> Self {
        Self::new(id)
    }
}
