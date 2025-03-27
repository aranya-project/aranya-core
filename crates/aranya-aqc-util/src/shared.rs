use core::fmt;

use aranya_crypto::{CipherSuite, EncryptionPublicKey};
use serde::{Deserialize, Serialize};

/// Decodes a [`EncryptionPublicKey`].
pub(crate) fn decode_enc_pk<CS: CipherSuite>(
    bytes: &[u8],
) -> postcard::Result<EncryptionPublicKey<CS>> {
    postcard::from_bytes(bytes)
}

/// Associates an AQC channel with Aranya policy rules that
/// govern communication in the channel.
///
/// Labels are defined inside Aranya policy.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct Label(u32);

impl Label {
    /// Creates a label from its corresponding policy ID.
    pub const fn new(label: u32) -> Self {
        Self(label)
    }

    /// Creates a label from its byte representation.
    pub const fn from_bytes(b: [u8; 4]) -> Self {
        Self(u32::from_le_bytes(b))
    }

    /// Converts the label to its byte representation.
    pub const fn to_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }

    /// Converts the label to a `u32`.
    pub const fn to_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_u32().fmt(f)
    }
}

impl From<Label> for u32 {
    #[inline]
    fn from(label: Label) -> u32 {
        label.to_u32()
    }
}

impl From<u32> for Label {
    #[inline]
    fn from(id: u32) -> Self {
        Self::new(id)
    }
}
