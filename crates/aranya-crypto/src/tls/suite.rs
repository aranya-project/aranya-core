use core::fmt;

use serde::{Deserialize, Serialize};
use zerocopy::{Immutable, IntoBytes, KnownLayout};

/// A TLS version.
#[repr(u16)]
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Hash,
    Immutable,
    IntoBytes,
    KnownLayout,
    Serialize,
    Deserialize,
)]
#[non_exhaustive]
pub(crate) enum Version {
    Tls13 = u16::to_be(0x0304),
}

/// A TLS 1.3 cipher suite.
#[repr(u16)]
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Hash,
    Immutable,
    IntoBytes,
    KnownLayout,
    Serialize,
    Deserialize,
)]
#[non_exhaustive]
pub enum CipherSuiteId {
    /// TLS_AES_128_GCM_SHA256
    #[serde(rename = "TLS_AES_128_GCM_SHA256")]
    TlsAes128GcmSha256 = u16::to_be(0x1301),
    /// TLS_AES_256_GCM_SHA384
    #[serde(rename = "TLS_AES_256_GCM_SHA384")]
    TlsAes256GcmSha384 = u16::to_be(0x1302),
    /// TLS_CHACHA20_POLY1305_SHA256
    #[serde(rename = "TLS_CHACHA20_POLY1305_SHA256")]
    TlsChaCha20Poly1305Sha256 = u16::to_be(0x1303),
    /// TLS_AES_128_CCM_SHA256
    #[serde(rename = "TLS_AES_128_CCM_SHA256")]
    TlsAes128CcmSha256 = u16::to_be(0x1304),
    /// TLS_AES_128_CCM_8_SHA256
    #[serde(rename = "TLS_AES_128_CCM_8_SHA256")]
    TlsAes128Ccm8Sha256 = u16::to_be(0x1305),
}

impl CipherSuiteId {
    /// Returns all of the cipher suites.
    pub const fn all() -> &'static [Self] {
        use CipherSuiteId::{
            TlsAes128Ccm8Sha256, TlsAes128CcmSha256, TlsAes128GcmSha256, TlsAes256GcmSha384,
            TlsChaCha20Poly1305Sha256,
        };
        &[
            TlsAes128GcmSha256,
            TlsAes256GcmSha384,
            TlsChaCha20Poly1305Sha256,
            TlsAes128CcmSha256,
            TlsAes128Ccm8Sha256,
        ]
    }

    /// Converts the cipher suite to its (big endian) byte
    /// representation.
    pub const fn to_bytes(self) -> [u8; 2] {
        zerocopy::transmute!(self)
    }

    /// Attempts to create a cipher suite from its (big endian)
    /// byte representation.
    ///
    /// It returns `None` if `bytes` is not a valid cipher suite.
    pub const fn try_from_bytes(bytes: [u8; 2]) -> Option<Self> {
        use CipherSuiteId::{
            TlsAes128Ccm8Sha256, TlsAes128CcmSha256, TlsAes128GcmSha256, TlsAes256GcmSha384,
            TlsChaCha20Poly1305Sha256,
        };
        let id = match u16::from_be_bytes(bytes) {
            0x1301 => TlsAes128GcmSha256,
            0x1302 => TlsAes256GcmSha384,
            0x1303 => TlsChaCha20Poly1305Sha256,
            0x1304 => TlsAes128CcmSha256,
            0x1305 => TlsAes128Ccm8Sha256,
            _ => return None,
        };
        Some(id)
    }
}

impl fmt::Display for CipherSuiteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CipherSuiteId::{
            TlsAes128Ccm8Sha256, TlsAes128CcmSha256, TlsAes128GcmSha256, TlsAes256GcmSha384,
            TlsChaCha20Poly1305Sha256,
        };
        let name = match self {
            TlsAes128GcmSha256 => "TLS_AES_128_GCM_SHA256",
            TlsAes256GcmSha384 => "TLS_AES_256_GCM_SHA384",
            TlsChaCha20Poly1305Sha256 => "TLS_CHACHA20_POLY1305_SHA256",
            TlsAes128CcmSha256 => "TLS_AES_128_CCM_SHA256",
            TlsAes128Ccm8Sha256 => "TLS_AES_128_CCM_8_SHA256",
        };
        name.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_suite_id() {
        use CipherSuiteId::*;
        let tests = [
            ([0x13, 0x01], Some(TlsAes128GcmSha256)),
            ([0x13, 0x02], Some(TlsAes256GcmSha384)),
            ([0x13, 0x03], Some(TlsChaCha20Poly1305Sha256)),
            ([0x13, 0x04], Some(TlsAes128CcmSha256)),
            ([0x13, 0x05], Some(TlsAes128Ccm8Sha256)),
            ([0x13, 0x00], None),
            ([0x13, 0x06], None),
        ];
        for (idx, (bytes, suite)) in tests.into_iter().enumerate() {
            let got = CipherSuiteId::try_from_bytes(bytes);
            assert_eq!(got, suite, "#{idx}");

            let Some(suite) = suite else {
                continue;
            };

            assert_eq!(suite.to_bytes(), bytes, "#{idx}");

            // Ensure that the `zerocopy` impls match the manual
            // methods.
            let got = suite.as_bytes();
            let want = suite.to_bytes();
            assert_eq!(got, want, "#{idx}");
        }
    }

    #[test]
    fn test_cipher_suite_round_trip() {
        for &suite in CipherSuiteId::all() {
            let got = CipherSuiteId::try_from_bytes(suite.to_bytes());
            assert_eq!(got, Some(suite), "{suite}");
        }
    }
}
