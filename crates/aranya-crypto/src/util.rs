#[cfg(feature = "tls")]
use crate::ciphersuite::CipherSuite;

#[cfg(feature = "tls")]
pub(crate) type Hpke<CS> = spideroak_crypto::hpke::Hpke<
    <CS as CipherSuite>::Kem,
    <CS as CipherSuite>::Kdf,
    <CS as CipherSuite>::Aead,
>;

#[cfg(any(feature = "memstore", feature = "test_util"))]
pub mod cbor {
    extern crate alloc;

    use alloc::vec::Vec;

    pub use ciborium::*;
    use serde::{Serialize, de::DeserializeOwned};

    pub fn to_allocvec<T: Serialize>(data: &T) -> Result<Vec<u8>, ser::Error<()>> {
        use ser::Error::*;
        let mut out = Vec::new();
        // NB: Remap errors because `ciborium_io` uses different
        // generic parameters depending whether `std` is enabled.
        // Yay.
        into_writer(data, &mut out).map_err(|err| match err {
            Io(_) => Io(()),
            Value(v) => Value(v),
        })?;
        Ok(out)
    }

    pub fn from_bytes<T: DeserializeOwned>(data: &[u8]) -> Result<T, de::Error<()>> {
        use de::Error::*;
        // NB: Remap errors because `ciborium_io` uses different
        // generic parameters depending whether `std` is enabled.
        // Yay.
        from_reader(data).map_err(|err| match err {
            Io(_) => Io(()),
            Syntax(v) => Syntax(v),
            Semantic(a, b) => Semantic(a, b),
            RecursionLimitExceeded => RecursionLimitExceeded,
        })
    }
}

#[cfg(feature = "tls")]
pub(crate) const fn is_zeroize_on_drop<T: crate::zeroize::ZeroizeOnDrop>(_: &T) {}
