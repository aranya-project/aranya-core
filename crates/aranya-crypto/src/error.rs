#![forbid(unsafe_code)]

use buggy::Bug;

use crate::{
    aead::{OpenError, SealError},
    engine::{UnwrapError, WrapError},
    hpke::HpkeError,
    id::IdError,
    import::{ExportError, ImportError},
    kdf::KdfError,
    kem::{EcdhError, KemError},
    mac::MacError,
    signer::{PkError, SignerError},
};

/// Encompasses the different errors directly returned by this
/// crate.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An argument was invalid.
    ///
    /// It describes why the argument is invalid.
    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),
    /// An internal bug was discovered.
    #[error(transparent)]
    Bug(#[from] Bug),

    /// An AEAD seal failure.
    #[error(transparent)]
    Seal(#[from] SealError),
    /// An AEAD open failure.
    #[error(transparent)]
    Open(#[from] OpenError),
    /// An ECDH failure.
    #[error(transparent)]
    Ecdh(#[from] EcdhError),
    /// An HPKE failure.
    #[error(transparent)]
    Hpke(#[from] HpkeError),
    /// A KDF failure.
    #[error(transparent)]
    Kdf(#[from] KdfError),
    /// A KEM failure.
    #[error(transparent)]
    Kem(#[from] KemError),
    /// A MAC failure.
    #[error(transparent)]
    Mac(#[from] MacError),
    /// A digital signature failure.
    #[error(transparent)]
    Signer(#[from] SignerError),
    /// An import failure.
    #[error(transparent)]
    Import(#[from] ImportError),
    /// An export failure.
    #[error(transparent)]
    Export(#[from] ExportError),
    /// A key wrapping failure.
    #[error(transparent)]
    Wrap(#[from] WrapError),
    /// A key unwrapping failure.
    #[error(transparent)]
    Unwrap(#[from] UnwrapError),
    /// An identifier failure.
    #[error(transparent)]
    Id(#[from] IdError),
    /// A public key failure.
    #[error(transparent)]
    Pk(#[from] PkError),
}
