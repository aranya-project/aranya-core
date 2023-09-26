#![forbid(unsafe_code)]

use {cfg_if::cfg_if, core::fmt};

#[cfg(feature = "alloc")]
use crate::idam::KeyConversionError;

use crate::{
    aead::AeadError,
    engine::{UnwrapError, WrapError},
    hpke::HpkeError,
    import::{ExportError, ImportError},
    kdf::KdfError,
    kem::{EcdhError, KemError},
    mac::MacError,
    signer::SignerError,
};

cfg_if! {
    if #[cfg(feature = "error_in_core")] {
        use core::error;
    } else if #[cfg(feature = "std")] {
        use std::error;
    }
}

/// Encompasses the different errors directly returned by this
/// crate.
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// An argument was invalid.
    ///
    /// It describes why the argument is invalid.
    InvalidArgument(&'static str),

    /// An AEAD failure.
    Aead(AeadError),
    /// An ECDH failure.
    Ecdh(EcdhError),
    /// An HPKE failure.
    Hpke(HpkeError),
    /// A KDF failure.
    Kdf(KdfError),
    /// A KEM failure.
    Kem(KemError),
    /// A MAC failure.
    Mac(MacError),
    /// A digital signature failure.
    Signer(SignerError),
    /// An import failure.
    Import(ImportError),
    /// An export failure.
    Export(ExportError),
    /// A key wrapping failure.
    Wrap(WrapError),
    /// A key unwrapping failure.
    Unwrap(UnwrapError),
    /// A key conversion failure.
    #[cfg(feature = "alloc")]
    KeyConversion(KeyConversionError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {}", msg),

            Self::Aead(err) => write!(f, "{}", err),
            Self::Ecdh(err) => write!(f, "{}", err),
            Self::Hpke(err) => write!(f, "{}", err),
            Self::Kdf(err) => write!(f, "{}", err),
            Self::Kem(err) => write!(f, "{}", err),
            Self::Mac(err) => write!(f, "{}", err),
            Self::Signer(err) => write!(f, "{}", err),
            Self::Import(err) => write!(f, "{}", err),
            Self::Export(err) => write!(f, "{}", err),
            Self::Wrap(err) => write!(f, "{}", err),
            Self::Unwrap(err) => write!(f, "{}", err),
            #[cfg(feature = "alloc")]
            Self::KeyConversion(err) => write!(f, "{}", err),
        }
    }
}

#[cfg_attr(docs, doc(cfg(any(feature = "error_in_core", feature = "std"))))]
#[cfg(any(feature = "error_in_core", feature = "std"))]
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Aead(err) => Some(err),
            Self::Ecdh(err) => Some(err),
            Self::Hpke(err) => Some(err),
            Self::Kdf(err) => Some(err),
            Self::Kem(err) => Some(err),
            Self::Mac(err) => Some(err),
            Self::Signer(err) => Some(err),
            Self::Import(err) => Some(err),
            Self::Export(err) => Some(err),
            Self::Wrap(err) => Some(err),
            Self::Unwrap(err) => Some(err),
            Self::KeyConversion(err) => Some(err),
            _ => None,
        }
    }
}

impl From<AeadError> for Error {
    fn from(err: AeadError) -> Self {
        Self::Aead(err)
    }
}

impl From<HpkeError> for Error {
    fn from(err: HpkeError) -> Self {
        Self::Hpke(err)
    }
}

impl From<KdfError> for Error {
    fn from(err: KdfError) -> Self {
        Self::Kdf(err)
    }
}

impl From<KemError> for Error {
    fn from(err: KemError) -> Self {
        Self::Kem(err)
    }
}

impl From<MacError> for Error {
    fn from(err: MacError) -> Self {
        Self::Mac(err)
    }
}

impl From<SignerError> for Error {
    fn from(err: SignerError) -> Self {
        Self::Signer(err)
    }
}

impl From<ImportError> for Error {
    fn from(err: ImportError) -> Self {
        Self::Import(err)
    }
}

impl From<ExportError> for Error {
    fn from(err: ExportError) -> Self {
        Self::Export(err)
    }
}

impl From<WrapError> for Error {
    fn from(err: WrapError) -> Self {
        Self::Wrap(err)
    }
}

impl From<UnwrapError> for Error {
    fn from(err: UnwrapError) -> Self {
        Self::Unwrap(err)
    }
}

#[cfg(feature = "alloc")]
impl From<KeyConversionError> for Error {
    fn from(err: KeyConversionError) -> Self {
        Self::KeyConversion(err)
    }
}

/// Returns [`Unreachable`], or invokes [`unreachable`] if
/// `debug_assertions` is enabled.
#[allow(unused_macros)] // used by some features
macro_rules! safe_unreachable {
    ($msg:expr) => {{
        if cfg!(debug_assertions) {
            ::core::unreachable!($msg);
        }
        $crate::error::Unreachable(::const_format::formatcp!(
            "{}:{}: {}",
            ::core::file!(),
            ::core::line!(),
            $msg
        ))
    }};
}
#[allow(unused_imports)] // used by some features
pub(crate) use safe_unreachable;

/// Returned when a code path should be unreachable.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Unreachable(pub(crate) &'static str);

impl Unreachable {
    /// Returns a human-readable string describing the error.
    pub fn as_str(&self) -> &'static str {
        "unreachable"
    }
}

impl fmt::Display for Unreachable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BUG: unreachable: {}", self.0)
    }
}

#[cfg_attr(docs, doc(cfg(any(feature = "error_in_core", feature = "std"))))]
#[cfg(any(feature = "error_in_core", feature = "std"))]
impl error::Error for Unreachable {}
