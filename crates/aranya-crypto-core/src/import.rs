//! Importing and exporting data.

use core::{
    fmt::{self, Display},
    ops::Range,
    result::Result,
};

use buggy::Bug;
use generic_array::{ArrayLength, GenericArray};

use crate::signer::PkError;

/// A slice could not be converted to a fixed-size buffer.
#[derive(Debug, Eq, PartialEq)]
pub struct InvalidSizeError {
    /// The incorrect data size.
    pub got: usize,
    /// The expected data size.
    pub want: Range<usize>,
}

impl Display for InvalidSizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid size data: got {}, want {}..{}",
            self.got, self.want.start, self.want.end
        )
    }
}

impl core::error::Error for InvalidSizeError {}

/// An error that occured while importing data.
#[derive(Debug, Eq, PartialEq)]
pub enum ImportError {
    /// An unknown or internal error has occurred.
    Other(&'static str),
    /// The data is an incorrect size.
    InvalidSize(InvalidSizeError),
    /// The data is syntactically invalid.
    InvalidSyntax,
    /// The data came from a different context (e.g., a different
    /// `Engine`).
    InvalidContext,
    /// An internal bug was discovered.
    Bug(Bug),
    /// The Public Key is invalid.
    PkError(PkError),
}

impl Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(msg) => write!(f, "{}", msg),
            Self::InvalidSize(err) => write!(f, "{}", err),
            Self::InvalidSyntax => write!(f, "data is syntactically invalid"),
            Self::InvalidContext => write!(f, "data came from a different context"),
            Self::Bug(err) => write!(f, "{}", err),
            Self::PkError(err) => write!(f, "{}", err),
        }
    }
}

impl core::error::Error for ImportError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::InvalidSize(err) => Some(err),
            Self::Bug(err) => Some(err),
            _ => None,
        }
    }
}

impl From<InvalidSizeError> for ImportError {
    fn from(err: InvalidSizeError) -> Self {
        Self::InvalidSize(err)
    }
}

impl From<Bug> for ImportError {
    fn from(err: Bug) -> Self {
        Self::Bug(err)
    }
}

impl From<PkError> for ImportError {
    fn from(err: PkError) -> Self {
        Self::PkError(err)
    }
}

/// Shorthand for creating an [`InvalidSizeError`] when importing
/// a `&[u8]` to `[u8; N]`.
pub fn try_from_slice<const N: usize>(data: &[u8]) -> Result<&[u8; N], InvalidSizeError> {
    data.try_into().map_err(|_| InvalidSizeError {
        got: data.len(),
        want: N..N,
    })
}

/// Shorthand for creating [`ImportError::InvalidSize`] when
/// importing a `&[u8]` to some type that imports `[u8; N]`.
pub fn try_import<T, const N: usize>(data: &[u8]) -> Result<T, ImportError>
where
    T: Import<[u8; N]>,
{
    T::import(*try_from_slice(data)?)
}

impl<'a, const N: usize> Import<&'a [u8]> for &'a [u8; N] {
    fn import(data: &[u8]) -> Result<&[u8; N], ImportError> {
        data.try_into().map_err(|_| {
            ImportError::InvalidSize(InvalidSizeError {
                got: data.len(),
                want: N..N,
            })
        })
    }
}

impl<const N: usize> Import<&[u8]> for [u8; N] {
    fn import(data: &[u8]) -> Result<Self, ImportError> {
        let data: &[u8; N] = Import::<_>::import(data)?;
        Ok(*data)
    }
}

impl<const N: usize> Import<[u8; N]> for [u8; N] {
    #[inline]
    fn import(data: [u8; N]) -> Result<Self, ImportError> {
        Ok(data)
    }
}

impl<'a, N: ArrayLength> Import<&'a [u8]> for &'a GenericArray<u8, N> {
    fn import(data: &'a [u8]) -> Result<Self, ImportError> {
        GenericArray::try_from_slice(data).map_err(|_| {
            ImportError::InvalidSize(InvalidSizeError {
                got: data.len(),
                want: N::USIZE..N::USIZE,
            })
        })
    }
}

impl<N: ArrayLength> Import<&[u8]> for GenericArray<u8, N> {
    fn import(data: &[u8]) -> Result<Self, ImportError> {
        let data: &GenericArray<u8, N> = Import::<_>::import(data)?;
        Ok(data.clone())
    }
}

impl<N: ArrayLength> Import<GenericArray<u8, N>> for GenericArray<u8, N> {
    #[inline]
    fn import(data: GenericArray<u8, N>) -> Result<Self, ImportError> {
        Ok(data)
    }
}

/// Implemented by types that can be imported from its encoding.
pub trait Import<T>: Sized {
    /// Creates itself from its encoding.
    fn import(data: T) -> Result<Self, ImportError>;
}

/// An error that occurs while exporting secret key material.
#[derive(Debug, Eq, PartialEq)]
pub enum ExportError {
    /// An unknown or internal error has occurred.
    Other(&'static str),
    /// The key is opaque and does not expose its key material.
    Opaque,
}

impl Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(msg) => write!(f, "{}", msg),
            Self::Opaque => write!(f, "the key is opaque and cannot be exported"),
        }
    }
}

impl core::error::Error for ExportError {}
