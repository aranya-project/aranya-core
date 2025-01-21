//! Importing and exporting data.

use core::{ops::Range, result::Result};

use aranya_buggy::Bug;
use generic_array::{ArrayLength, GenericArray};

use crate::signer::PkError;

/// A slice could not be converted to a fixed-size buffer.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid size data: got {got}, want {start}..{end}", start = self.want.start, end = self.want.end)]
pub struct InvalidSizeError {
    /// The incorrect data size.
    pub got: usize,
    /// The expected data size.
    pub want: Range<usize>,
}

/// An error that occured while importing data.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum ImportError {
    /// An unknown or internal error has occurred.
    #[error("{0}")]
    Other(&'static str),
    /// The data is an incorrect size.
    #[error(transparent)]
    InvalidSize(#[from] InvalidSizeError),
    /// The data is syntactically invalid.
    #[error("data is syntactically invalid")]
    InvalidSyntax,
    /// The data came from a different context (e.g., a different
    /// `Engine`).
    #[error("data came from a different context")]
    InvalidContext,
    /// An internal bug was discovered.
    #[error(transparent)]
    Bug(#[from] Bug),
    /// The Public Key is invalid.
    #[error(transparent)]
    PkError(#[from] PkError),
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
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum ExportError {
    /// An unknown or internal error has occurred.
    #[error("{0}")]
    Other(&'static str),
    /// The key is opaque and does not expose its key material.
    #[error("the key is opaque and cannot be exported")]
    Opaque,
}
