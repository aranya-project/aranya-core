//! [`Id`]s and generation of [`custom_id`] types.

#![forbid(unsafe_code)]

use core::iter;

pub use aranya_id::*;
use buggy::Bug;
use spideroak_crypto::{csprng::Csprng, signer::PkError};

use crate::ciphersuite::{CipherSuite, CipherSuiteExt as _};

/// Extension trait for IDs.
pub trait IdExt: Sized {
    /// Derives an [`Id`] from the hash of some data.
    fn new<'a, CS: CipherSuite>(
        tag: &'static [u8],
        context: impl IntoIterator<Item = &'a [u8]>,
    ) -> Self;

    /// Creates a random ID.
    fn random<R: Csprng>(rng: &mut R) -> Self;
}

impl<I> IdExt for I
where
    [u8; 32]: Into<I>,
{
    /// Derives an [`Id`] from the hash of some data.
    fn new<'a, CS: CipherSuite>(
        tag: &'static [u8],
        data: impl IntoIterator<Item = &'a [u8]>,
    ) -> Self {
        // id = H("ID-v1" || suites || data || tag)
        CS::tuple_hash(b"ID-v1", data.into_iter().chain(iter::once(tag)))
            .into_array()
            .into_array()
            .into()
    }

    /// Creates a random ID.
    fn random<R: Csprng>(rng: &mut R) -> Self {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        b.into()
    }
}

/// An object with a unique identifier.
pub trait Identified {
    /// Uniquely identifies the object.
    type Id: Copy
        + Clone
        + core::fmt::Display
        + core::fmt::Debug
        + core::hash::Hash
        + Eq
        + PartialEq
        + Ord
        + PartialOrd
        + serde::Serialize
        + serde::de::DeserializeOwned
        + Into<Id>;

    /// Uniquely identifies the object.
    fn id(&self) -> Result<Self::Id, IdError>;
}

/// An error that may occur when accessing an Id
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct IdError(IdErrorRepr);

impl IdError {
    pub(crate) const fn new(msg: &'static str) -> Self {
        Self(IdErrorRepr::Msg(msg))
    }
}

impl From<Bug> for IdError {
    #[inline]
    fn from(err: Bug) -> Self {
        Self(IdErrorRepr::Bug(err))
    }
}

impl From<PkError> for IdError {
    fn from(err: PkError) -> Self {
        Self::new(err.msg())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
enum IdErrorRepr {
    #[error("{0}")]
    Bug(Bug),
    #[error("{0}")]
    Msg(&'static str),
}
