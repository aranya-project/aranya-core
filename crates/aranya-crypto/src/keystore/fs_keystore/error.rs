use core::fmt;

use buggy::Bug;
use ciborium as cbor;
use rustix::io::Errno;

use crate::keystore::{self, ErrorKind};

#[derive(Copy, Clone, Debug, thiserror::Error)]
#[error("unexpected EOF")]
pub(crate) struct UnexpectedEof;

/// An error returned by [`super::Store`].
#[derive(Debug)]
pub struct Error(Repr);

impl Error {
    /// Attempts to downcast the error into `T`.
    #[inline]
    pub fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        self.0.downcast_ref::<T>()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        self.0.source()
    }
}

impl keystore::Error for Error {
    fn new<E>(kind: ErrorKind, err: E) -> Self
    where
        E: core::error::Error + Send + Sync + 'static,
    {
        match kind {
            ErrorKind::AlreadyExists => Self(Repr::AlreadyExists),
            _ => Self(Repr::new(&err)),
        }
    }

    fn kind(&self) -> ErrorKind {
        match self.0 {
            Repr::AlreadyExists => ErrorKind::AlreadyExists,
            _ => ErrorKind::Other,
        }
    }
}

impl From<UnexpectedEof> for Error {
    fn from(err: UnexpectedEof) -> Self {
        <Self as keystore::Error>::other(err)
    }
}

impl From<Errno> for Error {
    fn from(err: Errno) -> Self {
        <Self as keystore::Error>::other(err)
    }
}

impl<T> From<cbor::de::Error<T>> for Error
where
    T: core::error::Error + Send + Sync + 'static,
{
    fn from(err: cbor::de::Error<T>) -> Self {
        <Self as keystore::Error>::other(err)
    }
}

impl<T> From<cbor::ser::Error<T>> for Error
where
    T: core::error::Error + Send + Sync + 'static,
{
    fn from(err: cbor::ser::Error<T>) -> Self {
        <Self as keystore::Error>::other(err)
    }
}

impl From<Bug> for Error {
    fn from(err: Bug) -> Self {
        <Self as keystore::Error>::other(err)
    }
}

impl From<RootDeleted> for Error {
    fn from(err: RootDeleted) -> Self {
        <Self as keystore::Error>::other(err)
    }
}

#[derive(Debug)]
enum Repr {
    AlreadyExists,
    UnexpectedEof(UnexpectedEof),
    Bug(Bug),
    Errno(Errno),
    Encode(cbor::ser::Error<Errno>),
    Decode(cbor::de::Error<Errno>),
    RootDeleted(RootDeleted),
    Other,
}

impl Repr {
    fn new(err: &dyn core::any::Any) -> Self {
        if let Some(err) = err.downcast_ref::<UnexpectedEof>() {
            Self::UnexpectedEof(*err)
        } else if let Some(err) = err.downcast_ref::<Errno>() {
            Self::Errno(*err)
        } else if let Some(err) = err.downcast_ref::<cbor::ser::Error<Errno>>() {
            // ugh no `Clone`
            Self::Encode(match err {
                cbor::ser::Error::Io(x) => cbor::ser::Error::Io(*x),
                cbor::ser::Error::Value(x) => cbor::ser::Error::Value(x.clone()),
            })
        } else if let Some(err) = err.downcast_ref::<cbor::de::Error<Errno>>() {
            // ugh no `Clone`
            Self::Decode(match err {
                cbor::de::Error::Io(x) => cbor::de::Error::Io(*x),
                cbor::de::Error::Syntax(x) => cbor::de::Error::Syntax(*x),
                cbor::de::Error::Semantic(x, y) => cbor::de::Error::Semantic(*x, y.clone()),
                cbor::de::Error::RecursionLimitExceeded => cbor::de::Error::RecursionLimitExceeded,
            })
        } else if let Some(err) = err.downcast_ref::<Bug>() {
            Self::Bug(err.clone())
        } else if let Some(err) = err.downcast_ref::<RootDeleted>() {
            Self::RootDeleted(err.clone())
        } else {
            Self::Other
        }
    }

    fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        match self {
            Self::AlreadyExists => None,
            Self::UnexpectedEof(err) => downcast_ref(err),
            Self::Errno(err) => downcast_ref(err),
            Self::Encode(err) => downcast_ref(err),
            Self::Decode(err) => downcast_ref(err),
            Self::Bug(err) => downcast_ref(err),
            Self::RootDeleted(err) => downcast_ref(err),
            Self::Other => None,
        }
    }

    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::AlreadyExists => None,
            Self::UnexpectedEof(err) => Some(err),
            Self::Errno(err) => Some(err),
            Self::Encode(err) => Some(err),
            Self::Decode(err) => Some(err),
            Self::Bug(err) => Some(err),
            Self::RootDeleted(err) => Some(err),
            Self::Other => None,
        }
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => write!(f, "entry already exists"),
            Self::UnexpectedEof(err) => err.fmt(f),
            Self::Errno(err) => err.fmt(f),
            Self::Encode(err) => err.fmt(f),
            Self::Decode(err) => err.fmt(f),
            Self::Bug(err) => err.fmt(f),
            Self::RootDeleted(err) => err.fmt(f),
            Self::Other => write!(f, "unknown error"),
        }
    }
}

/// Downcasts `E` to `T`.
#[inline(always)]
fn downcast_ref<T: 'static, E: 'static>(err: &E) -> Option<&T> {
    (err as &dyn core::any::Any).downcast_ref()
}

/// The root keystore directory was deleted.
#[derive(Clone, Debug, thiserror::Error)]
#[error("root keystore directory deleted")]
pub struct RootDeleted(pub(crate) ());

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use super::*;

    #[cfg(feature = "std")]
    mod conversion {
        use keystore::Error as _;

        use super::*;

        #[test]
        fn already_exists() {
            assert!(matches!(
                Error::new(ErrorKind::AlreadyExists, Errno::INVAL),
                Error(Repr::AlreadyExists)
            ));
        }

        #[test]
        fn errno() {
            assert!(matches!(
                Error::new(ErrorKind::Other, Errno::INVAL),
                Error(Repr::Errno(Errno::INVAL))
            ));
        }

        #[test]
        fn encode() {
            assert!(matches!(
                Error::new(ErrorKind::Other, cbor::ser::Error::Io(Errno::INVAL)),
                Error(Repr::Encode(cbor::ser::Error::Io(Errno::INVAL)))
            ));

            assert!(matches!(
                Error::new(
                    ErrorKind::Other,
                    cbor::ser::Error::<Errno>::Value(String::from("asdf"))
                ),
                Error(Repr::Encode(cbor::ser::Error::Value(_)))
            ));
        }

        #[test]
        fn decode() {
            assert!(matches!(
                Error::new(ErrorKind::Other, cbor::de::Error::Io(Errno::INVAL)),
                Error(Repr::Decode(cbor::de::Error::Io(Errno::INVAL)))
            ));

            assert!(matches!(
                Error::new(
                    ErrorKind::Other,
                    cbor::de::Error::<Errno>::Semantic(Some(42), String::from("asdf"))
                ),
                Error(Repr::Decode(cbor::de::Error::Semantic(Some(42), _)))
            ));
        }

        #[test]
        fn trait_object() {
            // Limitation of current approach
            assert!(matches!(
                Error::new::<&(dyn core::error::Error + Send + Sync + 'static)>(
                    ErrorKind::Other,
                    &Errno::INVAL
                ),
                Error(Repr::Other)
            ));
        }
    }
}
