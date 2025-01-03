//! Type conversions.

pub mod alias;
pub mod cast;
pub mod enums;
pub mod newtype;
pub mod ptr;
pub mod slice;

use core::{error, fmt};

use crate::safe::{Error, InvalidPtr};

/// Errors returned by the various conversion macros.
// TODO(eric): Get rid of this? It's unused.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ConvError {
    /// For pointers to `T`.
    Default(InvalidPtr),
    /// For pointers to `Safe<T>`.
    Safe(Error),
}

impl error::Error for ConvError {}

impl fmt::Display for ConvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default(err) => write!(f, "{err}"),
            Self::Safe(err) => write!(f, "{err}"),
        }
    }
}

impl From<InvalidPtr> for ConvError {
    fn from(err: InvalidPtr) -> Self {
        Self::Default(err)
    }
}

impl From<Error> for ConvError {
    fn from(err: Error) -> Self {
        Self::Safe(err)
    }
}

/// TODO
pub trait TryFromFfi: Sized {
    /// TODO
    type Ffi;
    /// TODO
    type Error: Into<ConvError>;
    /// # Safety
    ///
    /// TODO
    unsafe fn try_from_ffi(val: Self::Ffi) -> Result<Self, Self::Error>;
}

macro_rules! tuple_impls {
    ($($name:ident)+) => {
        impl<$($name: TryFromFfi),+> TryFromFfi for ($($name,)+) {
            type Ffi = ($($name::Ffi,)+);
            type Error = ConvError;
            #[inline]
            unsafe fn try_from_ffi(val: Self::Ffi) -> Result<Self, Self::Error> {
                #[allow(non_snake_case)]
                let ($($name,)+) = val;
                Ok(($(
                    // SAFETY: See the method's safety docs.
                    unsafe { TryFromFfi::try_from_ffi($name) }.map_err(Into::into)?,
                )+))
            }
        }
    };
}
tuple_impls! { A }
tuple_impls! { A B }
tuple_impls! { A B C }
tuple_impls! { A B C D }
tuple_impls! { A B C D E }
tuple_impls! { A B C D E F }
tuple_impls! { A B C D E F G }
tuple_impls! { A B C D E F G H }
tuple_impls! { A B C D E F G H I }
tuple_impls! { A B C D E F G H I J }
tuple_impls! { A B C D E F G H I J K }
tuple_impls! { A B C D E F G H I J K L }
tuple_impls! { A B C D E F G H I J K L M }
tuple_impls! { A B C D E F G H I J K L M N }
tuple_impls! { A B C D E F G H I J K L M N O }
tuple_impls! { A B C D E F G H I J K L M N O P }
tuple_impls! { A B C D E F G H I J K L M N O P Q }
tuple_impls! { A B C D E F G H I J K L M N O P Q R }
tuple_impls! { A B C D E F G H I J K L M N O P Q R S }
tuple_impls! { A B C D E F G H I J K L M N O P Q R S T }
tuple_impls! { A B C D E F G H I J K L M N O P Q R S T U }
tuple_impls! { A B C D E F G H I J K L M N O P Q R S T U V }
tuple_impls! { A B C D E F G H I J K L M N O P Q R S T U V W }
tuple_impls! { A B C D E F G H I J K L M N O P Q R S T U V W X }
tuple_impls! { A B C D E F G H I J K L M N O P Q R S T U V W X Y }
tuple_impls! { A B C D E F G H I J K L M N O P Q R S T U V W X Y Z }

impl<T> TryFromFfi for &T {
    type Ffi = *const T;
    type Error = InvalidPtr;
    unsafe fn try_from_ffi(val: Self::Ffi) -> Result<Self, Self::Error> {
        if val.is_null() {
            return Err(InvalidPtr::Null);
        }
        if !val.is_aligned() {
            return Err(InvalidPtr::Unaligned);
        }
        // SAFETY: `val` is non-null and aligned. See also the
        // method's safety docs.
        let xref = unsafe { &*val };
        Ok(xref)
    }
}

/// # Safety
///
/// TODO
pub unsafe fn tramp<F, A, R>(f: F, args: A::Ffi) -> Result<R, ConvError>
where
    A: TryFromFfi<Ffi = A>,
    F: FnOnce(A) -> R,
{
    // SAFETY: See the function's safety docs.
    let args = unsafe { TryFromFfi::try_from_ffi(args) }.map_err(Into::into)?;
    Ok(f(args))
}
