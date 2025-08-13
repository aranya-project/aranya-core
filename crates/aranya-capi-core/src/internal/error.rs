use core::fmt;

use tracing::debug;

use crate::{
    as_mut,
    error::{ErrorCode, ExtendedError},
};

/// Converts `err` to `E2`.
#[cold]
#[track_caller]
pub fn convert_err<E1, E2>(err: &E1) -> E2
where
    E1: fmt::Display,
    E2: ErrorCode + for<'a> From<&'a E1>,
{
    debug!(%err);
    err.into()
}

/// Retrieves the error code from `err`, stores `err` in
/// `ext_err` if `ext_err` is non-null, suitably aligned, etc.,
/// then returns the error code.
#[cold]
#[track_caller]
pub fn handle_ext_error<E1, E2, E3>(err: E1, ext_err: *mut E2) -> E3
where
    E1: Into<<E2 as ExtendedError>::Error> + fmt::Display,
    E2: ExtendedError,
    E3: ErrorCode + for<'a> From<&'a E1>,
{
    debug!(%err);

    let res = (&err).into();
    if let Ok(ext_err) = as_mut!(ext_err) {
        ext_err.set(Some(err));
    }
    res
}
