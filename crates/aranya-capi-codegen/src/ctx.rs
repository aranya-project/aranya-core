use std::{cell::RefCell, fmt::Display};

use quote::ToTokens;
use syn::{Error, Ident, Path, Result};
use tracing::{error, instrument};

/// Code generation context.
#[derive(Debug)]
pub(crate) struct Ctx {
    /// The `#capi` in `extern aranya_capi_core as #capi`.
    pub capi: Ident,
    /// Path to `aranya_capi_core::internal::conv`.
    pub conv: Path,
    /// Path to `aranya_capi_core::internal::util`.
    pub util: Path,
    /// Path to `aranya_capi_core::internal::error`.
    pub error: Path,

    /// Path to the error code.
    pub err_ty: Path,
    /// Path to the extended error type.
    pub ext_err_ty: Path,

    /// Function identifier prefix.
    ///
    /// E.g., `os` converts `fn foo` to `fn os_foo`.
    pub fn_prefix: Ident,
    /// Type identifier prefix.
    ///
    /// E.g., `Os` converts `struct Foo` to `struct OsFoo`.
    pub ty_prefix: Ident,

    /// Path to the module where defs live.
    pub defs: Path,

    // Internal module paths for generated code.
    pub hidden: Ident,
    pub imports: Ident,

    /// Collected errors.
    ///
    /// We collect errors instead of immediately failing so that
    /// we can provide better error reporting.
    pub errs: RefCell<Errors>,
}

impl Ctx {
    /// Adds an error.
    pub fn error(&self, tokens: impl ToTokens, msg: impl Display) {
        self.errs.borrow_mut().error(tokens, msg);
    }

    /// Adds an [`Error`].
    pub fn push(&self, err: Error) {
        self.errs.borrow_mut().push(err);
    }

    /// Combines the errors, returning `Ok` if there are none or
    /// `Err` otherwise.
    pub fn propagate(&mut self) -> Result<()> {
        self.errs.borrow_mut().propagate()
    }
}

/// Taken from [`cxx`].
///
/// [`cxx`]: https://github.com/dtolnay/cxx/blob/afd4aa3f3d4e5d5e9a3a41d09df3408f5f86a469/syntax/report.rs
#[derive(Debug, Default)]
pub(crate) struct Errors(Vec<Error>);

impl Errors {
    #[instrument(skip_all)]
    fn push(&mut self, err: Error) {
        error!(%err);

        self.0.push(err);
    }

    fn error(&mut self, tokens: impl ToTokens, msg: impl Display) {
        // NB: We call `self.push` for logging purposes.
        self.push(Error::new_spanned(tokens, msg));
    }

    /// Combines the errors, returning `Ok` if there are none or
    /// `Err` otherwise.
    fn propagate(&mut self) -> Result<()> {
        let mut iter = self.0.drain(..);
        let mut all = match iter.next() {
            Some(err) => err,
            None => return Ok(()),
        };
        for err in iter {
            all.combine(err);
        }
        Err(all)
    }

    #[cfg(test)]
    pub(crate) fn clear(&mut self) {
        self.0.clear();
    }
}
