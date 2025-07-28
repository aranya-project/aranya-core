//! Error types for symbol resolution.

use buggy::Bug;

use crate::{
    compile::CompileError,
    hir::{IdentId, Span},
    symbol_resolution::{scope::DuplicateSymbolId, symbols::SymbolId},
};

/// Kinds of symbol resolution errors.
#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum SymbolResolutionError {
    /// An internal bug was discovered.
    #[error("internal bug: {0}")]
    Bug(#[from] Bug),

    /// An identifier was used but not defined.
    #[error("undefined identifier")]
    Undefined { ident: IdentId, span: Span },

    /// A symbol was defined multiple times in the same scope.
    #[error("{0}")]
    Duplicate(DuplicateSymbolId),

    /// Invalid shadowing.
    #[error("invalid shadowing of identifier")]
    InvalidShadowing {
        name: IdentId,
        original_span: Span,
        shadow_span: Span,
    },

    /// Invalid use of reserved identifier.
    #[error("reserved identifier")]
    ReservedIdentifier {
        ident: IdentId,
        span: Option<Span>,
        reserved_for: &'static str,
    },
}

impl From<SymbolResolutionError> for CompileError {
    fn from(_err: SymbolResolutionError) -> Self {
        todo!()
    }
}
