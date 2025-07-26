//! Error types for symbol resolution.

use buggy::Bug;

use crate::{
    hir::hir::IdentId,
    symbol_resolution::{
        scope::DuplicateSymbolId,
        symbols::Symbol,
    },
};

/// Kinds of symbol resolution errors.
#[derive(Clone, Debug, thiserror::Error)]
pub enum SymbolResolutionError {
    /// An internal bug was discovered.
    #[error("internal bug: {0}")]
    Bug(#[from] Bug),

    /// An identifier was used but not defined.
    #[error("undefined identifier")]
    Undefined { ident: IdentId, location: usize },

    /// A symbol was defined multiple times in the same scope.
    #[error("{0}")]
    Duplicate(DuplicateSymbolId),

    /// Invalid shadowing.
    #[error("invalid shadowing of identifier")]
    InvalidShadowing {
        name: IdentId,
        original_location: usize,
        shadow_location: usize,
    },

    /// Invalid use of reserved identifier.
    #[error("reserved identifier")]
    ReservedIdentifier {
        sym: Symbol,
        reserved_for: &'static str,
    },
}
