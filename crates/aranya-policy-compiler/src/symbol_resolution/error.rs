//! Error types for symbol resolution.

use aranya_policy_ast::Identifier;
use buggy::Bug;

use crate::symbol_resolution::symbols::{Duplicate, Symbol};

/// Kinds of symbol resolution errors.
#[derive(Clone, Debug, thiserror::Error)]
pub enum SymbolResolutionError {
    /// An internal bug was discovered.
    #[error("internal bug: {0}")]
    Bug(#[from] Bug),

    /// An identifier was used but not defined.
    #[error("undefined identifier {ident}")]
    Undefined { ident: Identifier, location: usize },

    /// A symbol was defined multiple times in the same scope.
    #[error("{0}")]
    Duplicate(Duplicate),

    /// Invalid shadowing.
    #[error("invalid shadowing of identifier {name}")]
    InvalidShadowing {
        name: Identifier,
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
