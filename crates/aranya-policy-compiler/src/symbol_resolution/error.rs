//! Error types for symbol resolution.

use aranya_policy_ast as ast;
use buggy::Bug;

use super::scope::{DuplicateSymbolId, ScopeId};
use crate::{
    diag::{Diag, DiagCtx, Diagnostic, EmissionGuarantee, Severity},
    hir::{IdentId, Span},
};

/// Kinds of symbol resolution errors.
#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum SymbolResolutionError {
    /// An internal bug was discovered.
    #[error("internal bug: {0}")]
    Bug(#[from] Bug),

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
    Reserved {
        ident: ast::Identifier,
        span: Span,
        reserved_for: &'static str,
    },
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for SymbolResolutionError {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        match self {
            SymbolResolutionError::Bug(bug) => Diag::new(ctx, severity, bug.to_string()),
            SymbolResolutionError::Duplicate(_id) => {
                todo!()
            }
            SymbolResolutionError::InvalidShadowing { .. } => {
                todo!()
            }
            SymbolResolutionError::Reserved { .. } => {
                todo!()
            }
        }
    }
}
