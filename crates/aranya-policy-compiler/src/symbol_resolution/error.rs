//! Error types for symbol resolution.

use aranya_policy_ast as ast;
use buggy::Bug;

use super::{
    scope::{DuplicateSymbolId, ScopeId},
    symbols::SymbolId,
};
use crate::{
    compile::CompileError,
    diag::{Diag, DiagCtx, Diagnostic, EmissionGuarantee, Severity},
    hir::{IdentId, Span},
};

/// Kinds of symbol resolution errors.
#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum SymbolResolutionError {
    /// An internal bug was discovered.
    #[error("internal bug: {0}")]
    Bug(#[from] Bug),

    /// An identifier was used but not defined.
    #[error("undefined identifier")]
    Undefined {
        ident: ast::Identifier,
        span: Span,
        scope: ScopeId,
    },

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
        ident: IdentId,
        span: Span,
        reserved_for: &'static str,
    },
}

impl From<SymbolResolutionError> for CompileError {
    fn from(_err: SymbolResolutionError) -> Self {
        todo!()
    }
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for SymbolResolutionError {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        match self {
            SymbolResolutionError::Bug(bug) =>  {
                Diag::new(ctx,severity,bug.to_string())
            }
            SymbolResolutionError::Undefined { span, .. } => {
                Diag::new(ctx,severity,"undefined identifier")
                    .with_span(span)
            }
            SymbolResolutionError::Duplicate(_id) => {
                //ctx.struct_span_err(id.ident.span(), "duplicate symbol")
                todo!()
            }
            SymbolResolutionError::InvalidShadowing {
                ..
                // name,
                // original_span,
                // shadow_span,
            } => { todo!() }
            SymbolResolutionError::Reserved { .. } => {
                todo!()
            }
        }
    }
}
