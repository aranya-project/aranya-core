mod check;
mod types;
mod unify;

pub(crate) use types::{Type, TypeError, TypeErrorKind, TypeId, TypeKind};

use std::collections::BTreeMap;

use crate::{ctx::Ctx, hir::{ExprId, Hir}};

/// Result type for type checking operations.
pub(crate) type Result<T, E = Vec<TypeError>> = std::result::Result<T, E>;

impl Ctx<'_> {
    /// Performs type checking on the HIR.
    /// 
    /// This runs a single-pass type checker that computes types for all
    /// expressions and validates type constraints.
    /// 
    /// # Returns
    /// 
    /// Returns `Ok(())` if type checking succeeds, or `Err(errors)` with
    /// a list of type errors if it fails.
    pub fn typecheck(&mut self) -> Result<BTreeMap<ExprId, Type>> {
        // Create the type checker with HIR and symbols
        let checker = check::TypeChecker::new(&self.hir, &self.symbols);
        
        // Run type checking
        checker.check()
    }
}
