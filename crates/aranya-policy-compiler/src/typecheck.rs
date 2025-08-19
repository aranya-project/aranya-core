mod check;
pub(crate) mod types;
//mod unify;

use std::collections::BTreeMap;

use self::{
    check::TypeChecker,
    types::{Type, TypeEnv},
};
use crate::{
    arena::Arena,
    ctx::Ctx,
    depgraph::{DepGraph, DepsPass},
    diag::ErrorGuaranteed,
    hir::{ExprId, Hir, HirLowerPass},
    pass::Pass,
    symbol_resolution::{SymbolTable, SymbolsPass},
};

// Type ID for the arena
crate::arena::new_key_type! {
    /// Uniquely identifies a type.
    pub struct TypeId;
}

/// Result type for type checking operations.
pub(crate) type Result<T, E = ErrorGuaranteed> = std::result::Result<T, E>;

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
    pub fn typecheck(&mut self) -> Result<()> {
        let _checker = TypeChecker {
            ctx: self,
            types: Arena::default(),
            expr_types: BTreeMap::new(),
            vtype_map: BTreeMap::new(),
            env: TypeEnv::default(),
            next_type_var: 0,
            has_errors: false,
        };
        // TODO: Port the actual type checking logic
        Ok(())
    }
}

// Type information from type checking
#[derive(Clone, Debug)]
pub struct TypeInfo {
    /// Maps expressions to their types.
    pub expr_types: BTreeMap<ExprId, TypeId>,

    /// Arena of types.
    pub types: Arena<TypeId, Type>,
}

// Pass implementation for type checking
pub struct TypesPass;

impl Pass for TypesPass {
    type Output = TypeInfo;
    type Deps = (HirLowerPass, SymbolsPass, DepsPass);
    const NAME: &'static str = "types";

    fn run<'ctx>(
        _cx: Ctx<'ctx>,
        (_hir, _symbols, _deps): (&Hir, &SymbolTable, &DepGraph),
    ) -> Result<TypeInfo, ErrorGuaranteed> {
        // TODO: Need to get the actual Ctx to run type checking
        // For now, return empty type info
        Ok(TypeInfo {
            expr_types: BTreeMap::new(),
            types: Arena::default(),
        })
    }
}
