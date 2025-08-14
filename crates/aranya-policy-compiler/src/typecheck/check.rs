use std::collections::BTreeMap;

use crate::{
    arena::Arena,
    ctx::Ctx,
    hir::{ExprId, Hir, VTypeId},
    symbol_resolution::SymbolTable,
    typecheck::types::{Type, TypeEnv, TypeId},
};

pub(crate) struct TypeChecker<'ctx> {
    ctx: &'ctx Ctx<'ctx>,
    hir: &'ctx Hir,
    symbols: &'ctx SymbolTable,

    /// Arena for storing types
    types: Arena<TypeId, Type>,

    /// Maps HIR expressions to their types
    expr_types: BTreeMap<ExprId, Type>,

    /// Maps HIR vtypes to our internal types (for caching)
    vtype_map: BTreeMap<VTypeId, Type>,

    /// Current type environment
    env: TypeEnv,

    /// Next type variable ID for inference
    next_type_var: u32,

    /// Tracks whether we've seen errors
    has_errors: bool,
}
