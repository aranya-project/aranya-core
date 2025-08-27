mod check;
pub(crate) mod types;
mod unify;

use std::{cell::RefCell, collections::BTreeMap};

use self::{
    check::TypeChecker,
    types::{Type, TypeEnv, TypeKind, TypeRef},
    unify::UnifierState,
};
use crate::{
    arena::Arena,
    ctx::Ctx,
    depgraph::{BuildDepGraph, DepsView},
    diag::{ErrorGuaranteed, OptionExt},
    hir::{ExprId, HirView, LowerAst},
    pass::{Pass, View},
    symtab::{SymbolResolution, SymbolsView},
};

#[derive(Copy, Clone, Debug)]
pub struct TypesPass;

impl Pass for TypesPass {
    const NAME: &'static str = "types";
    type Output = Types;
    type View<'cx> = TypesView<'cx>;
    type Deps = (LowerAst, SymbolResolution, BuildDepGraph);

    fn run<'ctx>(
        cx: Ctx<'ctx>,
        (hir, symbols, deps): (HirView<'ctx>, SymbolsView<'ctx>, DepsView<'ctx>),
    ) -> Result<Types, ErrorGuaranteed> {
        let mut checker = TypeChecker {
            ctx: cx,
            hir,
            symbols,
            deps,
            types: Types::new(),
            env: TypeEnv::default(),
            state: RefCell::new(UnifierState::new()),
            local_vars: RefCell::new(BTreeMap::new()),
            max_errs: 10,
            num_errs: 0,
        };

        checker.check()?;

        Ok(checker.types)
    }
}

// Type information from type checking
#[derive(Clone, Debug)]
pub struct Types {
    /// Maps expressions to their types.
    pub exprs: BTreeMap<ExprId, TypeRef>,
    /// Arena of types.
    pub types: Arena<TypeRef, TypeKind>,
}

impl Types {
    fn new() -> Self {
        Self {
            exprs: BTreeMap::new(),
            types: Arena::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TypesView<'cx> {
    cx: Ctx<'cx>,
    types: &'cx Types,
}

impl<'cx> TypesView<'cx> {
    /// Retrieves the type information.
    pub fn types(&self) -> &'cx Types {
        self.types
    }

    /// Gets the type for a specific expr.
    pub fn get_type_ref(&self, id: ExprId) -> TypeRef {
        self.types
            .exprs
            .get(&id)
            .copied()
            .unwrap_or_bug(self.cx.dcx(), "expr must have a type")
    }

    /// Gets the type for a specific expr.
    pub fn get_type(&self, id: ExprId) -> Type<'cx> {
        let xref = self.get_type_ref(id);
        let kind = self.cx.get_type(xref);
        Type { xref, kind }
    }
}

impl<'cx> View<'cx, Types> for TypesView<'cx> {
    fn new(cx: Ctx<'cx>, data: &'cx Types) -> Self {
        Self { cx, types: data }
    }
}
