mod check;
pub(crate) mod types;
//mod unify;

use std::collections::BTreeMap;

use self::{
    check::TypeChecker,
    types::{Type, TypeEnv, TypeRef},
};
use crate::{
    arena::Arena,
    ctx::Ctx,
    depgraph::{DepsPass, DepsView},
    diag::ErrorGuaranteed,
    hir::{AstLowering, ExprId, HirView},
    pass::{Pass, View},
    symtab::{SymbolResolution, SymbolsView},
};

#[derive(Copy, Clone, Debug)]
pub struct TypesPass;

impl Pass for TypesPass {
    const NAME: &'static str = "types";
    type Output = Types;
    type View<'cx> = TypesView<'cx>;
    type Deps = (AstLowering, SymbolResolution, DepsPass);

    fn run<'ctx>(
        cx: Ctx<'ctx>,
        (hir, symbols, deps): (HirView<'ctx>, SymbolsView<'ctx>, DepsView<'ctx>),
    ) -> Result<Types, ErrorGuaranteed> {
        let mut checker = TypeChecker {
            ctx: cx,
            hir,
            symbols,
            deps,
            expr_types: BTreeMap::new(),
            vtype_map: BTreeMap::new(),
            env: TypeEnv::default(),
            next_type_var: 0,
            max_errs: 10,
            num_errs: 0,
        };

        checker.check()?;

        let mut expr_types = BTreeMap::new();
        let mut types_arena = Arena::default();

        for (expr_id, type_ref) in checker.env.exprs {
            if let Some(ty) = checker.env.types.get(type_ref) {
                let type_id = types_arena.insert(ty.clone());
                expr_types.insert(expr_id, type_id);
            }
        }

        Ok(Types {
            exprs: expr_types,
            types: types_arena,
        })
    }
}

// Type information from type checking
#[derive(Clone, Debug)]
pub struct Types {
    /// Maps expressions to their types.
    pub exprs: BTreeMap<ExprId, TypeRef>,
    /// Arena of types.
    pub types: Arena<TypeRef, Type>,
}

pub struct TypesView<'cx> {
    cx: Ctx<'cx>,
    types: &'cx Types,
}

impl<'cx> TypesView<'cx> {
    /// Retrieves the type information.
    pub fn types(&self) -> &'cx Types {
        self.types
    }

    /// Gets the type for a specific expression ID.
    pub fn get_type(&self, expr_id: ExprId) -> Option<TypeRef> {
        self.types.exprs.get(&expr_id).copied()
    }
}

impl<'cx> View<'cx, Types> for TypesView<'cx> {
    fn new(cx: Ctx<'cx>, data: &'cx Types) -> Self {
        Self { cx, types: data }
    }
}
