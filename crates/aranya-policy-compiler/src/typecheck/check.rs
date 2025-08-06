use std::collections::BTreeMap;

use crate::{
    arena::Arena,
    hir::{
        types::{Expr, ExprId, ExprKind, LitKind},
        visit::Visitor,
        Hir,
    },
    typecheck::{
        types::{Type, TypeId, TypeKind},
        Result,
    },
};

pub(super) struct TypeChecker<'hir> {
    hir: &'hir Hir,
    exprs: BTreeMap<ExprId, Type>,
    types: Arena<TypeId, Type>,
}

impl TypeChecker<'_> {
    fn check_expr(&mut self, expr: &Expr) -> Result<Type> {
        let kind = match &expr.kind {
            ExprKind::Lit(lit) => match &lit.kind {
                LitKind::String(_) => TypeKind::String,
                LitKind::Int(_) => TypeKind::Int,
                LitKind::Bool(_) => TypeKind::Bool,
                _ => todo!(),
            },
            _ => todo!(),
        };
        Ok(Type {
            id: TypeId::default(), // TODO
            kind,
        })
    }
}

impl<'hir> Visitor<'hir> for TypeChecker<'hir> {
    type Result = Result<()>;

    fn hir(&self) -> &'hir Hir {
        self.hir
    }

    fn visit_expr(&mut self, expr: &'hir Expr) -> Self::Result {
        let _ = self.check_expr(expr); // TODO
        Ok(())
    }

    fn visit_expr_kind(&mut self, _kind: &'hir ExprKind) -> Self::Result {
        Ok(())
    }
}
