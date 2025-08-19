use std::{collections::BTreeMap, ops::ControlFlow};

use super::types::{
    Type, TypeBuiltin, TypeEnv, TypeRef,
};
use super::TypeId;
use crate::{
    arena::Arena,
    ctx::Ctx,
    diag::{ErrorGuaranteed, OptionExt, ResultExt},
    hir::{
        visit::{self, try_visit, Visitor, VisitorResult, Walkable},
        Expr, ExprId, ExprKind, FactLiteral, FunctionCall, Hir, Lit, LitKind, NamedStruct,
        StructFieldExpr, VType, VTypeId, VTypeKind,
    },
    symbol_resolution::{SymbolId, SymbolKind},
};

pub(super) struct TypeChecker<'ctx> {
    pub ctx: &'ctx Ctx<'ctx>,

    /// Arena for storing types
    pub types: Arena<TypeId, Type>,

    /// Maps HIR expressions to their types
    pub expr_types: BTreeMap<ExprId, Type>,

    /// Maps HIR vtypes to our internal types (for caching)
    pub vtype_map: BTreeMap<VTypeId, Type>,

    /// Current type environment
    pub env: TypeEnv,

    /// Next type variable ID for inference
    pub next_type_var: u32,

    /// Tracks whether we've seen errors
    pub has_errors: bool,
}

impl TypeChecker<'_> {
    pub(super) fn check(mut self) -> Result<(), ErrorGuaranteed> {
        // TODO: Port this to use the new pass system
        // Previous compiler passes should've rejected cycles in
        // the dep graph.
        // let sorted = self
        //     .ctx
        //     .deps
        //     .topo_sort()
        //     .unwrap_or_bug(&self.ctx.dcx, "unable to topologically sort deps");

        todo!("TypeChecker not yet ported to new pass system")
    }
}

struct Resolver<'a, 'ctx> {
    ctx: &'ctx Ctx<'ctx>,
    env: &'a mut TypeEnv,
}

impl Resolver<'_, '_> {
    fn resolve_expr(&mut self, expr: &Expr) -> TypeRef {
        match &expr.kind {
            ExprKind::Lit(lit) => self.resolve_lit(lit),
            ExprKind::Intrinsic(_) => todo!(),
            ExprKind::FunctionCall(call) => self.resolve_fn_call(call),
            _ => todo!(),
        }
    }

    fn resolve_vtype(&mut self, vtype: &VType) -> TypeRef {
        let VType {
            id: _,
            span: _,
            kind,
        } = vtype;
        match kind {
            VTypeKind::String => self.env.new_builtin(TypeBuiltin::String),
            VTypeKind::Bytes => self.env.new_builtin(TypeBuiltin::Bytes),
            VTypeKind::Int => self.env.new_builtin(TypeBuiltin::Int),
            VTypeKind::Bool => self.env.new_builtin(TypeBuiltin::Bool),
            VTypeKind::Id => self.env.new_builtin(TypeBuiltin::Id),
            VTypeKind::Struct(_ident) => {
                todo!()
            }
            VTypeKind::Enum(_ident) => {
                todo!()
            }
            VTypeKind::Optional(_ident) => {
                todo!()
            }
        }
    }

    fn resolve_fn_call(&mut self, call: &FunctionCall) -> TypeRef {
        // TODO: Port to new pass system
        // Need to access symbol table and HIR through the pass context
        todo!("Function call type resolution not yet ported to new pass system")
    }

    fn resolve_lit(&mut self, lit: &Lit) -> TypeRef {
        let Lit { kind } = lit;
        match kind {
            LitKind::Int(_) => self.env.new_builtin(TypeBuiltin::Int),
            LitKind::String(_) => self.env.new_builtin(TypeBuiltin::String),
            LitKind::Bool(_) => self.env.new_builtin(TypeBuiltin::Bool),
            LitKind::Optional(expr) => match expr {
                Some(expr) => self.env.exprs[expr],
                None => self.env.new_none(),
            },
            LitKind::NamedStruct(NamedStruct { ident, fields }) => {
                // TODO: Port to new pass system
                // Need to access symbol table through the pass context
                todo!("Named struct type resolution not yet ported to new pass system")
            }
            LitKind::Fact(FactLiteral { ident, keys, vals }) => {
                // TODO: Implement fact literal type resolution
                // For now, just return a placeholder type
                todo!("Fact literal type resolution not yet implemented")
            }
        }
    }
}

impl<'ctx: 'hir, 'hir> Visitor<'hir> for Resolver<'_, 'ctx> {
    type Result = ControlFlow<()>;

    fn hir(&self) -> &'hir Hir {
        // TODO: Port to new pass system
        // Need to access HIR through the pass context
        todo!("HIR access not yet ported to new pass system")
    }

    fn visit_vtype(&mut self, vtype: &'hir VType) -> Self::Result {
        try_visit!(vtype.walk(self));

        self.resolve_vtype(vtype);

        Self::Result::output()
    }

    fn visit_expr(&mut self, expr: &'hir Expr) -> Self::Result {
        try_visit!(expr.walk(self));

        self.resolve_expr(expr);

        Self::Result::output()
    }

    fn visit_expr_kind(&mut self, _kind: &'hir ExprKind) -> Self::Result {
        todo!()
    }
}
