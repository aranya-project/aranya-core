use std::{
    borrow::Cow,
    collections::BTreeMap,
    ops::{ControlFlow, Index},
};

use aranya_policy_ast::{self as ast, ident};
use unindent::Unindent as _;

use super::types::{
    EnumVariant, FactField, StructField, Type, TypeEnum, TypeEnv, TypeFact, TypeFunc, TypeOptional,
    TypeRef, TypeStruct,
};
use crate::{
    arena::Arena,
    ctx::Ctx,
    depgraph::DepsView,
    diag::{
        Diag, DiagCtx, Diagnostic, EmissionGuarantee, ErrorGuaranteed, MultiSpan, OptionExt,
        ResultExt, Severity,
    },
    hir::{
        self,
        visit::{try_visit, Visitor, VisitorResult, Walkable},
        ActionCall, BinOp, Body, BodyId, CheckStmt, EnumRef, Expr, ExprId, ExprKind, FactCountType,
        FactFieldExpr, FactKeyId, FactLiteral, FactValId, ForeignFunctionCall, FuncDef,
        FunctionCall, Hir, HirView, IdentId, IdentRef, Intrinsic, LetStmt, Lit, LitKind, MatchExpr,
        MatchExprArm, MatchPattern, NamedStruct, ReturnStmt, Span, Stmt, StmtKind, StructFieldExpr,
        StructFieldId, StructFieldKind, Ternary, UnaryOp, VType, VTypeId, VTypeKind,
    },
    symtab::{SymbolId, SymbolKind, SymbolsView},
};

pub(super) struct TypeChecker<'cx> {
    pub ctx: Ctx<'cx>,

    pub hir: HirView<'cx>,
    pub symbols: SymbolsView<'cx>,
    pub deps: DepsView<'cx>,

    /// Maps HIR expressions to their types
    pub expr_types: BTreeMap<ExprId, TypeRef>,

    /// Maps HIR vtypes to our internal types (for caching)
    pub vtype_map: BTreeMap<VTypeId, Type>,

    /// Current type environment
    pub env: TypeEnv,

    /// Next type variable ID for inference
    pub next_type_var: u32,

    /// Maximum number of errors before stopping
    pub max_errs: usize,
    /// Number of errors emitted so far
    pub num_errs: usize,
}

impl<'cx> TypeChecker<'cx> {
    pub(super) fn check(&mut self) -> Result<(), ErrorGuaranteed> {
        let sorted = self.deps.topo_sorted();
        for &id in sorted {
            if let Err(err) = self.check_symbol(id) {
                self.num_errs += 1;
                if self.num_errs > self.max_errs {
                    return Err(err);
                }
            }
        }
        match self.dcx().has_errors() {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn dcx(&self) -> &'cx DiagCtx {
        self.ctx.dcx()
    }

    fn get_type_string(&self, ty: &'cx Type) -> Cow<'static, str> {
        match ty {
            Type::String => Cow::Borrowed("string"),
            Type::Int => Cow::Borrowed("int"),
            Type::Bool => Cow::Borrowed("bool"),
            Type::Bytes => Cow::Borrowed("bytes"),
            Type::Id => Cow::Borrowed("id"),
            Type::Struct(TypeStruct { symbol, .. }) => {
                Cow::Owned(format!("struct {}", self.get_sym_ident(*symbol)))
            }
            Type::Enum(TypeEnum { symbol, .. }) => {
                Cow::Owned(format!("enum {}", self.get_sym_ident(*symbol)))
            }
            Type::Function(TypeFunc { symbol, .. }) => {
                // TODO
                Cow::Owned(format!("func {}", self.get_sym_ident(*symbol)))
            }
            Type::Fact(TypeFact { symbol, .. }) => {
                // TODO
                Cow::Owned(format!("fact {}", self.get_sym_ident(*symbol)))
            }
            Type::Optional(TypeOptional { inner: ty }) => match ty {
                Some(xref) => Cow::Owned(format!("optional {}", self.get_type_ref_string(*xref))),
                None => Cow::Borrowed("None"),
            },
            Type::Unit => Cow::Borrowed("unit"),
            Type::Error => Cow::Borrowed("error"),
        }
    }

    fn get_type_ref_string(&self, id: TypeRef) -> Cow<'static, str> {
        self.get_type_string(self.ctx.get_type(id))
    }

    fn get_sym_ident(&self, id: SymbolId) -> ast::Identifier {
        let sym = self.symbols.get(id);
        let ident = self.hir.lookup(sym.ident);
        self.ctx.get_ident(ident.xref)
    }

    fn get_sym_type(&self, ident: IdentId) -> &'cx Type {
        let sym_id = self.symbols.resolve(ident);
        let ty_ref = self
            .env
            .symbols
            .get(&sym_id)
            .unwrap_or_bug(self.dcx(), "type not found");
        self.ctx.get_type(*ty_ref)
    }

    fn check_symbol(&mut self, sym_id: SymbolId) -> Result<(), ErrorGuaranteed> {
        let sym = self.symbols.get(sym_id);
        match sym.kind {
            SymbolKind::Func(_) => {}
            SymbolKind::Action(_) => {}
            SymbolKind::GlobalVar(_) => {}
            SymbolKind::Struct(_) => {}
            SymbolKind::Enum(_) => {}
            SymbolKind::Fact(_) => {}
            SymbolKind::FinishFunc(_) => {}

            // These symbol kinds don't define types.
            SymbolKind::Cmd(_) => {}
            SymbolKind::Effect(_) => {}
            SymbolKind::FfiEnum(_) => {}
            SymbolKind::FfiFunc(_) => {}
            SymbolKind::FfiImport(_) => {}
            SymbolKind::FfiModule(_) => {}
            SymbolKind::FfiStruct(_) => {}
            SymbolKind::LocalVar(_) => {}
        }
        Ok(())
    }

    /// Attempts to find a struct field.
    ///
    /// It emits an error and returns `None` if the field is not
    /// found.
    fn find_struct_field(&self, ty: &'cx TypeStruct, field: IdentId) -> Option<&'cx StructField> {
        let xref = self.hir.lookup_ident_ref(field);
        if let Some(field) = ty.fields.iter().find(|f| f.xref == xref) {
            return Some(field);
        }
        let st_name = {
            let sym = self.symbols.get(ty.symbol);
            self.hir.lookup_ident(sym.ident)
        };
        let field_name = self.ctx.get_ident(xref);
        let span = MultiSpan::from_span(
            self.hir.lookup_span(field),
            format!("struct `{st_name}` does not have field `{field_name}`"),
        );
        self.dcx().emit_span_err(span, "unknown field");
        None
    }

    fn check_expr(&self, expr: ExprId) -> TypeRef {
        let Expr {
            id: _,
            span: _,
            kind,
            pure: _,
            returns: _,
        } = self.hir.lookup(expr);
        match kind {
            ExprKind::Lit(lit) => self.check_lit(lit),
            ExprKind::Intrinsic(v) => self.check_intrinsic(v),
            ExprKind::FunctionCall(_) => {
                todo!()
            }
            ExprKind::ForeignFunctionCall(_) => {
                todo!()
            }
            ExprKind::Identifier(ident) => self.check_identifier(*ident),
            ExprKind::EnumRef(v) => self.check_enum_ref(v),
            ExprKind::Binary(op, left, right) => self.check_bin_op(*op, *left, *right),
            ExprKind::Unary(op, operand) => self.check_unary_op(*op, *operand),
            ExprKind::Dot(expr, ident) => self.check_dot(*expr, *ident),
            ExprKind::Is(expr, is_some) => self.check_is(*expr, *is_some),
            ExprKind::Block(..) => {
                todo!()
            }
            ExprKind::Substruct(base, target) => self.check_substruct(*base, *target),
            ExprKind::Match(match_expr) => self.check_match(match_expr),
            ExprKind::Ternary(ternary) => self.check_ternary(ternary),
        }
    }

    /// Checks that `expr` has the expected type and returns the
    /// resulting type.
    ///
    /// `reason` is the reason why `expr` must have a particular
    /// type.
    fn check_expr_is_ty(&self, expr: ExprId, expect: TypeRef, reason: Option<Span>) -> TypeRef {
        let found = self.check_expr(expr);
        if found != expect {
            self.dcx().emit_err_diag(TypeMismatch {
                span: self.hir.lookup_span(expr),
                expected: self.get_type_ref_string(expect),
                found: self.get_type_ref_string(found),
                reason,
            });
            self.ctx.builtins.error
        } else {
            expect
        }
    }

    fn check_lit(&self, lit: &'cx Lit) -> TypeRef {
        let Lit { kind } = lit;
        match kind {
            LitKind::Int(_) => self.ctx.builtins.int,
            LitKind::String(_) => self.ctx.builtins.string,
            LitKind::Bool(_) => self.ctx.builtins.bool,
            LitKind::Optional(expr) => match expr {
                Some(expr) => {
                    let inner = self.check_expr(*expr);
                    self.ctx
                        .intern_type(Type::Optional(TypeOptional { inner: Some(inner) }))
                }
                None => self.ctx.builtins.none,
            },
            LitKind::NamedStruct(v) => self.check_lit_named_struct(v),
            LitKind::Fact(v) => self.check_lit_fact(v),
        }
    }

    fn check_lit_named_struct(&self, st: &'cx NamedStruct) -> TypeRef {
        let NamedStruct { ident, fields } = st;

        let sym_id = self.symbols.resolve(*ident);
        let ty_ref = self
            .env
            .symbols
            .get(&sym_id)
            .unwrap_or_bug(self.dcx(), "type not found");

        let Type::Struct(st) = self.ctx.get_type(*ty_ref) else {
            let name = self.get_sym_ident(sym_id);
            let span = MultiSpan::from_span(self.hir.lookup_span(*ident), "expected struct");
            self.dcx()
                .emit_span_err(span, format!("`{name}` is not a struct"));
            return self.ctx.builtins.error;
        };

        for &StructFieldExpr { ident, expr } in fields {
            let expect = match self.find_struct_field(st, ident) {
                Some(field) => field.ty,
                None => return self.ctx.builtins.error,
            };
            self.check_expr_is_ty(expr, expect, Some(self.hir.lookup_span(ident)));
        }

        *ty_ref
    }

    fn check_lit_fact(&self, fact: &'cx FactLiteral) -> TypeRef {
        let FactLiteral { ident, keys, vals } = fact;

        let sym_id = self.symbols.resolve(*ident);
        let ty_ref = self
            .env
            .symbols
            .get(&sym_id)
            .unwrap_or_bug(self.dcx(), "type not found");

        let Type::Fact(fact) = self.ctx.get_type(*ty_ref) else {
            let name = self.get_sym_ident(sym_id);
            let span = MultiSpan::from_span(self.hir.lookup_span(*ident), "expected fact");
            self.dcx()
                .emit_span_err(span, format!("`{name}` is not a fact"));
            return self.ctx.builtins.error;
        };

        for &FactFieldExpr { ident, expr } in keys {
            let ty = match self.find_fact_key(fact, ident) {
                Some(field) => field.ty,
                None => return self.ctx.builtins.error,
            };
            match expr {
                hir::FactField::Expr(expr) => {
                    self.check_expr_is_ty(expr, ty, Some(self.hir.lookup_span(ident)));
                }
                hir::FactField::Bind => {}
            }
        }

        for &FactFieldExpr { ident, expr } in vals {
            let ty = match self.find_fact_val(fact, ident) {
                Some(field) => field.ty,
                None => return self.ctx.builtins.error,
            };
            match expr {
                hir::FactField::Expr(expr) => {
                    self.check_expr_is_ty(expr, ty, Some(self.hir.lookup_span(ident)));
                }
                hir::FactField::Bind => {}
            }
        }

        *ty_ref
    }

    /// Attempts to find a fact key.
    ///
    /// It emits an error and returns `None` if the field is not
    /// found.
    fn find_fact_key(&self, ty: &'cx TypeFact, field: IdentId) -> Option<&'cx FactField> {
        let xref = self.hir.lookup_ident_ref(field);
        if let Some(field) = ty.keys.iter().find(|f| f.xref == xref) {
            return Some(field);
        }
        let fact_name = {
            let sym = self.symbols.get(ty.symbol);
            let xref = self.hir.lookup(sym.ident).xref;
            self.ctx.get_ident(xref)
        };
        let field_name = self.ctx.get_ident(xref);
        let span = MultiSpan::from_span(
            self.hir.lookup_span(field),
            format!("fact `{fact_name}` does not have key `{field_name}`"),
        );
        self.dcx().emit_span_err(span, "unknown field");
        None
    }

    /// Attempts to find a fact value.
    ///
    /// It emits an error and returns `None` if the field is not
    /// found.
    fn find_fact_val(&self, fact: &'cx TypeFact, field: IdentId) -> Option<&'cx FactField> {
        let xref = self.hir.lookup_ident_ref(field);
        if let Some(field) = fact.vals.iter().find(|f| f.xref == xref) {
            return Some(field);
        }
        let fact_name = {
            let sym = self.symbols.get(fact.symbol);
            let xref = self.hir.lookup(sym.ident).xref;
            self.ctx.get_ident(xref)
        };
        let field_name = self.ctx.get_ident(xref);
        let span = MultiSpan::from_span(
            self.hir.lookup_span(field),
            format!("fact `{fact_name}` does not have value `{field_name}`"),
        );
        self.dcx().emit_span_err(span, "unknown field");
        None
    }

    fn check_enum_ref(&self, xref: &'cx EnumRef) -> TypeRef {
        let EnumRef { ident, value } = xref;

        let sym_id = self.symbols.resolve(*ident);
        let ty_ref = self
            .env
            .symbols
            .get(&sym_id)
            .unwrap_or_bug(self.dcx(), "type not found");

        let Type::Enum(ty) = self.ctx.get_type(*ty_ref) else {
            let name = {
                let ident = self.hir.lookup(*ident);
                self.ctx.get_ident(ident.xref)
            };
            let mut span = MultiSpan::from_span(self.hir.lookup_span(*ident), "expected enum");
            span.push_label(
                self.hir.lookup_span(*value),
                "this is a reference to an enum variant",
            );
            span.push_label(
                self.symbols.get(sym_id).span,
                format!("`{name}` is defined here"),
            );
            self.dcx()
                .emit_span_err(span, format!("`{name}` is not an enum"));
            return self.ctx.builtins.error;
        };

        let xref = self.hir.lookup_ident_ref(*value);
        if !ty.variants.iter().any(|v| v.xref == xref) {
            let enum_name = {
                let sym = self.symbols.get(ty.symbol);
                self.hir.lookup_ident(sym.ident)
            };
            let variant_name = self.ctx.get_ident(xref);
            let span = MultiSpan::from_span(
                self.hir.lookup_span(*value),
                format!("enum `{enum_name}` does not have variant `{variant_name}`"),
            );
            self.dcx().emit_span_err(span, "unknown variant");
            return self.ctx.builtins.error;
        }

        *ty_ref
    }

    fn check_bin_op(&self, op: BinOp, left: ExprId, right: ExprId) -> TypeRef {
        let expect = match op {
            BinOp::Add | BinOp::Sub | BinOp::Gt | BinOp::Lt | BinOp::GtEq | BinOp::LtEq => {
                self.check_expr_is_ty(left, self.ctx.builtins.int, None)
            }
            BinOp::And | BinOp::Or => self.check_expr_is_ty(left, self.ctx.builtins.bool, None),
            BinOp::Eq | BinOp::Neq => self.check_expr(right),
        };
        self.check_expr_is_ty(right, expect, Some(self.hir.lookup_span(left)))
    }

    fn check_unary_op(&self, op: UnaryOp, expr: ExprId) -> TypeRef {
        match op {
            UnaryOp::Not => self.check_expr_is_ty(expr, self.ctx.builtins.bool, None),
            UnaryOp::Neg => self.check_expr_is_ty(expr, self.ctx.builtins.int, None),
            UnaryOp::Check => self.check_expr_is_ty(expr, self.ctx.builtins.bool, None),
            UnaryOp::CheckUnwrap | UnaryOp::Unwrap => {
                let expr_ty = self.check_expr(expr);
                match self.ctx.get_type(expr_ty) {
                    Type::Optional(TypeOptional { inner: Some(id) }) => *id,
                    // Cannot unwrap a `None`.
                    Type::Optional(TypeOptional { inner: None }) => {
                        let span = MultiSpan::from_span(
                            self.hir.lookup(expr).span,
                            "cannot unwrap `None`",
                        );
                        self.dcx().emit_span_err(span, "type mismatch");
                        self.ctx.builtins.error
                    }
                    // Cannot unwrap a non-optional type.
                    found => {
                        self.dcx().emit_err_diag(TypeMismatch {
                            span: self.hir.lookup(expr).span,
                            expected: "optional".into(),
                            found: self.get_type_string(found),
                            reason: None,
                        });
                        self.ctx.builtins.error
                    }
                }
            }
        }
    }

    fn check_dot(&self, expr: ExprId, ident: IdentId) -> TypeRef {
        let expr_span = self.hir.lookup_span(expr);
        let expr_ty = self.check_expr(expr);

        let st = match self.ctx.get_type(expr_ty) {
            ty @ (Type::String | Type::Bytes | Type::Int | Type::Bool | Type::Id) => {
                let span = MultiSpan::from_span(expr_span, "");
                self.dcx().emit_span_err(
                    span,
                    format!(
                        "`{}` is a primitive type and does not have fields",
                        self.get_type_string(ty)
                    ),
                );
                return self.ctx.builtins.error;
            }
            Type::Optional(TypeOptional { inner }) => {
                let span = MultiSpan::from_span(expr_span, "optional types do not have fields");
                let mut err = self.dcx().create_err("type mismatch").with_span(span);
                if let Some(Type::Struct(_)) = inner.map(|id| self.ctx.get_type(id)) {
                    err = err.with_note("try unwrapping the optional first");
                }
                err.emit();
                return self.ctx.builtins.error;
            }
            Type::Struct(st) => st,
            Type::Enum(TypeEnum { symbol, .. }) => {
                let name = {
                    let sym = self.symbols.get(*symbol);
                    let xref = self.hir.lookup(sym.ident).xref;
                    self.ctx.get_ident(xref)
                };
                let span = MultiSpan::from_span(expr_span, "");
                self.dcx().emit_span_err(
                    span,
                    format!("`{name}` is an enum and does not have fields"),
                );
                return self.ctx.builtins.error;
            }
            Type::Function(_) => self
                .dcx()
                .emit_bug("expression should not resolve to a function type"),
            Type::Fact(_) => self
                .dcx()
                .emit_bug("expression should not resolve to a fact type"),
            Type::Unit => self
                .dcx()
                .emit_bug("expression should not resolve to a unit type"),
            Type::Error => return self.ctx.builtins.error,
        };

        match self.find_struct_field(st, ident) {
            Some(field) => field.ty,
            None => self.ctx.builtins.error,
        }
    }

    fn check_ternary(&self, ternary: &'cx Ternary) -> TypeRef {
        let Ternary {
            cond,
            true_expr,
            false_expr,
        } = ternary;

        self.check_expr_is_ty(*cond, self.ctx.builtins.bool, None);

        let true_type = self.check_expr(*true_expr);
        let false_type = self.check_expr(*false_expr);

        if true_type != false_type {
            self.dcx().emit_err_diag(TernaryBranchTypeMismatch {
                span: self.hir.lookup_span(*false_expr),
                expected: self.get_type_ref_string(true_type),
                found: self.get_type_ref_string(false_type),
                reason: Some(self.hir.lookup_span(*true_expr)),
            });
            return self.ctx.builtins.error;
        }
        true_type
    }

    fn check_substruct(&self, expr: ExprId, ident: IdentId) -> TypeRef {
        let base_type = self.check_expr(expr);
        let Type::Struct(base_st) = self.ctx.get_type(base_type) else {
            let span = MultiSpan::from_span(
                self.hir.lookup_span(expr),
                format!(
                    "expected struct, found `{}`",
                    self.get_type_ref_string(base_type)
                ),
            );
            self.dcx()
                .emit_span_err(span, "cannot apply substruct to non-struct type");
            return self.ctx.builtins.error;
        };

        let sym_id = self.symbols.resolve(ident);
        let ty_ref = self
            .env
            .symbols
            .get(&sym_id)
            .unwrap_or_bug(self.dcx(), "type not found");

        let Type::Struct(target_st) = self.ctx.get_type(*ty_ref) else {
            let name = self.get_sym_ident(sym_id);
            let span = MultiSpan::from_span(self.hir.lookup_span(ident), "expected struct");
            self.dcx()
                .emit_span_err(span, format!("`{name}` is not a struct"));
            return self.ctx.builtins.error;
        };

        if !self.check_is_substruct_of(target_st, base_st, self.hir.lookup_span(ident)) {
            self.ctx.builtins.error
        } else {
            *ty_ref
        }
    }

    /// Is `target` a substruct of `base`?
    ///
    /// Emits errors for each non-substruct field.
    fn check_is_substruct_of(
        &self,
        target: &TypeStruct,
        base: &TypeStruct,
        target_span: Span,
    ) -> bool {
        let mut span = MultiSpan::new();

        for target_field in &target.fields {
            match base.fields.iter().find(|f| f.ident == target_field.ident) {
                Some(base_field) => {
                    if target_field.ty == base_field.ty {
                        continue;
                    }
                    let msg = {
                        let field_name = self.hir.lookup_ident(target_field.ident);
                        let target_name = self.get_sym_ident(target.symbol);
                        let target_type = self.get_type_ref_string(target_field.ty);
                        let base_type = self.get_type_ref_string(base_field.ty);
                        let base_name = self.get_sym_ident(base.symbol);
                        format!(
                            "field `{field_name}` has type `{target_type}` in `{target_name}`, \
                             but `{base_type}` in `{base_name}`"
                        )
                    };
                    span.push_label(self.hir.lookup_span(target_field.ident), msg);
                }
                None => {
                    let field_name = self.ctx.get_ident(self.hir.lookup(target_field.ident).xref);
                    let base_name = self.get_sym_ident(base.symbol);
                    span.push_label(
                        self.hir.lookup_span(target_field.ident),
                        format!("field `{field_name}` not found in `{base_name}`",),
                    );
                }
            }
        }

        if !span.is_empty() {
            span.push_primary(target_span, "not a subset");
            let target_name = self.get_sym_ident(target.symbol);
            let base_name = self.get_sym_ident(base.symbol);
            self.dcx().emit_span_err(
                span,
                format!("struct `{target_name}` is not a subset of struct `{base_name}`"),
            );
            return false;
        }

        true
    }

    fn check_is(&self, expr: ExprId, _is_some: bool) -> TypeRef {
        let ty = self.check_expr(expr);
        let Type::Optional(_) = self.ctx.get_type(ty) else {
            let span = MultiSpan::from_span(
                self.hir.lookup_span(expr),
                format!(
                    "expected optional type, found `{}`",
                    self.get_type_ref_string(ty)
                ),
            );
            self.dcx()
                .emit_span_err(span, "`is` expects an `optional` expression");
            return self.ctx.builtins.error;
        };
        self.ctx.builtins.bool
    }

    fn check_identifier(&self, ident: IdentId) -> TypeRef {
        let sym_id = self.symbols.resolve(ident);
        *self
            .env
            .symbols
            .get(&sym_id)
            .unwrap_or_bug(self.dcx(), "type not found")
    }

    fn check_intrinsic(&self, intrinsic: &'cx Intrinsic) -> TypeRef {
        match intrinsic {
            Intrinsic::Query(fact) => {
                let fact_type = self.check_lit_fact(fact);
                self.ctx.intern_type(Type::Optional(TypeOptional {
                    inner: Some(fact_type),
                }))
            }
            Intrinsic::FactCount(count_type, _limit, fact) => {
                self.check_lit_fact(fact);

                match count_type {
                    FactCountType::UpTo => self.ctx.builtins.int,
                    FactCountType::AtLeast | FactCountType::AtMost | FactCountType::Exactly => {
                        self.ctx.builtins.bool
                    }
                }
            }
            Intrinsic::Serialize(expr) => {
                self.check_expr(*expr);
                self.ctx.builtins.bytes
            }
            Intrinsic::Deserialize(expr) => {
                let expr_type = self.check_expr(*expr);
                // Check that expression is bytes type
                if expr_type != self.ctx.builtins.bytes {
                    self.dcx().emit_err_diag(TypeMismatch {
                        span: self.hir.lookup_span(*expr),
                        expected: self.get_type_ref_string(self.ctx.builtins.bytes),
                        found: self.get_type_ref_string(expr_type),
                        reason: None,
                    });
                    return self.ctx.builtins.error;
                }
                // For now, return error type since we don't have context for target struct
                // This will be improved when we have better context handling
                self.ctx.builtins.error
            }
        }
    }

    fn check_match(&self, expr: &'cx MatchExpr) -> TypeRef {
        let MatchExpr { scrutinee, arms } = expr;

        let scrutinee = self.check_expr(*scrutinee);

        // Use the first arm as the expected type for all arms.
        let expr_ty = self.check_expr(arms[0].expr);
        for arm in arms {
            self.check_match_pattern(&arm.pattern, scrutinee);

            let arm_type = self.check_expr(arm.expr);
            if arm_type != expr_ty {
                self.dcx().emit_err_diag(MatchArmTypeMismatch {
                    span: self.hir.lookup_span(arm.expr),
                    expected: self.get_type_ref_string(expr_ty),
                    found: self.get_type_ref_string(arm_type),
                    reason: Some(self.hir.lookup_span(arms[0].expr)),
                });
                return self.ctx.builtins.error;
            }
        }
        expr_ty
    }

    /// Checks that each expr in the pattern is a literal with
    /// the same type as `ty`.
    fn check_match_pattern(&self, pat: &'cx MatchPattern, ty: TypeRef) {
        match pat {
            MatchPattern::Default => {}
            MatchPattern::Values(exprs) => {
                for &expr in exprs {
                    let value_type = self.check_expr(expr);
                    if value_type != ty {
                        self.dcx().emit_err_diag(TypeMismatch {
                            span: self.hir.lookup_span(expr),
                            expected: self.get_type_ref_string(ty),
                            found: self.get_type_ref_string(value_type),
                            reason: None,
                        });
                    }
                    let expr = self.hir.lookup(expr);
                    if !matches!(expr.kind, ExprKind::Lit(_)) {
                        let span = MultiSpan::from_span(expr.span, "not a literal");
                        self.dcx()
                            .emit_span_err(span, "match patterns must be literals");
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("`if` and `else` have incompatible types")]
struct TernaryBranchTypeMismatch {
    span: Span,
    expected: Cow<'static, str>,
    found: Cow<'static, str>,
    reason: Option<Span>,
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for TernaryBranchTypeMismatch {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let mut span = MultiSpan::from_span(
            self.span,
            format!("expected `{}`, found `{}`", self.expected, self.found),
        );
        if let Some(reason) = self.reason {
            span.push_label(reason, format!("because this is `{}`", self.expected));
        }
        Diag::new(ctx, severity, "`if` and `else` have incompatible types").with_span(span)
    }
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("`match` arms have incompatible types")]
struct MatchArmTypeMismatch {
    span: Span,
    expected: Cow<'static, str>,
    found: Cow<'static, str>,
    reason: Option<Span>,
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for MatchArmTypeMismatch {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let mut span = MultiSpan::from_span(
            self.span,
            format!("expected `{}`, found `{}`", self.expected, self.found),
        );
        if let Some(reason) = self.reason {
            span.push_label(reason, format!("because this is `{}`", self.expected));
        }
        Diag::new(ctx, severity, "`match` arms have incompatible types").with_span(span)
    }
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("mismatched types")]
struct TypeMismatch {
    span: Span,
    expected: Cow<'static, str>,
    found: Cow<'static, str>,
    reason: Option<Span>,
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for TypeMismatch {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let mut span = MultiSpan::from_span(
            self.span,
            format!("expected `{}`, found `{}`", self.expected, self.found),
        );
        if let Some(reason) = self.reason {
            span.push_label(reason, format!("because this is `{}`", self.expected));
        }
        Diag::new(ctx, severity, "mismatched types").with_span(span)
    }
}
