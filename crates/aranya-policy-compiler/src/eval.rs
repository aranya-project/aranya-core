//! Const eval.

use std::collections::BTreeMap;

use indexmap::IndexSet;

use crate::{
    ctx::Ctx,
    diag::ErrorGuaranteed,
    hir::{
        BinOp, Block, BlockId, Body, EnumRef, Expr, ExprId, ExprKind, FuncDef, FunctionCall, Hir,
        HirView, IdentId, IdentRef, Intrinsic, LetStmt, Lit, LitKind, LowerAst, MatchExpr,
        MatchPattern, NamedStruct, Stmt, StmtKind, Ternary, TextRef, UnaryOp,
        visit::{Visitor, Walkable},
    },
    intern::typed_interner,
    pass::{Pass, View},
    symtab::{ItemKind, SymbolId, SymbolKind, SymbolResolution, SymbolsView},
    typecheck::{
        TypesPass, TypesView,
        types::{Type, TypeKind, TypeRef},
    },
};

// TODO: rename to ValueInterner
typed_interner! {
    pub(crate) struct ConstInterner(Value) => ValueRef;
}

#[derive(Copy, Clone, Debug)]
pub struct ConstEval;

impl Pass for ConstEval {
    const NAME: &'static str = "const eval";
    type Output = Consts;
    type View<'cx> = ConstEvalView<'cx>;
    type Deps = (LowerAst, SymbolResolution, TypesPass);

    fn run<'cx>(
        cx: Ctx<'cx>,
        (hir, symbols, types): (HirView<'cx>, SymbolsView<'cx>, TypesView<'cx>),
    ) -> Result<Self::Output, ErrorGuaranteed> {
        let mut ev = Evaluator {
            cx,
            hir,
            symbols,
            types,
            consts: Consts::default(),
        };
        ev.visit_all();
        Ok(ev.consts)
    }
}

#[derive(Clone, Debug)]
struct Evaluator<'cx> {
    cx: Ctx<'cx>,
    hir: HirView<'cx>,
    symbols: SymbolsView<'cx>,
    types: TypesView<'cx>,
    consts: Consts,
}

impl<'cx> Evaluator<'cx> {
    fn get(&self, id: ExprId) -> EvalResult {
        match self.consts.exprs.get(&id) {
            Some(Ok(xref)) => Ok(*xref),
            Some(Err(Error::IntOverflow)) => Err(EvalError::IntOverflow),
            None => Err(EvalError::NotConst),
        }
    }

    fn get_val(&self, id: ExprId) -> Result<&'cx Value, EvalError> {
        let xref = self.get(id)?.to_value();
        Ok(self.cx.get_const(xref))
    }

    fn set(&mut self, id: ExprId, res: EvalResult) {
        match res {
            Ok(v) => {
                self.consts.exprs.insert(id, Ok(v));
            }
            Err(EvalError::IntOverflow) => {
                self.consts.exprs.insert(id, Err(Error::IntOverflow));
            }
            Err(EvalError::NotConst) => {}
        }
    }

    fn fold_lit(&self, lit: &Lit, id: ExprId) -> EvalResult {
        let val = match &lit.kind {
            LitKind::Int(v) => Value::Int(*v),
            LitKind::Bool(v) => Value::Bool(*v),
            LitKind::String(v) => Value::String(*v),
            LitKind::Optional(v) => match v {
                Some(id) => Value::Optional(Some(self.get(*id)?)),
                None => Value::Optional(None),
            },
            LitKind::NamedStruct(ns) => self.fold_named_struct_lit(ns, id)?,
            _ => return Err(EvalError::NotConst),
        };
        Ok(Const::Lit(self.cx.intern_const(val)))
    }

    fn fold_enum_ref(&self, expr: &EnumRef, id: ExprId) -> EvalResult {
        let Type { xref, kind } = self.types.get_type(id);
        let TypeKind::Enum(_) = kind else {
            self.cx.dcx().emit_span_bug(
                (self.hir.lookup_span(id), "expression"),
                "EnumRef type is not an enum",
            );
        };

        let variant_xref = self.hir.lookup_ident_ref(expr.value);
        let val = Value::Enum(EnumValue {
            ty: xref,
            variant: variant_xref,
        });
        Ok(Const::Lit(self.cx.intern_const(val)))
    }

    fn fold_named_struct_lit(&self, ns: &NamedStruct, id: ExprId) -> Result<Value, EvalError> {
        let Type { xref, kind } = self.types.get_type(id);
        let TypeKind::Struct(st) = kind else {
            self.cx.dcx().emit_span_bug(
                (self.hir.lookup_span(id), "struct literal"),
                "NamedStruct type is not a struct",
            );
        };
        if ns.fields.len() != st.fields.len() {
            self.cx.dcx().emit_span_bug(
                (self.hir.lookup_span(id), "struct literal"),
                "struct literal has wrong number of fields",
            );
        }
        let mut fields: BTreeMap<IdentRef, ValueRef> = BTreeMap::new();
        for fe in &ns.fields {
            let xref_field = self.hir.lookup_ident_ref(fe.ident);
            let cref = self.get(fe.expr)?.to_value();
            if fields.insert(xref_field, cref).is_some() {
                self.cx.dcx().emit_span_bug(
                    (self.hir.lookup_span(id), "struct literal"),
                    "duplicate struct field in literal",
                );
            }
        }
        for declared in &st.fields {
            if !fields.contains_key(&declared.xref) {
                self.cx.dcx().emit_span_bug(
                    (self.hir.lookup_span(id), "struct literal"),
                    "missing struct field in literal",
                );
            }
        }
        Ok(Value::Struct(StructValue { ty: xref, fields }))
    }

    fn fold_unary(&self, op: UnaryOp, id: ExprId) -> EvalResult {
        use Value::*;

        match op {
            UnaryOp::CheckUnwrap | UnaryOp::Unwrap => match self.get_val(id)? {
                Optional(Some(inner)) => return Ok(inner.to_expr()),
                Optional(None) => {
                    let x = self.cx.intern_const(Never);
                    return Ok(Const::Lit(x));
                }
                _ => return Err(EvalError::NotConst),
            },
            _ => {}
        }

        let val = match (op, self.get_val(id)?) {
            (UnaryOp::Neg, Int(v)) => v.checked_neg().map(Int).ok_or(EvalError::IntOverflow)?,
            (UnaryOp::Not, Bool(v)) => Bool(!v),
            (UnaryOp::Check, Bool(v)) => {
                if *v {
                    Unit
                } else {
                    Never
                }
            }
            _ => return Err(EvalError::NotConst),
        };
        Ok(Const::Expr(self.cx.intern_const(val)))
    }

    fn fold_binary(&self, op: BinOp, lhs: ExprId, rhs: ExprId) -> EvalResult {
        use BinOp::*;
        use Value::*;

        let lhs = self.get_val(lhs)?;
        let rhs = self.get_val(rhs)?;
        let val = match (op, lhs, rhs) {
            // Integers
            (Add, Int(a), Int(b)) => a.checked_add(*b).map(Int).ok_or(EvalError::IntOverflow)?,
            (Sub, Int(a), Int(b)) => a.checked_sub(*b).map(Int).ok_or(EvalError::IntOverflow)?,

            (Eq, Int(a), Int(b)) => Bool(a == b),
            (Neq, Int(a), Int(b)) => Bool(a != b),
            (Gt, Int(a), Int(b)) => Bool(a > b),
            (Lt, Int(a), Int(b)) => Bool(a < b),
            (GtEq, Int(a), Int(b)) => Bool(a >= b),
            (LtEq, Int(a), Int(b)) => Bool(a <= b),

            // Booleans
            (And, Bool(a), Bool(b)) => Bool(*a && *b),
            (Or, Bool(a), Bool(b)) => Bool(*a || *b),
            (Eq, Bool(a), Bool(b)) => Bool(a == b),
            (Neq, Bool(a), Bool(b)) => Bool(a != b),

            // Strings
            (Eq, String(a), String(b)) => Bool(a == b),
            (Neq, String(a), String(b)) => Bool(a != b),

            // Enums: only equality/inequality
            (Eq, Enum(lhs), Enum(rhs)) => Bool(lhs == rhs),
            (Neq, Enum(lhs), Enum(rhs)) => Bool(lhs != rhs),

            // Structs: only equality/inequality
            (Eq, Struct(a), Struct(b)) => Bool(a == b),
            (Neq, Struct(a), Struct(b)) => Bool(a != b),

            // Optionals: only equality/inequality
            (Eq, Optional(a), Optional(b)) => Bool(a == b),
            (Neq, Optional(a), Optional(b)) => Bool(a != b),

            _ => return Err(EvalError::NotConst),
        };
        Ok(Const::Expr(self.cx.intern_const(val)))
    }

    fn fold_ternary(&self, expr: &Ternary) -> EvalResult {
        let &Ternary {
            cond,
            true_expr,
            false_expr,
        } = expr;
        let cons = match self.get_val(cond)? {
            Value::Bool(true) => self.get(true_expr)?,
            Value::Bool(false) => self.get(false_expr)?,
            _ => return Err(EvalError::NotConst),
        };
        Ok(cons.to_expr())
    }

    fn fold_is(&self, expr: ExprId, is_some: bool) -> EvalResult {
        match self.get_val(expr)? {
            Value::Optional(v) => {
                let val = Value::Bool(v.is_some() == is_some);
                let xref = self.cx.intern_const(val);
                Ok(Const::Lit(xref))
            }
            _ => Err(EvalError::NotConst),
        }
    }

    fn fold_match(&self, expr: &MatchExpr) -> EvalResult {
        let scrut = self.get(expr.scrutinee)?;

        let mut seen_default = false;
        let mut seen: IndexSet<ValueRef> = IndexSet::new();
        let mut is_const = !expr.arms.is_empty();
        let mut chosen: Option<ExprId> = None;

        for arm in &expr.arms {
            match &arm.pattern {
                MatchPattern::Default => {
                    if seen_default {
                        is_const = false;
                        continue;
                    }
                    seen_default = true;
                    if chosen.is_none() {
                        chosen = Some(arm.expr);
                    }
                }
                MatchPattern::Values(vals) => {
                    for &id in vals {
                        let Const::Lit(v) = self.get(id)? else {
                            return Err(EvalError::NotConst);
                        };
                        if !seen.insert(v) {
                            is_const = false;
                        } else if chosen.is_none() && scrut.to_value() == v {
                            chosen = Some(arm.expr);
                        }
                    }
                }
            }
        }

        if !is_const {
            return Err(EvalError::NotConst);
        }

        match chosen {
            Some(id) => self.get(id),
            None => Err(EvalError::NotConst),
        }
    }

    fn fold_block(&self, block: BlockId, expr: ExprId) -> EvalResult {
        let &Block {
            id: _,
            span: _,
            ref stmts,
            expr: block_expr,
            returns: _,
        } = self.hir.lookup(block);
        if !stmts.is_empty() {
            // TODO(eric): We could check if all of the
            // statements are constant. But this might not be
            // worth the effort.
            return Err(EvalError::NotConst);
        }
        let cons = if let Some(inner) = block_expr {
            self.get(inner)?
        } else {
            self.get(expr)?
        };
        Ok(cons.to_expr())
    }

    fn fold_ident(&self, ident: IdentId) -> EvalResult {
        let sym_id = self.symbols.resolve_item(ident);
        self.consts
            .symbols
            .get(&sym_id)
            .copied()
            .ok_or(EvalError::NotConst)
    }

    fn fold_dot(&self, expr: ExprId, ident: IdentId) -> EvalResult {
        // Type must be struct (post-typecheck invariant)
        let Type { kind, .. } = self.types.get_type(expr);
        let TypeKind::Struct(_) = kind else {
            self.cx.dcx().emit_span_bug(
                (self.hir.lookup_span(expr), "field access"),
                "Dot on non-struct",
            );
        };

        // Value must be struct
        let Value::Struct(StructValue { fields, .. }) = self.get_val(expr)? else {
            self.cx.dcx().emit_span_bug(
                (self.hir.lookup_span(expr), "field access"),
                "non-struct value for struct field access",
            );
        };
        let xref = self.hir.lookup_ident_ref(ident);
        let Some(&vref) = fields.get(&xref) else {
            self.cx.dcx().emit_span_bug(
                (self.hir.lookup_span(expr), "field access"),
                "missing struct field in value",
            );
        };
        Ok(Const::Expr(vref))
    }

    fn fold_cast(&self, src_expr: ExprId, _ident: IdentId, result_expr: ExprId) -> EvalResult {
        let Value::Struct(StructValue {
            fields: src_fields, ..
        }) = self.get_val(src_expr)?
        else {
            self.cx.dcx().emit_span_bug(
                (self.hir.lookup_span(src_expr), "struct cast"),
                "cast source is not a struct",
            );
        };

        let Type {
            xref: target_ty,
            kind,
        } = self.types.get_type(result_expr);
        let TypeKind::Struct(target_st) = kind else {
            self.cx.dcx().emit_span_bug(
                (self.hir.lookup_span(result_expr), "struct cast"),
                "cast target is not a struct",
            );
        };

        let mut fields = BTreeMap::new();
        for declared in &target_st.fields {
            let Some(&vref) = src_fields.get(&declared.xref) else {
                self.cx.dcx().emit_span_bug(
                    (self.hir.lookup_span(result_expr), "struct cast"),
                    "missing field in cast source",
                );
            };
            fields.insert(declared.xref, vref);
        }
        let val = Value::Struct(StructValue {
            ty: target_ty,
            fields,
        });
        Ok(Const::Expr(self.cx.intern_const(val)))
    }

    fn fold_func_call(&mut self, call: &'cx FunctionCall) -> EvalResult {
        let FunctionCall { ident, args } = call;

        let sym_id = self.symbols.resolve_item(*ident);
        let sym = self.symbols.get(sym_id);
        let SymbolKind::Item(ItemKind::Func(id)) = &sym.kind else {
            self.cx.dcx().emit_span_bug(
                (self.symbols.get_span(sym_id), "function call"),
                "called symbol is not a function",
            );
        };
        let FuncDef {
            id: _,
            span: _,
            ident: _,
            result: _,
            body,
        } = self.hir.lookup(*id);

        let Body {
            id: _,
            span: _,
            params,
            stmts,
            returns: _,
        } = self.hir.lookup(*body);

        // Arity check
        if args.len() != params.len() {
            return Err(EvalError::NotConst);
        }

        // Evaluate all arguments to constants first
        let mut arg_consts: Vec<ConstRef> = Vec::with_capacity(args.len());
        for &arg_id in args {
            let cons = self.get(arg_id)?;
            arg_consts.push(cons);
        }

        // Snapshot current symbol environment and bind params
        let saved_symbols = self.consts.symbols.clone();
        for (param_id, cons) in params.iter().zip(arg_consts.iter().copied()) {
            let param = self.hir.lookup(*param_id);
            let sym_id = self.symbols.resolve_item(param.ident);
            self.consts.symbols.insert(sym_id, cons);
        }

        // Ensure expressions inside are evaluated under this environment
        // Walk the body (this visits stmts and exprs)
        self.visit_body(self.hir.lookup(*body));

        // Verify all statements/expressions are constant and only allowed kinds appear
        let mut checker = ConstBodyChecker::new(self);
        checker.visit_body(self.hir.lookup(*body));

        // Extract the function return value if checker passed
        let result = if checker.ok {
            match stmts.last() {
                Some(&stmt_id) => {
                    let stmt = self.hir.lookup(stmt_id);
                    match &stmt.kind {
                        StmtKind::Return(ret) => {
                            let cons = self.get(ret.expr)?;
                            Ok(cons.to_expr())
                        }
                        _ => Err(EvalError::NotConst),
                    }
                }
                None => Err(EvalError::NotConst),
            }
        } else {
            Err(EvalError::NotConst)
        };

        // Restore environment
        self.consts.symbols = saved_symbols;

        result
    }

    fn fold_substruct(&self, src_expr: ExprId, _ident: IdentId, result_expr: ExprId) -> EvalResult {
        let Value::Struct(StructValue {
            fields: src_fields, ..
        }) = self.get_val(src_expr)?
        else {
            self.cx.dcx().emit_span_bug(
                (self.hir.lookup_span(src_expr), "struct substruct"),
                "substruct source is not a struct",
            );
        };

        let Type {
            xref: target_ty,
            kind,
        } = self.types.get_type(result_expr);
        let TypeKind::Struct(target_st) = kind else {
            self.cx.dcx().emit_span_bug(
                (self.hir.lookup_span(result_expr), "struct substruct"),
                "substruct target is not a struct",
            );
        };

        let mut fields = BTreeMap::new();
        for declared in &target_st.fields {
            let Some(&vref) = src_fields.get(&declared.xref) else {
                self.cx.dcx().emit_span_bug(
                    (self.hir.lookup_span(result_expr), "struct substruct"),
                    "missing field in substruct source",
                );
            };
            fields.insert(declared.xref, vref);
        }

        let val = Value::Struct(StructValue {
            ty: target_ty,
            fields,
        });
        Ok(Const::Expr(self.cx.intern_const(val)))
    }

    fn fold_let(&mut self, stmt: &'cx LetStmt) -> Result<(), EvalError> {
        let LetStmt { ident, expr } = stmt;
        let cons = self.get(*expr)?;
        let sym_id = self.symbols.resolve_item(*ident);
        self.consts.symbols.insert(sym_id, cons);
        Ok(())
    }
}

impl<'cx> Visitor<'cx> for Evaluator<'cx> {
    type Result = ();

    fn hir(&self) -> &'cx Hir {
        self.hir.hir()
    }

    fn visit_expr(&mut self, expr: &'cx Expr) -> Self::Result {
        expr.walk(self);

        let Expr {
            id,
            span: _,
            kind,
            pure: _,
            returns: _,
        } = expr;
        let result = match kind {
            ExprKind::Lit(v) => self.fold_lit(v, *id),
            ExprKind::EnumRef(v) => self.fold_enum_ref(v, *id),
            ExprKind::Unary(op, expr) => self.fold_unary(*op, *expr),
            ExprKind::Binary(op, lhs, rhs) => self.fold_binary(*op, *lhs, *rhs),
            ExprKind::Ternary(v) => self.fold_ternary(v),
            ExprKind::Is(expr, is_some) => self.fold_is(*expr, *is_some),
            ExprKind::Match(v) => self.fold_match(v),
            ExprKind::Block(block, expr) => self.fold_block(*block, *expr),
            ExprKind::Identifier(ident) => self.fold_ident(*ident),
            ExprKind::Dot(expr, ident) => self.fold_dot(*expr, *ident),
            ExprKind::Cast(expr, ident) => self.fold_cast(*expr, *ident, *id),
            ExprKind::FunctionCall(call) => self.fold_func_call(call),
            ExprKind::Substruct(expr, ident) => self.fold_substruct(*expr, *ident, *id),
            ExprKind::Intrinsic(Intrinsic::Todo) => {
                Ok(Const::Lit(self.cx.intern_const(Value::Never)))
            }
            // Not constants by definition for ourpurposes
            ExprKind::Intrinsic(_) | ExprKind::ForeignFunctionCall(_) => Err(EvalError::NotConst),
        };
        self.set(*id, result);
    }

    fn visit_stmt(&mut self, stmt: &'cx Stmt) -> Self::Result {
        stmt.walk(self);

        let Stmt {
            id: _,
            span: _,
            kind,
            returns: _,
        } = stmt;
        match kind {
            StmtKind::Let(v) => {
                let _ = self.fold_let(v);
            }
            _ => {}
        }
    }
}

// Verifies that every expression in a body evaluated to a constant and
// that only allowed statement kinds appear for const evaluation.
struct ConstBodyChecker<'a, 'cx> {
    cx: Ctx<'cx>,
    hir: HirView<'cx>,
    consts: &'a Consts,
    ok: bool,
}

impl<'a, 'cx> ConstBodyChecker<'a, 'cx> {
    fn new(ev: &'a Evaluator<'cx>) -> Self {
        Self {
            cx: ev.cx,
            hir: ev.hir,
            consts: &ev.consts,
            ok: true,
        }
    }

    fn is_const(&self, id: ExprId) -> bool {
        matches!(self.consts.exprs.get(&id), Some(Ok(_)))
    }

    fn is_const_bool(&self, id: ExprId) -> bool {
        match self.consts.exprs.get(&id) {
            Some(Ok(Const::Lit(v))) | Some(Ok(Const::Expr(v))) => {
                matches!(self.cx.get_const(*v), Value::Bool(_))
            }
            _ => false,
        }
    }
}

impl<'a, 'cx> Visitor<'cx> for ConstBodyChecker<'a, 'cx> {
    type Result = ();

    fn hir(&self) -> &'cx Hir {
        self.hir.hir()
    }

    fn visit_expr(&mut self, expr: &'cx Expr) -> Self::Result {
        expr.walk(self);
        let Expr { id, kind, .. } = expr;
        // Treat Intrinsic::Todo as a constant expression for checking purposes
        let is_const = match kind {
            ExprKind::Intrinsic(Intrinsic::Todo) => true,
            _ => self.is_const(*id),
        };
        if !is_const {
            self.ok = false;
        }
    }

    fn visit_stmt_kind(&mut self, kind: &'cx StmtKind) -> Self::Result {
        use StmtKind::*;
        match kind {
            Let(_) | Return(_) => {}
            Check(v) => {
                if !self.is_const_bool(v.expr) {
                    self.ok = false;
                }
            }
            DebugAssert(v) => {
                if !self.is_const_bool(v.expr) {
                    self.ok = false;
                }
            }
            // Disallow all other side-effecting or control-flow statements in const contexts
            Match(_) | If(_) | Finish(_) | Map(_) | ActionCall(_) | Publish(_) | Create(_)
            | Update(_) | Delete(_) | Emit(_) | FunctionCall(_) => {
                self.ok = false;
            }
        }
        // Continue walking into nested nodes so expressions are checked
        crate::hir::visit::walk_stmt_kind(self, kind)
    }
}

type ConstRef = Const<ValueRef>;
type EvalResult = Result<ConstRef, EvalError>;

enum EvalError {
    IntOverflow,
    NotConst,
}

#[derive(Clone, Debug, Default)]
pub struct Consts {
    pub exprs: BTreeMap<ExprId, Result<ConstRef, Error>>,
    pub symbols: BTreeMap<SymbolId, ConstRef>,
}

/// A constant value.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Const<T> {
    /// A constant literal.
    Lit(T),
    /// A constant expression.
    Expr(T),
}

impl<T> Const<T> {
    pub fn as_value(&self) -> &T {
        match self {
            Self::Lit(v) | Self::Expr(v) => v,
        }
    }

    pub fn to_value(self) -> T {
        match self {
            Self::Lit(v) | Self::Expr(v) => v,
        }
    }

    pub fn to_expr(self) -> Self {
        match self {
            Self::Lit(v) | Self::Expr(v) => Self::Expr(v),
        }
    }
}

/// A constant value.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Value {
    Int(i64),
    Bool(bool),
    String(TextRef),
    Enum(EnumValue),
    Struct(StructValue),
    Optional(Option<ConstRef>),
    Unit,
    Never,
}

/// A constant enum reference.
#[derive(Clone, Debug, Hash)]
pub struct EnumValue {
    pub ty: TypeRef,
    pub variant: IdentRef,
}

impl Eq for EnumValue {}
impl PartialEq for EnumValue {
    fn eq(&self, other: &Self) -> bool {
        // The type checker should ensure that we do not compare
        // different types.
        assert_eq!(self.ty, other.ty);

        self.variant == other.variant
    }
}

/// A constant struct literal.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct StructValue {
    pub ty: TypeRef,
    pub fields: BTreeMap<IdentRef, ValueRef>,
}

/// An error that occurred during constant evaluation.
#[derive(Copy, Clone, Debug)]
pub enum Error {
    /// An integer expression overflowed.
    IntOverflow,
}

#[derive(Copy, Clone, Debug)]
pub struct ConstEvalView<'cx> {
    cx: Ctx<'cx>,
    consts: &'cx Consts,
}

impl<'cx> ConstEvalView<'cx> {
    /// Retrieves the const evaluation result for a given
    /// expression, if available.
    ///
    /// It returns `None` if the expression is not a constant.
    pub fn get(&self, expr: ExprId) -> Option<Result<Const<&'cx Value>, Error>> {
        let cons = self.consts.exprs.get(&expr).copied()?;
        match cons {
            Ok(Const::Lit(v)) => Some(Ok(Const::Lit(self.cx.get_const(v)))),
            Ok(Const::Expr(v)) => Some(Ok(Const::Expr(self.cx.get_const(v)))),
            Err(err) => Some(Err(err)),
        }
    }

    /// Retrieves the const evaluation result for a given
    /// expression, if available, and if it is a literal.
    ///
    /// It returns `None` if the expression is not a constant or
    /// not a literal constant.
    pub fn get_lit(&self, expr: ExprId) -> Option<Result<&'cx Value, Error>> {
        self.get(expr).and_then(|res| match res {
            Ok(Const::Lit(v)) => Some(Ok(v)),
            Ok(Const::Expr(_)) => None,
            Err(err) => Some(Err(err)),
        })
    }
}

impl<'cx> View<'cx, Consts> for ConstEvalView<'cx> {
    fn new(cx: Ctx<'cx>, data: &'cx Consts) -> Self {
        Self { cx, consts: data }
    }
}

#[cfg(test)]
mod tests;
