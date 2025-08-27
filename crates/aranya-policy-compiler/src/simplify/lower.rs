use super::types::{self as s, Hir};
use crate::{
    ctx::Ctx,
    diag::{ErrorGuaranteed, OptionExt, ResultExt},
    eval::{ConstEvalView, Value as ConstValue},
    hir::{self, HirView, StmtKind},
    symtab::SymbolsView,
    typecheck::{TypesView, types::TypeRef},
};

pub(super) fn run<'cx>(
    cx: Ctx<'cx>,
    (hir, symbols, types, consts): (
        HirView<'cx>,
        SymbolsView<'cx>,
        TypesView<'cx>,
        ConstEvalView<'cx>,
    ),
) -> Result<Hir, ErrorGuaranteed> {
    let mut lower = Lower {
        cx,
        hir,
        symbols,
        types,
        _consts: consts,
        out: Hir::default(),
    };

    // Lower function/action/finish bodies and globals
    for (_, body) in lower.hir.hir().bodies.iter() {
        let _ = lower.lower_stmt_block(&body.stmts);
    }
    for (_, g) in lower.hir.hir().global_lets.iter() {
        let _ = lower.lower_expr(g.expr);
    }

    Ok(lower.out)
}

/// Stateful lowering context from HIR to simplified IR.
///
/// Why keep this as a struct:
/// - Centralizes access to `cx`, `hir`, `types`, const-eval, and output arenas
///   so helpers don't need long parameter lists.
/// - Ensures we build a coherent simplified IR before returning.
struct Lower<'cx> {
    cx: Ctx<'cx>,
    hir: HirView<'cx>,
    symbols: SymbolsView<'cx>,
    types: TypesView<'cx>,
    _consts: ConstEvalView<'cx>,
    out: Hir,
}

impl<'cx> Lower<'cx> {
    /// Unit and never are used to type effect-only and early-exit expressions.
    /// They come from the checked types' builtins and are not synthesized.
    fn unit(&self) -> TypeRef {
        self.cx.builtins.unit
    }
    fn never(&self) -> TypeRef {
        self.cx.builtins.never
    }

    fn insert_expr(&mut self, kind: s::ExprKind, ty: TypeRef, pure: hir::Pure) -> s::ExprId {
        self.out
            .exprs
            .insert_with_key(|id| s::Expr { id, kind, ty, pure })
    }

    // --- Purity helpers ---------------------------------------------------
    fn and_pure(a: hir::Pure, b: hir::Pure) -> hir::Pure {
        match (a, b) {
            (hir::Pure::Yes, hir::Pure::Yes) => hir::Pure::Yes,
            _ => hir::Pure::No,
        }
    }

    fn and_pures(&self, items: impl IntoIterator<Item = hir::Pure>) -> hir::Pure {
        let mut acc = hir::Pure::Yes;
        for p in items {
            acc = Self::and_pure(acc, p);
            if let hir::Pure::No = acc {
                return hir::Pure::No;
            }
        }
        acc
    }

    fn insert_unary(&mut self, op: hir::UnaryOp, e: s::ExprId, ty: TypeRef) -> s::ExprId {
        let pure = self.out.exprs[e].pure;
        self.insert_expr(s::ExprKind::Unary(op, e), ty, pure)
    }

    fn insert_binary(
        &mut self,
        op: hir::BinOp,
        l: s::ExprId,
        r: s::ExprId,
        ty: TypeRef,
    ) -> s::ExprId {
        let pure = Self::and_pure(self.out.exprs[l].pure, self.out.exprs[r].pure);
        self.insert_expr(s::ExprKind::Binary(op, l, r), ty, pure)
    }

    fn insert_if(
        &mut self,
        cond: s::ExprId,
        then_expr: s::ExprId,
        else_expr: s::ExprId,
        ty: TypeRef,
    ) -> s::ExprId {
        let pure = self.and_pures([
            self.out.exprs[cond].pure,
            self.out.exprs[then_expr].pure,
            self.out.exprs[else_expr].pure,
        ]);
        self.insert_expr(
            s::ExprKind::If {
                cond,
                then_expr,
                else_expr,
            },
            ty,
            pure,
        )
    }

    fn unit_expr(&mut self) -> s::ExprId {
        // Create a trivial integer literal (type int). Callers should wrap with
        // `Discard` to produce a unit-typed expression when used as a statement.
        self.insert_expr(s::ExprKind::LitInt(0), self.cx.builtins.int, hir::Pure::Yes)
    }

    /// Lower a HIR expression into a simplified expression.
    ///
    /// Why no caching by `hir::ExprId`:
    /// - HIR expressions are stored in arenas and referenced once by owners
    ///   (bodies/globals). We don't expect shared subexpressions at HIR level,
    ///   so caching adds complexity without payoff.
    fn lower_expr(&mut self, eid: hir::ExprId) -> s::ExprId {
        let hexpr = &self.hir.hir().exprs[eid];
        let ty = self.types.get_type_ref(eid);
        let pure = hexpr.pure;
        // Constant folding via ConstEval: if this expression evaluates to a
        // compile-time constant, materialize a simplified literal immediately.
        if let Some(res) = self._consts.get_lit(eid) {
            let v = res.unwrap_or_bug(self.cx.dcx(), "simplify: const eval error");
            return self.lower_const_value(v.clone(), eid, ty);
        }
        let id = match &hexpr.kind {
            hir::ExprKind::Lit(l) => {
                use hir::LitKind::*;
                match &l.kind {
                    Int(v) => self.insert_expr(s::ExprKind::LitInt(*v), ty, pure),
                    Bool(b) => self.insert_expr(s::ExprKind::LitBool(*b), ty, pure),
                    String(t) => self.insert_expr(s::ExprKind::LitString(*t), ty, pure),
                    NamedStruct(ns) => {
                        // Lower named-struct literal to simplified form
                        let fields = ns
                            .fields
                            .iter()
                            .map(|f| s::NamedFieldExpr {
                                ident: f.ident,
                                expr: self.lower_expr(f.expr),
                                resolved: None,
                            })
                            .collect();
                        let value = s::NamedStruct {
                            ident: ns.ident,
                            fields,
                        };
                        self.insert_expr(s::ExprKind::NamedStruct(value), ty, pure)
                    }
                    _ => self.insert_expr(s::ExprKind::Hir(eid), ty, pure),
                }
            }
            hir::ExprKind::Ternary(t) => self.lower_ternary(t, ty),
            hir::ExprKind::Match(m) => self.lower_match(m, ty),
            hir::ExprKind::Unary(op, e) => {
                let e_id = self.lower_expr(*e);
                self.insert_unary(*op, e_id, ty)
            }
            hir::ExprKind::Binary(op, l, r) => {
                let l_id = self.lower_expr(*l);
                let r_id = self.lower_expr(*r);
                self.insert_binary(*op, l_id, r_id, ty)
            }
            hir::ExprKind::Identifier(id) => self.insert_expr(s::ExprKind::Ident(*id), ty, pure),
            hir::ExprKind::Dot(e, ident) => {
                let base = self.lower_expr(*e);
                let pure = self.out.exprs[base].pure;
                let kind = s::ExprKind::Dot(s::Dot {
                    expr: base,
                    ident: *ident,
                });
                self.insert_expr(kind, ty, pure)
            }
            hir::ExprKind::EnumRef(er) => {
                let kind = s::ExprKind::EnumRef(s::EnumRef {
                    ident: er.ident,
                    value: er.value,
                });
                self.insert_expr(kind, ty, hir::Pure::Yes)
            }
            hir::ExprKind::Substruct(e, ident) => {
                let base = self.lower_expr(*e);
                let pure = self.out.exprs[base].pure;
                let kind = s::ExprKind::Substruct(s::Substruct {
                    expr: base,
                    ident: *ident,
                });
                self.insert_expr(kind, ty, pure)
            }
            hir::ExprKind::Cast(e, ident) => {
                let base = self.lower_expr(*e);
                let pure = self.out.exprs[base].pure;
                let kind = s::ExprKind::Cast(s::Cast {
                    expr: base,
                    ident: *ident,
                });
                self.insert_expr(kind, ty, pure)
            }
            hir::ExprKind::Intrinsic(i) => {
                use hir::Intrinsic as HI;
                let kind = match i {
                    HI::Query(f) => s::Intrinsic::Query(self.lower_fact_literal(f)),
                    HI::FactCount(t, n, f) => {
                        s::Intrinsic::FactCount(t.clone(), *n, self.lower_fact_literal(f))
                    }
                    HI::Serialize(e) => {
                        let eid = self.lower_expr(*e);
                        s::Intrinsic::Serialize(eid)
                    }
                    HI::Deserialize(e) => {
                        let eid = self.lower_expr(*e);
                        s::Intrinsic::Deserialize(eid)
                    }
                    HI::Todo => s::Intrinsic::Todo,
                };
                // Intrinsics are pure except those that depend on impure inputs; purity derives from children
                let pure = match &kind {
                    s::Intrinsic::Serialize(e) | s::Intrinsic::Deserialize(e) => {
                        self.out.exprs[*e].pure
                    }
                    s::Intrinsic::Query(_)
                    | s::Intrinsic::FactCount(_, _, _)
                    | s::Intrinsic::Todo => hir::Pure::Yes,
                };
                self.insert_expr(s::ExprKind::Intrinsic(kind), ty, pure)
            }
            hir::ExprKind::Is(e, is_some) => {
                let e_id = self.lower_expr(*e);
                let pure = self.out.exprs[e_id].pure;
                self.insert_expr(s::ExprKind::Is(e_id, *is_some), ty, pure)
            }
            hir::ExprKind::ForeignFunctionCall(call) => {
                let args = call.args.iter().map(|&a| self.lower_expr(a)).collect();
                let kind = s::ExprKind::ForeignFunctionCall(s::ForeignFunctionCall {
                    module: call.module,
                    ident: call.ident,
                    args,
                });
                self.insert_expr(kind, ty, hir::Pure::No)
            }
            hir::ExprKind::FunctionCall(call) => {
                let args = call.args.iter().map(|&a| self.lower_expr(a)).collect();
                let kind = s::ExprKind::FunctionCall(s::FunctionCall {
                    ident: call.ident,
                    args,
                });
                self.insert_expr(kind, ty, hir::Pure::Yes)
            }
            hir::ExprKind::Block(bid, expr) => self.lower_block_expr(*bid, *expr),
            _ => self.insert_expr(s::ExprKind::Hir(eid), ty, pure),
        };
        id
    }

    fn lower_const_value(&mut self, v: ConstValue, hir_eid: hir::ExprId, ty: TypeRef) -> s::ExprId {
        use crate::eval::Value as CV;
        match v {
            CV::Int(i) => self.insert_expr(s::ExprKind::LitInt(i), ty, hir::Pure::Yes),
            CV::Bool(b) => self.insert_expr(s::ExprKind::LitBool(b), ty, hir::Pure::Yes),
            CV::String(t) => self.insert_expr(s::ExprKind::LitString(t), ty, hir::Pure::Yes),
            // For enums, structs, and optionals, leave as HIR for now; we
            // haven't introduced dedicated simplified literals for these yet.
            CV::Enum(_) | CV::Struct(_) | CV::Optional(_) => {
                self.insert_expr(s::ExprKind::Hir(hir_eid), ty, hir::Pure::Yes)
            }
            CV::Unit | CV::Never => {
                // Preserve as passthrough HIR until dedicated simplified forms are introduced
                self.insert_expr(s::ExprKind::Hir(hir_eid), ty, hir::Pure::Yes)
            }
        }
    }

    fn lower_ternary(&mut self, t: &hir::Ternary, ty: TypeRef) -> s::ExprId {
        // Lower ternary `if a then b else c` into a single `If` expression.
        let cond = self.lower_expr(t.cond);
        let then_expr = self.lower_expr(t.true_expr);
        let else_expr = self.lower_expr(t.false_expr);
        self.insert_if(cond, then_expr, else_expr, ty)
    }

    fn lower_match(&mut self, m: &hir::MatchExpr, ty: TypeRef) -> s::ExprId {
        // Strategy:
        // - Evaluate scrutinee exactly once to preserve ordering/purity.
        // - Build nested If chain from the bottom up by iterating arms in reverse.
        // - A Default arm sets the current else branch.
        // - A Values arm builds an OR-chain of Eq comparisons against the scrutinee.
        // - Exhaustiveness is guaranteed by prior passes; otherwise ICE.
        let scrut = self.lower_expr(m.scrutinee);
        let mut current: Option<s::ExprId> = None;
        for arm in m.arms.iter().rev() {
            let arm_expr = self.lower_expr(arm.expr);
            match &arm.pattern {
                hir::MatchPattern::Default => {
                    current = Some(arm_expr);
                }
                hir::MatchPattern::Values(vals) => {
                    let mut cond: Option<s::ExprId> = None;
                    for &v in vals {
                        let v_id = self.lower_expr(v);
                        let eq =
                            self.insert_binary(hir::BinOp::Eq, scrut, v_id, self.cx.builtins.bool);
                        cond = Some(match cond.take() {
                            None => eq,
                            Some(prev) => {
                                self.insert_binary(hir::BinOp::Or, prev, eq, self.cx.builtins.bool)
                            }
                        });
                    }
                    let else_expr = current.unwrap_or_else(|| {
                        self.cx
                            .dcx()
                            .emit_bug("simplify: non-exhaustive match during rewrite")
                    });
                    let cond = cond
                        .unwrap_or_bug(self.cx.dcx(), "simplify: empty values list in match arm");
                    let if_id = self.insert_if(cond, arm_expr, else_expr, ty);
                    current = Some(if_id);
                }
            }
        }
        current.unwrap_or_bug(self.cx.dcx(), "simplify: match has no arms")
    }

    fn lower_block_expr(&mut self, bid: hir::BlockId, expr: hir::ExprId) -> s::ExprId {
        // Flatten nested blocks early so MIR lowering only deals with simple
        // sequences and a single trailing value.
        let mut seq = self.lower_stmt_block(&self.hir.hir().blocks[bid].stmts);
        let inner = self.lower_expr(expr);
        seq.push(inner);
        if seq.len() == 1 {
            seq[0]
        } else {
            let bid = self
                .out
                .blocks
                .insert_with_key(|id| s::Block { id, exprs: seq });
            let last = *self.out.blocks[bid].exprs.last().unwrap();
            let last_ty = self.out.exprs[last].ty;
            // Block purity is the AND of all contained expressions' purity.
            let block_pure = {
                let p = self.out.blocks[bid]
                    .exprs
                    .iter()
                    .map(|&eid| self.out.exprs[eid].pure);
                self.and_pures(p)
            };
            self.insert_expr(s::ExprKind::Block(bid), last_ty, block_pure)
        }
    }

    /// Convert a statement into an expression (unit or never typed).
    ///
    /// Why: The simplified IR is expression-only. Side effects are preserved
    /// as unit-typed expressions, and `return` is represented by a `Never`.
    fn lower_stmt(&mut self, sid: hir::StmtId) -> s::ExprId {
        let s = &self.hir.hir().stmts[sid];
        match &s.kind {
            StmtKind::Finish(block_id) => {
                // Lower the finish block to an expression (possibly a Block), then discard it
                // to produce unit. Finish semantics are effectful, so purity is No.
                let seq = self.lower_stmt_block(&self.hir.hir().blocks[*block_id].stmts);
                let tail = if let Some(&last) = seq.last() {
                    last
                } else {
                    self.unit_expr()
                };
                // Materialize a Block if needed to preserve sequencing
                let expr_id = if seq.len() <= 1 {
                    tail
                } else {
                    let bid = self
                        .out
                        .blocks
                        .insert_with_key(|id| s::Block { id, exprs: seq });
                    self.insert_expr(
                        s::ExprKind::Block(bid),
                        self.out.exprs[tail].ty,
                        hir::Pure::No,
                    )
                };
                let kind = s::ExprKind::Discard(s::Discard { expr: expr_id });
                self.insert_expr(kind, self.unit(), hir::Pure::No)
            }
            StmtKind::Let(v) => {
                let value = self.lower_expr(v.expr);
                let kind = s::ExprKind::Let(s::Let {
                    ident: v.ident,
                    value,
                });
                self.insert_expr(kind, self.unit(), self.out.exprs[value].pure)
            }
            StmtKind::Check(v) => {
                let e = self.lower_expr(v.expr);
                let kind = s::ExprKind::Check(s::Check { expr: e });
                self.insert_expr(kind, self.unit(), hir::Pure::Yes)
            }
            StmtKind::DebugAssert(v) => {
                let e = self.lower_expr(v.expr);
                let kind = s::ExprKind::DebugAssert(s::DebugAssert { expr: e });
                self.insert_expr(kind, self.unit(), hir::Pure::Yes)
            }
            StmtKind::ActionCall(v) => {
                let args = v.args.iter().map(|&a| self.lower_expr(a)).collect();
                let kind = s::ExprKind::ActionCall(s::ActionCall {
                    ident: v.ident,
                    args,
                });
                self.insert_expr(kind, self.unit(), hir::Pure::No)
            }
            StmtKind::FunctionCall(v) => {
                let args = v.args.iter().map(|&a| self.lower_expr(a)).collect();
                let call = s::ExprKind::FunctionCall(s::FunctionCall {
                    ident: v.ident,
                    args,
                });
                // The call is used in statement position; we assign unit type for the
                // inner call expression and then discard it. If we need the precise
                // return type here in the future, this pass would need a symbol lookup.
                let call_expr = self.insert_expr(call, self.unit(), hir::Pure::Yes);
                let kind = s::ExprKind::Discard(s::Discard { expr: call_expr });
                self.insert_expr(kind, self.unit(), hir::Pure::Yes)
            }
            StmtKind::Publish(v) => {
                // Expect a named-struct payload
                let e = self.lower_expr(v.expr);
                match &self.out.exprs[e].kind {
                    s::ExprKind::NamedStruct(ns) => {
                        let mut value = ns.clone();
                        // Resolve fields against command struct (by name)
                        if let Some(sym) = self.symbols.table().item_resolutions.get(&value.ident) {
                            if let Some(sym) = self.symbols.table().get(*sym) {
                                if let crate::symtab::SymbolKind::Item(
                                    crate::symtab::ItemKind::Cmd(cmd_id),
                                ) = sym.kind
                                {
                                    // cmd struct is in `structs` via `struct_id` on CmdDef
                                    let sdef = &self.hir.hir().cmds[cmd_id];
                                    let sid = sdef.struct_id;
                                    for f in &mut value.fields {
                                        f.resolved =
                                            self.resolve_field_in_struct_chain(sid, f.ident);
                                    }
                                }
                            }
                        }
                        let kind = s::ExprKind::Publish(s::Publish { value });
                        self.insert_expr(kind, self.unit(), hir::Pure::No)
                    }
                    other => self.cx.dcx().emit_bug(format!(
                        "simplify: publish expects named-struct payload, found {:?}",
                        other
                    )),
                }
            }
            StmtKind::Emit(v) => {
                // Expect a named-struct payload
                let e = self.lower_expr(v.expr);
                match &self.out.exprs[e].kind {
                    s::ExprKind::NamedStruct(ns) => {
                        let mut value = ns.clone();
                        // Resolve fields against effect struct (by name)
                        if let Some(sym) = self.symbols.table().item_resolutions.get(&value.ident) {
                            if let Some(sym) = self.symbols.table().get(*sym) {
                                if let crate::symtab::SymbolKind::Item(
                                    crate::symtab::ItemKind::Effect(effect_id),
                                ) = sym.kind
                                {
                                    let sdef = &self.hir.hir().effects[effect_id];
                                    let sid = sdef.struct_id;
                                    for f in &mut value.fields {
                                        f.resolved =
                                            self.resolve_field_in_struct_chain(sid, f.ident);
                                    }
                                }
                            }
                        }
                        let kind = s::ExprKind::Emit(s::Emit { value });
                        self.insert_expr(kind, self.unit(), hir::Pure::No)
                    }
                    other => self.cx.dcx().emit_bug(format!(
                        "simplify: emit expects named-struct payload, found {:?}",
                        other
                    )),
                }
            }
            StmtKind::Create(v) => {
                let fact = self.lower_fact_literal(&v.fact);
                let kind = s::ExprKind::Create(s::Create { fact });
                self.insert_expr(kind, self.unit(), hir::Pure::No)
            }
            StmtKind::Update(v) => {
                let fact = self.lower_fact_literal(&v.fact);
                let to = v.to.iter().map(|f| self.lower_fact_field_expr(f)).collect();
                let kind = s::ExprKind::Update(s::Update { fact, to });
                self.insert_expr(kind, self.unit(), hir::Pure::No)
            }
            StmtKind::Delete(v) => {
                let fact = self.lower_fact_literal(&v.fact);
                let kind = s::ExprKind::Delete(s::Delete { fact });
                self.insert_expr(kind, self.unit(), hir::Pure::No)
            }
            StmtKind::Return(v) => {
                let e = self.lower_expr(v.expr);
                let kind = s::ExprKind::Return(e);
                self.insert_expr(kind, self.never(), self.out.exprs[e].pure)
            }
            StmtKind::If(v) => {
                // Build nested If expression chain from branches, with optional else.
                let mut else_expr = if let Some(else_bid) = v.else_block {
                    let seq = self.lower_stmt_block(&self.hir.hir().blocks[else_bid].stmts);
                    let tail = if let Some(&last) = seq.last() {
                        last
                    } else {
                        self.unit_expr()
                    };
                    if seq.len() <= 1 {
                        tail
                    } else {
                        let bid = self
                            .out
                            .blocks
                            .insert_with_key(|id| s::Block { id, exprs: seq });
                        let last = *self.out.blocks[bid].exprs.last().unwrap();
                        let last_ty = self.out.exprs[last].ty;
                        // Block purity is AND of contained expressions
                        let block_pure = {
                            let p = self.out.blocks[bid]
                                .exprs
                                .iter()
                                .map(|&eid| self.out.exprs[eid].pure);
                            self.and_pures(p)
                        };
                        self.insert_expr(s::ExprKind::Block(bid), last_ty, block_pure)
                    }
                } else {
                    self.unit_expr()
                };
                for br in v.branches.iter().rev() {
                    let cond = self.lower_expr(br.expr);
                    let seq = self.lower_stmt_block(&self.hir.hir().blocks[br.block].stmts);
                    let then_expr = if let Some(&last) = seq.last() {
                        if seq.len() <= 1 {
                            last
                        } else {
                            let bid = self
                                .out
                                .blocks
                                .insert_with_key(|id| s::Block { id, exprs: seq });
                            let last = *self.out.blocks[bid].exprs.last().unwrap();
                            let last_ty = self.out.exprs[last].ty;
                            let block_pure = {
                                let p = self.out.blocks[bid]
                                    .exprs
                                    .iter()
                                    .map(|&eid| self.out.exprs[eid].pure);
                                self.and_pures(p)
                            };
                            self.insert_expr(s::ExprKind::Block(bid), last_ty, block_pure)
                        }
                    } else {
                        self.unit_expr()
                    };
                    else_expr = self.insert_if(cond, then_expr, else_expr, self.unit());
                }
                let kind = s::ExprKind::Discard(s::Discard { expr: else_expr });
                let pure = self.out.exprs[else_expr].pure;
                self.insert_expr(kind, self.unit(), pure)
            }
            StmtKind::Match(v) => {
                // Statement form: lower to nested If of unit-typed branches, wrap with Discard.
                let scrut = self.lower_expr(v.expr);
                let mut current: Option<s::ExprId> = None;
                for arm in v.arms.iter().rev() {
                    let seq = self.lower_stmt_block(&self.hir.hir().blocks[arm.block].stmts);
                    let arm_expr = if let Some(&last) = seq.last() {
                        if seq.len() <= 1 {
                            last
                        } else {
                            let bid = self
                                .out
                                .blocks
                                .insert_with_key(|id| s::Block { id, exprs: seq });
                            let last = *self.out.blocks[bid].exprs.last().unwrap();
                            let last_ty = self.out.exprs[last].ty;
                            let block_pure = {
                                let p = self.out.blocks[bid]
                                    .exprs
                                    .iter()
                                    .map(|&eid| self.out.exprs[eid].pure);
                                self.and_pures(p)
                            };
                            self.insert_expr(s::ExprKind::Block(bid), last_ty, block_pure)
                        }
                    } else {
                        self.unit_expr()
                    };
                    match &arm.pattern {
                        hir::MatchPattern::Default => {
                            current = Some(arm_expr);
                        }
                        hir::MatchPattern::Values(vals) => {
                            let mut cond: Option<s::ExprId> = None;
                            for &val in vals {
                                let v_id = self.lower_expr(val);
                                let eq = self.insert_binary(
                                    hir::BinOp::Eq,
                                    scrut,
                                    v_id,
                                    self.cx.builtins.bool,
                                );
                                cond = Some(match cond.take() {
                                    None => eq,
                                    Some(prev) => self.insert_binary(
                                        hir::BinOp::Or,
                                        prev,
                                        eq,
                                        self.cx.builtins.bool,
                                    ),
                                });
                            }
                            let else_expr = current.unwrap_or_else(|| {
                                self.cx
                                    .dcx()
                                    .emit_bug("simplify: non-exhaustive match stmt during rewrite")
                            });
                            let cond = cond.unwrap_or_bug(
                                self.cx.dcx(),
                                "simplify: empty values list in match stmt arm",
                            );
                            let if_id = self.insert_if(cond, arm_expr, else_expr, self.unit());
                            current = Some(if_id);
                        }
                    }
                }
                let top = current.unwrap_or_bug(self.cx.dcx(), "simplify: match stmt has no arms");
                let pure = self.out.exprs[top].pure;
                let kind = s::ExprKind::Discard(s::Discard { expr: top });
                self.insert_expr(kind, self.unit(), pure)
            }
            StmtKind::Map(_) => self.cx.dcx().emit_bug(
                "simplify: Map statement must be normalized away before simplify; found Map",
            ),
            other => self.cx.dcx().emit_bug(format!(
                "simplify: statement lowering not implemented for {:?} (stmt id {:?})",
                other, sid
            )),
        }
    }

    fn lower_fact_literal(&mut self, v: &hir::FactLiteral) -> s::FactLiteral {
        s::FactLiteral {
            ident: v.ident,
            keys: v
                .keys
                .iter()
                .map(|f| self.lower_fact_field_expr(f))
                .collect(),
            vals: v
                .vals
                .iter()
                .map(|f| self.lower_fact_field_expr(f))
                .collect(),
        }
    }

    fn lower_fact_field_expr(&mut self, f: &hir::FactFieldExpr) -> s::FactFieldExpr {
        let expr = match f.expr {
            hir::FactField::Expr(e) => s::FactField::Expr(self.lower_expr(e)),
            hir::FactField::Bind => s::FactField::Bind,
        };
        s::FactFieldExpr {
            ident: f.ident,
            expr,
        }
    }

    fn lower_stmt_block(&mut self, stmts: &[hir::StmtId]) -> Vec<s::ExprId> {
        let mut out = Vec::with_capacity(stmts.len());
        for &sid in stmts {
            let eid = self.lower_stmt(sid);
            match &self.out.exprs[eid].kind {
                s::ExprKind::Block(bid) => {
                    let exprs = self.out.blocks[*bid].exprs.clone();
                    out.extend(exprs);
                }
                _ => out.push(eid),
            }
        }
        out
    }
}

impl<'cx> Lower<'cx> {
    fn resolve_field_in_struct_chain(
        &self,
        sid: hir::StructId,
        field_ident: hir::IdentId,
    ) -> Option<s::ResolvedField> {
        fn walk(
            lower: &Lower<'_>,
            sid: hir::StructId,
            target: hir::IdentId,
        ) -> Option<hir::StructFieldId> {
            let sdef = &lower.hir.hir().structs[sid];
            for &sfid in &sdef.items {
                let sf = &lower.hir.hir().struct_fields[sfid];
                match &sf.kind {
                    hir::StructFieldKind::Field { ident, .. } => {
                        if *ident == target {
                            return Some(sfid);
                        }
                    }
                    hir::StructFieldKind::StructRef(sident) => {
                        // Resolve included struct name to StructId via symbols
                        if let Some(sym) = lower.symbols.table().type_resolutions.get(sident) {
                            if let Some(sym) = lower.symbols.table().get(*sym) {
                                if let crate::symtab::SymbolKind::Type(
                                    crate::symtab::TypeKind::Struct(inner_sid, _),
                                ) = sym.kind
                                {
                                    if let Some(found) = walk(lower, inner_sid, target) {
                                        return Some(found);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            None
        }
        walk(self, sid, field_ident).map(s::ResolvedField::Struct)
    }
}
