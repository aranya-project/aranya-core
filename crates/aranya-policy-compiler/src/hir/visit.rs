#[cfg(test)]
mod tests;

use std::{convert::Infallible, ops::ControlFlow};

use crate::{
    ctx::InternedIdent,
    hir::hir::{
        ActionArg, ActionArgId, ActionDef, ActionId, ActionSig, Block, BlockId, CmdDef, CmdField,
        CmdFieldKind, CmdId, EffectDef, EffectField, EffectFieldId, EffectFieldKind, EffectId,
        EnumDef, EnumId, Expr, ExprId, ExprKind, FactDef, FactField, FactFieldExpr, FactId,
        FactKey, FactLiteral, FactVal, FinishFuncArg, FinishFuncDef, FinishFuncId, FinishFuncSig,
        FuncArg, FuncDef, FuncId, FuncSig, GlobalId, GlobalLetDef, Hir, Ident, IdentId, Intrinsic,
        Lit, LitKind, MatchPattern, NamedStruct, Stmt, StmtId, StmtKind, StructDef, StructField,
        StructFieldExpr, StructFieldId, StructFieldKind, StructId, VType, VTypeId, VTypeKind,
    },
};

macro_rules! try_visit {
    ($e:expr) => {
        match $crate::hir::visit::VisitorResult::branch($e) {
            core::ops::ControlFlow::Continue(()) => (),
            #[allow(unreachable_code)]
            core::ops::ControlFlow::Break(r) => {
                return $crate::hir::visit::VisitorResult::from_residual(r);
            }
        }
    };
}
pub(crate) use try_visit;

/// Visits [`Node`]s in [`Hir`].
pub(crate) trait Visitor<'hir>: Sized {
    /// The result from a "visit_" method.
    type Result: VisitorResult;

    //
    // Actions
    //

    fn visit_action(&mut self, def: &'hir ActionDef<'hir>) -> Self::Result {
        walk_action(self, def)
    }
    fn visit_action_id(&mut self, _id: ActionId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_action_sig(&mut self, sig: &'hir ActionSig<'hir>) -> Self::Result {
        walk_action_sig(self, sig)
    }
    fn visit_action_arg(&mut self, arg: &'hir ActionArg<'hir>) -> Self::Result {
        walk_action_arg(self, arg)
    }
    fn visit_action_arg_id(&mut self, _id: ActionArgId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_action_body(&mut self, block: &'hir Block<'hir>) -> Self::Result {
        walk_block(self, block)
    }

    //
    // Commands
    //

    fn visit_cmd(&mut self, def: &'hir CmdDef<'hir>) -> Self::Result {
        walk_cmd(self, def)
    }
    fn visit_cmd_id(&mut self, _id: CmdId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_cmd_field(&mut self, field: &'hir CmdField<'hir>) -> Self::Result {
        walk_cmd_field(self, field)
    }
    fn visit_cmd_seal_block(&mut self, block: &'hir Block<'hir>) -> Self::Result {
        walk_block(self, block)
    }
    fn visit_cmd_open_block(&mut self, block: &'hir Block<'hir>) -> Self::Result {
        walk_block(self, block)
    }
    fn visit_cmd_policy_block(&mut self, block: &'hir Block<'hir>) -> Self::Result {
        walk_block(self, block)
    }
    fn visit_cmd_recall_block(&mut self, block: &'hir Block<'hir>) -> Self::Result {
        walk_block(self, block)
    }

    //
    // Effects
    //

    fn visit_effect_def(&mut self, def: &'hir EffectDef<'hir>) -> Self::Result {
        walk_effect(self, def)
    }
    fn visit_effect_id(&mut self, _id: EffectId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_effect_field(&mut self, field: &'hir EffectField<'hir>) -> Self::Result {
        walk_effect_field(self, field)
    }
    fn visit_effect_field_id(&mut self, _id: EffectFieldId) -> Self::Result {
        Self::Result::output()
    }

    //
    // Enums
    //

    fn visit_enum_def(&mut self, def: &'hir EnumDef<'hir>) -> Self::Result {
        walk_enum(self, def)
    }
    fn visit_enum_id(&mut self, _id: EnumId) -> Self::Result {
        Self::Result::output()
    }

    //
    // Facts
    //

    fn visit_fact_def(&mut self, def: &'hir FactDef<'hir>) -> Self::Result {
        walk_fact(self, def)
    }
    fn visit_fact_id(&mut self, _id: FactId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_fact_key(&mut self, key: &'hir FactKey<'hir>) -> Self::Result {
        walk_fact_key(self, key)
    }
    fn visit_fact_val(&mut self, val: &'hir FactVal<'hir>) -> Self::Result {
        walk_fact_val(self, val)
    }

    //
    // Finish functions
    //

    fn visit_finish_func_def(&mut self, def: &'hir FinishFuncDef<'hir>) -> Self::Result {
        walk_finish_func(self, def)
    }
    fn visit_finish_func_id(&mut self, _id: FinishFuncId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_finish_func_sig(&mut self, sig: &'hir FinishFuncSig<'hir>) -> Self::Result {
        walk_finish_func_sig(self, sig)
    }
    fn visit_finish_func_arg(&mut self, arg: &'hir FinishFuncArg<'hir>) -> Self::Result {
        walk_finish_func_arg(self, arg)
    }
    fn visit_finish_func_body(&mut self, block: &'hir Block<'hir>) -> Self::Result {
        walk_block(self, block)
    }

    //
    // Functions
    //

    fn visit_func_def(&mut self, _def: &'hir FuncDef<'hir>) -> Self::Result {
        walk_func(self, _def)
    }
    fn visit_func_id(&mut self, _id: FuncId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_func_sig(&mut self, sig: &'hir FuncSig<'hir>) -> Self::Result {
        walk_func_sig(self, sig)
    }
    fn visit_func_arg(&mut self, arg: &'hir FuncArg<'hir>) -> Self::Result {
        walk_func_arg(self, arg)
    }
    fn visit_func_result(&mut self, vtype: &'hir VType<'hir>) -> Self::Result {
        walk_vtype(self, vtype)
    }
    fn visit_func_body(&mut self, block: &'hir Block<'hir>) -> Self::Result {
        walk_block(self, block)
    }

    //
    // Globals
    //

    fn visit_global_def(&mut self, def: &'hir GlobalLetDef<'hir>) -> Self::Result {
        walk_global_let(self, def)
    }
    fn visit_global_id(&mut self, _id: GlobalId) -> Self::Result {
        Self::Result::output()
    }

    //
    // Structs
    //

    fn visit_struct_def(&mut self, def: &'hir StructDef<'hir>) -> Self::Result {
        walk_struct(self, def)
    }
    fn visit_struct_id(&mut self, _id: StructId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_struct_field(&mut self, field: &'hir StructField<'hir>) -> Self::Result {
        walk_struct_field(self, field)
    }

    //
    // Misc
    //

    fn visit_ident(&mut self, _ident: Ident) -> Self::Result {
        Self::Result::output()
    }
    fn visit_ident_ident(&mut self, _ident: InternedIdent) -> Self::Result {
        Self::Result::output()
    }

    fn visit_block(&mut self, block: &'hir Block<'hir>) -> Self::Result {
        walk_block(self, block)
    }
    fn visit_block_id(&mut self, _id: BlockId) -> Self::Result {
        Self::Result::output()
    }

    fn visit_expr(&mut self, expr: &'hir Expr<'hir>) -> Self::Result {
        walk_expr(self, expr)
    }
    fn visit_expr_id(&mut self, _id: ExprId) -> Self::Result {
        Self::Result::output()
    }

    fn visit_stmt(&mut self, _stmt: &'hir Stmt<'hir>) -> Self::Result {
        Self::Result::output()
    }
    fn visit_stmt_id(&mut self, _id: StmtId) -> Self::Result {
        Self::Result::output()
    }

    fn visit_vtype(&mut self, vtype: &'hir VType<'hir>) -> Self::Result {
        walk_vtype(self, vtype)
    }
    fn visit_vtype_id(&mut self, _id: VTypeId) -> Self::Result {
        Self::Result::output()
    }

    fn visit_lit(&mut self, lit: &'hir Lit<'hir>) -> Self::Result {
        walk_lit(self, lit)
    }

    fn visit_named_struct_lit(&mut self, lit: &'hir NamedStruct<'hir>) -> Self::Result {
        walk_named_struct_lit(self, lit)
    }
    fn visit_named_struct_lit_field(&mut self, field: &'hir StructFieldExpr<'hir>) -> Self::Result {
        walk_struct_field_expr(self, field)
    }

    fn visit_fact_lit(&mut self, fact: &'hir FactLiteral<'hir>) -> Self::Result {
        walk_fact_lit(self, fact)
    }
    fn visit_fact_lit_key(&mut self, key: &'hir FactFieldExpr<'hir>) -> Self::Result {
        walk_fact_field_expr(self, key)
    }
    fn visit_fact_lit_val(&mut self, val: &'hir FactFieldExpr<'hir>) -> Self::Result {
        walk_fact_field_expr(self, val)
    }
}

/// The result from a [`Visitor`] method.
pub(crate) trait VisitorResult {
    type Residual;

    fn output() -> Self;
    fn from_residual(residual: Self::Residual) -> Self;
    fn from_branch(b: ControlFlow<Self::Residual>) -> Self;
    fn branch(self) -> ControlFlow<Self::Residual>;
}

impl VisitorResult for () {
    type Residual = Infallible;

    fn output() -> Self {}
    fn from_residual(_: Self::Residual) -> Self {}
    fn from_branch(_: ControlFlow<Self::Residual>) -> Self {}
    fn branch(self) -> ControlFlow<Self::Residual> {
        ControlFlow::Continue(())
    }
}

impl<T> VisitorResult for ControlFlow<T> {
    type Residual = T;

    fn output() -> Self {
        ControlFlow::Continue(())
    }
    fn from_residual(residual: Self::Residual) -> Self {
        ControlFlow::Break(residual)
    }
    fn from_branch(b: Self) -> Self {
        b
    }
    fn branch(self) -> Self {
        self
    }
}

impl<E> VisitorResult for Result<(), E> {
    type Residual = Result<Infallible, E>;

    fn output() -> Self {
        Ok(())
    }
    fn from_residual(residual: Self::Residual) -> Self {
        match residual {
            Err(e) => Err(From::from(e)),
        }
    }
    fn from_branch(b: ControlFlow<Self::Residual>) -> Self {
        match b {
            ControlFlow::Continue(()) => Ok(()),
            ControlFlow::Break(Err(e)) => Err(e),
        }
    }
    fn branch(self) -> ControlFlow<Self::Residual> {
        match self {
            Ok(v) => ControlFlow::Continue(v),
            Err(e) => ControlFlow::Break(Err(e)),
        }
    }
}

/// Walks a specific action.
///
/// This performs a DFS.
pub fn walk_action<'hir, V>(visitor: &mut V, def: &'hir ActionDef<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_action_id(def.id));
    try_visit!(visitor.visit_action_sig(&def.sig));
    V::Result::output()
}

pub fn walk_action_sig<'hir, V>(visitor: &mut V, sig: &'hir ActionSig<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    for arg in &sig.args {
        try_visit!(visitor.visit_action_arg(arg));
    }
    V::Result::output()
}

/// Walks a specific action argument.
///
/// This performs a DFS.
pub fn walk_action_arg<'hir, V>(visitor: &mut V, arg: &'hir ActionArg<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_action_arg_id(arg.id));
    try_visit!(visitor.visit_ident(&arg.ident));
    try_visit!(visitor.visit_vtype(arg.ty));
    V::Result::output()
}

/// Walks a specific command.
///
/// This performs a DFS.
pub fn walk_cmd<'hir, V>(visitor: &mut V, def: &'hir CmdDef<'_>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_cmd_id(def.id));
    for field in &def.fields {
        try_visit!(visitor.visit_cmd_field(field));
        match &field.kind {
            CmdFieldKind::Field { ident, ty } => {
                try_visit!(visitor.visit_ident(ident));
                try_visit!(visitor.visit_vtype(ty));
            }
            CmdFieldKind::StructRef(ident) => {
                try_visit!(visitor.visit_ident(ident));
            }
        }
    }
    try_visit!(visitor.visit_cmd_seal_block(def.seal));
    try_visit!(visitor.visit_cmd_open_block(def.open));
    try_visit!(visitor.visit_cmd_policy_block(def.policy));
    try_visit!(visitor.visit_cmd_recall_block(def.recall));
    V::Result::output()
}

pub fn walk_cmd_field<'hir, V>(visitor: &mut V, field: &'hir CmdField<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_cmd_field_id(field.id));
    match &field.kind {
        CmdFieldKind::Field { ident, ty } => {
            try_visit!(visitor.visit_ident(*ident));
            try_visit!(visitor.visit_vtype(*ty));
        }
        CmdFieldKind::StructRef(ident) => {
            try_visit!(visitor.visit_ident(*ident));
        }
    }
    V::Result::output()
}

/// Walks an identifier.
///
/// This performs a DFS.
pub fn walk_ident<'hir, V>(visitor: &mut V, ident: Ident) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_ident(ident));
    V::Result::output()
}

/// Walks a variable type.
///
/// This performs a DFS.
pub fn walk_vtype<'hir, V>(visitor: &mut V, ty: &'hir VType<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_vtype_id(ty.id));
    match &ty.kind {
        VTypeKind::String | VTypeKind::Bytes | VTypeKind::Int | VTypeKind::Bool | VTypeKind::Id => {
        }
        VTypeKind::Struct(v) => {
            try_visit!(visitor.visit_ident(*v));
        }
        VTypeKind::Enum(v) => {
            try_visit!(visitor.visit_ident(*v));
        }
        VTypeKind::Optional(v) => {
            try_visit!(visitor.visit_vtype(*v));
        }
    }
    V::Result::output()
}

/// Walks a block.
///
/// This performs a DFS.
pub fn walk_block<'hir, V>(visitor: &mut V, block: &'hir Block<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_block_id(block.id));
    for stmt in &block.stmts {
        try_visit!(visitor.visit_stmt(stmt));
    }
    V::Result::output()
}

/// Walks a statement.
///
/// This performs a DFS.
pub fn walk_stmt<'hir, V>(visitor: &mut V, stmt: &'hir Stmt<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_stmt_id(stmt.id));
    walk_stmt_kind(visitor, &stmt.kind)
}

/// Walks a statement.
///
/// This performs a DFS.
pub(super) fn walk_stmt_kind<'hir, V>(visitor: &mut V, kind: &'hir StmtKind<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    match kind {
        StmtKind::Let(v) => {
            try_visit!(visitor.visit_ident(v.ident));
            try_visit!(visitor.visit_expr(v.expr));
        }
        StmtKind::Check(v) => {
            try_visit!(visitor.visit_expr(v.expr));
        }
        StmtKind::Match(v) => {
            try_visit!(visitor.visit_expr(v.expr));
            for arm in &v.arms {
                match &arm.pattern {
                    MatchPattern::Default => {}
                    MatchPattern::Values(values) => {
                        for &expr in values {
                            try_visit!(visitor.visit_expr(expr));
                        }
                    }
                }
                try_visit!(visitor.visit_block(arm.block));
            }
        }
        StmtKind::If(v) => {
            for branch in &v.branches {
                try_visit!(visitor.visit_expr(branch.expr));
                try_visit!(visitor.visit_block(branch.block));
            }
            if let Some(else_block) = v.else_block {
                try_visit!(visitor.visit_block(else_block));
            }
        }
        StmtKind::Finish(block) => {
            try_visit!(visitor.visit_block(*block));
        }
        StmtKind::Map(v) => {
            try_visit!(visitor.visit_fact_lit(&v.fact));
            try_visit!(visitor.visit_ident(v.ident));
            try_visit!(visitor.visit_block(v.block));
        }
        StmtKind::Return(v) => {
            try_visit!(visitor.visit_expr(v.expr));
        }
        StmtKind::ActionCall(v) => {
            try_visit!(visitor.visit_ident(v.ident));
            for &expr in &v.args {
                try_visit!(visitor.visit_expr(expr));
            }
        }
        StmtKind::Publish(v) => {
            try_visit!(visitor.visit_expr(v.exor));
        }
        StmtKind::Create(v) => {
            try_visit!(visitor.visit_fact_lit(&v.fact));
        }
        StmtKind::Update(v) => {
            try_visit!(visitor.visit_fact_lit(&v.fact));
            for (ident, field) in &v.to {
                try_visit!(visitor.visit_ident(*ident));
                try_visit!(visitor.visit_fact_field(field));
            }
        }
        StmtKind::Delete(v) => {
            try_visit!(visitor.visit_fact_lit(&v.fact));
        }
        StmtKind::Emit(v) => {
            try_visit!(visitor.visit_expr(v.expr));
        }
        StmtKind::FunctionCall(v) => {
            try_visit!(visitor.visit_ident(v.ident));
            for &expr in &v.args {
                try_visit!(visitor.visit_expr(expr));
            }
        }
        StmtKind::DebugAssert(v) => {
            try_visit!(visitor.visit_expr(v.expr));
        }
    }
    V::Result::output()
}

/// Walks an expression.
///
/// This performs a DFS.
pub fn walk_expr<'hir, V>(visitor: &mut V, expr: &'hir Expr<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_expr_id(expr.id));
    walk_expr_kind(visitor, &expr.kind);
}

/// Broken out for HIR lowering.
///
/// This performs a DFS.
pub(super) fn walk_expr_kind<'hir, V>(visitor: &mut V, kind: &'hir ExprKind<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    match kind {
        ExprKind::Lit(v) => {
            try_visit!(visitor.visit_lit(v));
        }
        ExprKind::NamedStruct(v) => {
            try_visit!(visitor.visit_ident(v.ident));
            for (ident, expr) in &v.fields {
                try_visit!(visitor.visit_ident(*ident));
                try_visit!(visitor.visit_expr(*expr));
            }
        }
        ExprKind::Ternary(v) => {
            try_visit!(visitor.visit_expr(v.cond));
            try_visit!(visitor.visit_expr(v.true_expr));
            try_visit!(visitor.visit_expr(v.false_expr));
        }
        ExprKind::Intrinsic(v) => match v {
            Intrinsic::Query(fact) => {
                try_visit!(visitor.visit_fact_lit(fact));
            }
            Intrinsic::FactCount(_, _, fact) => {
                try_visit!(visitor.visit_fact_lit(fact));
            }
            Intrinsic::Serialize(expr) | Intrinsic::Deserialize(expr) => {
                try_visit!(visitor.visit_expr(*expr));
            }
        },
        ExprKind::FunctionCall(v) => {
            try_visit!(visitor.visit_ident(v.ident));
            for &arg in &v.args {
                try_visit!(visitor.visit_expr(arg));
            }
        }
        ExprKind::ForeignFunctionCall(v) => {
            try_visit!(visitor.visit_ident(v.module));
            try_visit!(visitor.visit_ident(v.ident));
            for &arg in &v.args {
                try_visit!(visitor.visit_expr(arg));
            }
        }
        ExprKind::Identifier(v) => {
            try_visit!(visitor.visit_ident(*v));
        }
        ExprKind::EnumRef(v) => {
            try_visit!(visitor.visit_ident(v.ident));
            try_visit!(visitor.visit_ident(v.value));
        }
        ExprKind::Add(lhs, rhs)
        | ExprKind::Sub(lhs, rhs)
        | ExprKind::And(lhs, rhs)
        | ExprKind::Or(lhs, rhs) => {
            try_visit!(visitor.visit_expr(*lhs));
            try_visit!(visitor.visit_expr(*rhs));
        }
        ExprKind::Dot(expr, ident) => {
            try_visit!(visitor.visit_expr(*expr));
            try_visit!(visitor.visit_ident(*ident));
        }
        ExprKind::Equal(lhs, rhs)
        | ExprKind::NotEqual(lhs, rhs)
        | ExprKind::GreaterThan(lhs, rhs)
        | ExprKind::LessThan(lhs, rhs)
        | ExprKind::GreaterThanOrEqual(lhs, rhs)
        | ExprKind::LessThanOrEqual(lhs, rhs) => {
            try_visit!(visitor.visit_expr(*lhs));
            try_visit!(visitor.visit_expr(*rhs));
        }
        ExprKind::Negative(expr)
        | ExprKind::Not(expr)
        | ExprKind::Unwrap(expr)
        | ExprKind::CheckUnwrap(expr) => {
            try_visit!(visitor.visit_expr(*expr));
        }
        ExprKind::Is(expr, true | false) => {
            try_visit!(visitor.visit_expr(*expr));
        }
        ExprKind::Block(block, expr) => {
            try_visit!(visitor.visit_block(*block));
            try_visit!(visitor.visit_expr(*expr));
        }
        ExprKind::Substruct(expr, ident) => {
            try_visit!(visitor.visit_expr(*expr));
            try_visit!(visitor.visit_ident(*ident));
        }
        ExprKind::Match(v) => {
            try_visit!(visitor.visit_expr(v.scrutinee));
            for arm in &v.arms {
                match &arm.pattern {
                    MatchPattern::Default => {}
                    MatchPattern::Values(values) => {
                        for &expr in values {
                            try_visit!(visitor.visit_expr(expr));
                        }
                    }
                }
                try_visit!(visitor.visit_expr(arm.expr));
            }
        }
    }
    V::Result::output()
}

/// Walks the literal.
///
/// This performs a DFS.
pub fn walk_lit<'hir, V>(visitor: &mut V, lit: &'hir Lit<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    match &lit.kind {
        LitKind::String(_) | LitKind::Int(_) | LitKind::Bool(_) => {}
        LitKind::Optional(v) => {
            if let Some(v) = v {
                try_visit!(visitor.visit_expr(v));
            }
        }
        LitKind::NamedStruct(v) => {}
        LitKind::Fact(v) => {
            try_visit!(visitor.visit_fact_lit(v));
        }
    }
    V::Result::output()
}

/// Walks the named struct literal.
///
/// This performs a DFS.
pub fn walk_named_struct_lit<'hir, V>(visitor: &mut V, lit: &'hir NamedStruct<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_ident(lit.ident));
    for field in lit.fields {
        try_visit!(visitor.visit_named_struct_lit_field(field));
    }
    V::Result::output()
}

/// Walks the fact literal.
///
/// This performs a DFS.
pub fn walk_fact_lit<'hir, V>(visitor: &mut V, fact: &'hir FactLiteral<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_ident(fact.ident));
    for k in &fact.keys {
        try_visit!(visitor.visit_fact_lit_key(k));
    }
    for v in &fact.vals {
        try_visit!(visitor.visit_fact_lit_val(v));
    }
    V::Result::output()
}

/// Walks a fact field.
///
/// This performs a DFS.
pub fn walk_fact_field<'hir, V>(visitor: &mut V, field: &'hir FactField<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    match field {
        FactField::Expr(expr) => {
            try_visit!(visitor.visit_expr(*expr));
        }
        FactField::Bind => {}
    }
    V::Result::output()
}

/// Walks an effect field.
///
/// This performs a DFS.
pub fn walk_effect_field<'hir, V>(visitor: &mut V, field: &'hir EffectField<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_effect_field_id(field.id));
    match &field.kind {
        EffectFieldKind::Field { ident, ty } => {
            try_visit!(visitor.visit_ident(*ident));
            try_visit!(visitor.visit_vtype(*ty));
        }
        EffectFieldKind::StructRef(ident) => {
            try_visit!(visitor.visit_ident(*ident));
        }
    }
    V::Result::output()
}

/// This performs a DFS.
fn walk_struct_field<'hir, V>(visitor: &mut V, field: &'hir StructField<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_struct_field_id(field.id));
    match &field.kind {
        StructFieldKind::Field { ident, ty } => {
            try_visit!(visitor.visit_ident(*ident));
            try_visit!(visitor.visit_vtype(*ty));
        }
        StructFieldKind::StructRef(ident) => {
            try_visit!(visitor.visit_ident(*ident));
        }
    }
    V::Result::output()
}

/// Walks a specific effect.
///
/// This performs a DFS.
pub fn walk_effect<'hir, V>(visitor: &mut V, def: &'hir EffectDef<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_effect_id(def.id));
    for f in &def.items {
        try_visit!(visitor.visit_effect_field(f));
    }
    V::Result::output()
}

/// Walks a specific enum.
///
/// This performs a DFS.
pub fn walk_enum<'hir, V>(visitor: &mut V, def: &'hir EnumDef<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_enum_id(def.id));
    V::Result::output()
}

/// Walks a specific finish function.
///
/// This performs a DFS.
pub fn walk_finish_func<'hir, V>(visitor: &mut V, def: &'hir FinishFuncDef<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_finish_func_id(def.id));
    for arg in &def.sig.args {
        try_visit!(visitor.visit_finish_func_arg(arg));
    }
    try_visit!(visitor.visit_block(def.block));
    V::Result::output()
}

pub fn walk_finish_func_sig<'hir, V>(visitor: &mut V, sig: &'hir FinishFuncSig<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    for arg in &sig.args {
        try_visit!(visitor.visit_finish_func_arg(arg));
    }
    try_visit!(visitor.visit_vtype(&sig.result));
    V::Result::output()
}

pub fn walk_finish_func_arg<'hir, V>(visitor: &mut V, arg: &'hir FinishFuncArg<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_ident(arg.ident));
    try_visit!(visitor.visit_vtype(arg.ty));
    V::Result::output()
}

/// Walks a specific function.
///
/// This performs a DFS.
pub fn walk_func<'hir, V>(visitor: &mut V, def: &'hir FuncDef<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_func_id(def.id));
    try_visit!(visitor.visit_func_sig(&def.sig));
    try_visit!(visitor.visit_block(def.block));
    V::Result::output()
}

pub fn walk_func_sig<'hir, V>(visitor: &mut V, sig: &'hir FuncSig<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    for arg in &sig.args {
        try_visit!(visitor.visit_func_arg(arg));
    }
    try_visit!(visitor.visit_vtype(&sig.result));
    V::Result::output()
}

pub fn walk_func_arg<'hir, V>(visitor: &mut V, arg: &'hir FuncArg<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_func_arg_id(arg.id));
    try_visit!(visitor.visit_ident(arg.ident));
    try_visit!(visitor.visit_vtype(arg.ty));
    V::Result::output()
}

/// Walks a specific global let.
///
/// This performs a DFS.
pub fn walk_global_let<'hir, V>(visitor: &mut V, def: &'hir GlobalLetDef<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_global_id(def.id));
    try_visit!(visitor.visit_expr(def.expr));
    V::Result::output()
}

/// Walks a specific struct.
///
/// This performs a DFS.
pub fn walk_struct<'hir, V>(visitor: &mut V, def: &'hir StructDef<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_struct_id(def.id));
    for field in &def.items {
        try_visit!(visitor.visit_struct_field(field));
    }
    V::Result::output()
}

pub fn walk_fact<'hir, V>(visitor: &mut V, def: &'hir FactDef<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_fact_id(def.id));
    for k in &def.keys {
        try_visit!(visitor.visit_fact_key(k));
    }
    for v in &def.vals {
        try_visit!(visitor.visit_fact_val(v));
    }
    V::Result::output()
}

pub fn walk_fact_key<'hir, V>(visitor: &mut V, key: &'hir FactKey<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_ident(key.ident));
    try_visit!(visitor.visit_vtype(key.ty));
    try_visit!(visitor.visit_fact_field(&key.expr));
    V::Result::output()
}

/// Walks a fact field.
///
/// This performs a DFS.
pub fn walk_fact_val<'hir, V>(visitor: &mut V, val: &'hir FactVal<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_ident(val.ident));
    try_visit!(visitor.visit_vtype(val.ty));
    try_visit!(visitor.visit_fact_field(&val.expr));
    V::Result::output()
}

pub fn walk_fact_field_expr<'hir, V>(visitor: &mut V, field: &'hir FactFieldExpr<'hir>) -> V::Result
where
    V: Visitor<'hir>,
{
    match field {
        FactFieldExpr::Expr(expr) => {
            try_visit!(visitor.visit_expr(*expr));
        }
        FactFieldExpr::Bind => {}
    }
    V::Result::output()
}

pub fn walk_struct_field_expr<'hir, V>(
    visitor: &mut V,
    field: &'hir StructFieldExpr<'hir>,
) -> V::Result
where
    V: Visitor<'hir>,
{
    match field {
        StructFieldExpr::Expr(expr) => {
            try_visit!(visitor.visit_expr(*expr));
        }
        StructFieldExpr::Bind => {}
    }
    V::Result::output()
}
