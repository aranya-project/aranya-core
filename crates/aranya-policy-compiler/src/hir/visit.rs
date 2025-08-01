#[cfg(test)]
mod tests;

use std::{convert::Infallible, ops::ControlFlow};

use crate::hir::{
    arena::IdentRef,
    hir::{
        ActionArg, ActionArgId, ActionDef, ActionId, ActionSig, Block, BlockId, CmdDef, CmdField,
        CmdFieldId, CmdFieldKind, CmdId, EffectDef, EffectField, EffectFieldId, EffectFieldKind,
        EffectId, EnumDef, EnumId, Expr, ExprId, ExprKind, FactDef, FactField, FactFieldExpr,
        FactId, FactKey, FactKeyId, FactLiteral, FactVal, FactValId, FinishFuncArg,
        FinishFuncArgId, FinishFuncDef, FinishFuncId, FinishFuncSig, FuncArg, FuncArgId, FuncDef,
        FuncId, FuncSig, GlobalId, GlobalLetDef, Hir, Ident, IdentId, Intrinsic, Lit, LitKind,
        MatchPattern, NamedStruct, Stmt, StmtId, StmtKind, StructDef, StructField, StructFieldExpr,
        StructFieldId, StructFieldKind, StructId, VType, VTypeId, VTypeKind,
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

// TODO(eric): Use autoref specialization to combine this with
// `try_visit`. Specialize on `Index`.
macro_rules! try_visit_by_id {
    // Visiting some type via its ID.
    ($visitor:ident . $f:ident ($id:expr)) => {
        try_visit!($visitor.$f(::std::ops::Index::index($visitor.hir(), $id,)))
    };
}
pub(crate) use try_visit_by_id;

/// Visits HIR nodes.
///
/// # Usage
pub(crate) trait Visitor<'hir>: Sized {
    /// The result from a "visit_" method.
    type Result: VisitorResult;

    /// Returns the HIR being visited.
    fn hir(&self) -> &'hir Hir;

    /// Visits all the top-level items.
    fn visit_all(&mut self) -> Self::Result {
        for (_, def) in &self.hir().actions {
            try_visit!(self.visit_action(def));
        }
        for (_, def) in &self.hir().cmds {
            try_visit!(self.visit_cmd(def));
        }
        for (_, def) in &self.hir().effects {
            try_visit!(self.visit_effect_def(def));
        }
        for (_, def) in &self.hir().enums {
            try_visit!(self.visit_enum_def(def));
        }
        for (_, def) in &self.hir().facts {
            try_visit!(self.visit_fact_def(def));
        }
        for (_, def) in &self.hir().finish_funcs {
            try_visit!(self.visit_finish_func_def(def));
        }
        for (_, def) in &self.hir().funcs {
            try_visit!(self.visit_func_def(def));
        }
        for (_, def) in &self.hir().global_lets {
            try_visit!(self.visit_global_def(def));
        }
        for (_, def) in &self.hir().structs {
            try_visit!(self.visit_struct_def(def));
        }
        Self::Result::output()
    }

    //
    // Actions
    //

    fn visit_action(&mut self, def: &'hir ActionDef) -> Self::Result {
        walk_action(self, def)
    }
    fn visit_action_id(&mut self, _id: ActionId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_action_sig(&mut self, sig: &'hir ActionSig) -> Self::Result {
        walk_action_sig(self, sig)
    }
    fn visit_action_arg(&mut self, arg: &'hir ActionArg) -> Self::Result {
        walk_action_arg(self, arg)
    }
    fn visit_action_arg_id(&mut self, _id: ActionArgId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_action_body(&mut self, block: &'hir Block) -> Self::Result {
        walk_block(self, block)
    }

    //
    // Commands
    //

    fn visit_cmd(&mut self, def: &'hir CmdDef) -> Self::Result {
        walk_cmd(self, def)
    }
    fn visit_cmd_id(&mut self, _id: CmdId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_cmd_field(&mut self, field: &'hir CmdField) -> Self::Result {
        walk_cmd_field(self, field)
    }
    fn visit_cmd_field_id(&mut self, _id: CmdFieldId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_cmd_seal_block(&mut self, block: &'hir Block) -> Self::Result {
        walk_block(self, block)
    }
    fn visit_cmd_open_block(&mut self, block: &'hir Block) -> Self::Result {
        walk_block(self, block)
    }
    fn visit_cmd_policy_block(&mut self, block: &'hir Block) -> Self::Result {
        walk_block(self, block)
    }
    fn visit_cmd_recall_block(&mut self, block: &'hir Block) -> Self::Result {
        walk_block(self, block)
    }

    //
    // Effects
    //

    fn visit_effect_def(&mut self, def: &'hir EffectDef) -> Self::Result {
        walk_effect(self, def)
    }
    fn visit_effect_id(&mut self, _id: EffectId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_effect_field(&mut self, field: &'hir EffectField) -> Self::Result {
        walk_effect_field(self, field)
    }
    fn visit_effect_field_id(&mut self, _id: EffectFieldId) -> Self::Result {
        Self::Result::output()
    }

    //
    // Enums
    //

    fn visit_enum_def(&mut self, def: &'hir EnumDef) -> Self::Result {
        walk_enum(self, def)
    }
    fn visit_enum_id(&mut self, _id: EnumId) -> Self::Result {
        Self::Result::output()
    }

    //
    // Facts
    //

    fn visit_fact_def(&mut self, def: &'hir FactDef) -> Self::Result {
        walk_fact(self, def)
    }
    fn visit_fact_id(&mut self, _id: FactId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_fact_key(&mut self, key: &'hir FactKey) -> Self::Result {
        walk_fact_key(self, key)
    }
    fn visit_fact_key_id(&mut self, _id: FactKeyId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_fact_val(&mut self, val: &'hir FactVal) -> Self::Result {
        walk_fact_val(self, val)
    }
    fn visit_fact_val_id(&mut self, _id: FactValId) -> Self::Result {
        Self::Result::output()
    }

    //
    // Finish functions
    //

    fn visit_finish_func_def(&mut self, def: &'hir FinishFuncDef) -> Self::Result {
        walk_finish_func(self, def)
    }
    fn visit_finish_func_id(&mut self, _id: FinishFuncId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_finish_func_sig(&mut self, sig: &'hir FinishFuncSig) -> Self::Result {
        walk_finish_func_sig(self, sig)
    }
    fn visit_finish_func_arg(&mut self, arg: &'hir FinishFuncArg) -> Self::Result {
        walk_finish_func_arg(self, arg)
    }
    fn visit_finish_func_arg_id(&mut self, _id: FinishFuncArgId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_finish_func_body(&mut self, block: &'hir Block) -> Self::Result {
        walk_block(self, block)
    }

    //
    // Functions
    //

    fn visit_func_def(&mut self, _def: &'hir FuncDef) -> Self::Result {
        walk_func(self, _def)
    }
    fn visit_func_id(&mut self, _id: FuncId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_func_sig(&mut self, sig: &'hir FuncSig) -> Self::Result {
        walk_func_sig(self, sig)
    }
    fn visit_func_arg(&mut self, arg: &'hir FuncArg) -> Self::Result {
        walk_func_arg(self, arg)
    }
    fn visit_func_arg_id(&mut self, _id: FuncArgId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_func_result(&mut self, vtype: &'hir VType) -> Self::Result {
        walk_vtype(self, vtype)
    }
    fn visit_func_body(&mut self, block: &'hir Block) -> Self::Result {
        walk_block(self, block)
    }

    //
    // Globals
    //

    fn visit_global_def(&mut self, def: &'hir GlobalLetDef) -> Self::Result {
        walk_global_let(self, def)
    }
    fn visit_global_id(&mut self, _id: GlobalId) -> Self::Result {
        Self::Result::output()
    }

    //
    // Structs
    //

    fn visit_struct_def(&mut self, def: &'hir StructDef) -> Self::Result {
        walk_struct(self, def)
    }
    fn visit_struct_id(&mut self, _id: StructId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_struct_field(&mut self, field: &'hir StructField) -> Self::Result {
        walk_struct_field(self, field)
    }
    fn visit_struct_field_id(&mut self, _id: StructFieldId) -> Self::Result {
        Self::Result::output()
    }

    //
    // Ident
    //

    fn visit_ident(&mut self, ident: &'hir Ident) -> Self::Result {
        walk_ident(self, ident)
    }
    fn visit_ident_id(&mut self, _id: IdentId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_ident_ident(&mut self, _ident: IdentRef) -> Self::Result {
        Self::Result::output()
    }

    //
    // Blocks
    //

    fn visit_block(&mut self, block: &'hir Block) -> Self::Result {
        walk_block(self, block)
    }
    fn visit_block_id(&mut self, _id: BlockId) -> Self::Result {
        Self::Result::output()
    }

    fn visit_expr(&mut self, expr: &'hir Expr) -> Self::Result {
        walk_expr(self, expr)
    }
    fn visit_expr_id(&mut self, _id: ExprId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_expr_kind(&mut self, kind: &'hir ExprKind) -> Self::Result {
        walk_expr_kind(self, kind)
    }

    //
    // Statements
    //

    fn visit_stmt(&mut self, stmt: &'hir Stmt) -> Self::Result {
        walk_stmt(self, stmt)
    }
    fn visit_stmt_id(&mut self, _id: StmtId) -> Self::Result {
        Self::Result::output()
    }
    fn visit_stmt_kind(&mut self, kind: &'hir StmtKind) -> Self::Result {
        walk_stmt_kind(self, kind)
    }

    //
    // VType
    //

    fn visit_vtype(&mut self, vtype: &'hir VType) -> Self::Result {
        walk_vtype(self, vtype)
    }
    fn visit_vtype_id(&mut self, _id: VTypeId) -> Self::Result {
        Self::Result::output()
    }

    //
    // Literals
    //

    fn visit_lit(&mut self, lit: &'hir Lit) -> Self::Result {
        walk_lit(self, lit)
    }

    fn visit_named_struct_lit(&mut self, lit: &'hir NamedStruct) -> Self::Result {
        walk_named_struct_lit(self, lit)
    }
    fn visit_named_struct_lit_field(&mut self, field: &'hir StructFieldExpr) -> Self::Result {
        walk_struct_field_expr(self, field)
    }

    fn visit_fact_lit(&mut self, fact: &'hir FactLiteral) -> Self::Result {
        walk_fact_lit(self, fact)
    }
    fn visit_fact_lit_key(&mut self, key: &'hir FactFieldExpr) -> Self::Result {
        walk_fact_field_expr(self, key)
    }
    fn visit_fact_lit_val(&mut self, val: &'hir FactFieldExpr) -> Self::Result {
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
            Err(e) => Err(e),
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
pub fn walk_action<'hir, V>(visitor: &mut V, def: &'hir ActionDef) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_action_id(def.id));
    try_visit!(visitor.visit_action_sig(&def.sig));
    try_visit_by_id!(visitor.visit_action_body(def.block));
    V::Result::output()
}

pub fn walk_action_sig<'hir, V>(visitor: &mut V, sig: &'hir ActionSig) -> V::Result
where
    V: Visitor<'hir>,
{
    for &id in &sig.args {
        try_visit_by_id!(visitor.visit_action_arg(id));
    }
    V::Result::output()
}

/// Walks a specific action argument.
///
/// This performs a DFS.
pub fn walk_action_arg<'hir, V>(visitor: &mut V, arg: &'hir ActionArg) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_action_arg_id(arg.id));
    try_visit_by_id!(visitor.visit_ident(arg.ident));
    try_visit_by_id!(visitor.visit_vtype(arg.ty));
    V::Result::output()
}

/// Walks a specific command.
///
/// This performs a DFS.
pub fn walk_cmd<'hir, V>(visitor: &mut V, def: &'hir CmdDef) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_cmd_id(def.id));
    for &id in &def.fields {
        try_visit_by_id!(visitor.visit_cmd_field(id));
    }
    try_visit_by_id!(visitor.visit_cmd_seal_block(def.seal));
    try_visit_by_id!(visitor.visit_cmd_open_block(def.open));
    try_visit_by_id!(visitor.visit_cmd_policy_block(def.policy));
    try_visit_by_id!(visitor.visit_cmd_recall_block(def.recall));
    V::Result::output()
}

pub fn walk_cmd_field<'hir, V>(visitor: &mut V, field: &'hir CmdField) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_cmd_field_id(field.id));
    match &field.kind {
        CmdFieldKind::Field { ident, ty } => {
            try_visit_by_id!(visitor.visit_ident(*ident));
            try_visit_by_id!(visitor.visit_vtype(*ty));
        }
        CmdFieldKind::StructRef(ident) => {
            try_visit_by_id!(visitor.visit_ident(*ident));
        }
    }
    V::Result::output()
}

/// Walks an identifier.
///
/// This performs a DFS.
pub fn walk_ident<'hir, V>(visitor: &mut V, ident: &'hir Ident) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_ident_id(ident.id));
    try_visit!(visitor.visit_ident_ident(ident.ident));
    V::Result::output()
}

/// Walks a variable type.
///
/// This performs a DFS.
pub fn walk_vtype<'hir, V>(visitor: &mut V, ty: &'hir VType) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_vtype_id(ty.id));
    match &ty.kind {
        VTypeKind::String | VTypeKind::Bytes | VTypeKind::Int | VTypeKind::Bool | VTypeKind::Id => {
        }
        VTypeKind::Struct(v) => {
            try_visit_by_id!(visitor.visit_ident(*v));
        }
        VTypeKind::Enum(v) => {
            try_visit_by_id!(visitor.visit_ident(*v));
        }
        VTypeKind::Optional(v) => {
            try_visit_by_id!(visitor.visit_vtype(*v));
        }
    }
    V::Result::output()
}

/// Walks a block.
///
/// This performs a DFS.
pub fn walk_block<'hir, V>(visitor: &mut V, block: &'hir Block) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_block_id(block.id));
    for &id in &block.stmts {
        try_visit_by_id!(visitor.visit_stmt(id));
    }
    V::Result::output()
}

/// Walks a statement.
///
/// This performs a DFS.
pub fn walk_stmt<'hir, V>(visitor: &mut V, stmt: &'hir Stmt) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_stmt_id(stmt.id));
    try_visit!(visitor.visit_stmt_kind(&stmt.kind));
    V::Result::output()
}

/// Walks a statement.
///
/// This performs a DFS.
pub fn walk_stmt_kind<'hir, V>(visitor: &mut V, kind: &'hir StmtKind) -> V::Result
where
    V: Visitor<'hir>,
{
    match kind {
        StmtKind::Let(v) => {
            try_visit_by_id!(visitor.visit_ident(v.ident));
            try_visit_by_id!(visitor.visit_expr(v.expr));
        }
        StmtKind::Check(v) => {
            try_visit_by_id!(visitor.visit_expr(v.expr));
        }
        StmtKind::Match(v) => {
            try_visit_by_id!(visitor.visit_expr(v.expr));
            for arm in &v.arms {
                match &arm.pattern {
                    MatchPattern::Default => {}
                    MatchPattern::Values(values) => {
                        for &expr in values {
                            try_visit_by_id!(visitor.visit_expr(expr));
                        }
                    }
                }
                try_visit_by_id!(visitor.visit_block(arm.block));
            }
        }
        StmtKind::If(v) => {
            for branch in &v.branches {
                try_visit_by_id!(visitor.visit_expr(branch.expr));
                try_visit_by_id!(visitor.visit_block(branch.block));
            }
            if let Some(else_block) = v.else_block {
                try_visit_by_id!(visitor.visit_block(else_block));
            }
        }
        StmtKind::Finish(block) => {
            try_visit_by_id!(visitor.visit_block(*block));
        }
        StmtKind::Map(v) => {
            try_visit!(visitor.visit_fact_lit(&v.fact));
            try_visit_by_id!(visitor.visit_ident(v.ident));
            try_visit_by_id!(visitor.visit_block(v.block));
        }
        StmtKind::Return(v) => {
            try_visit_by_id!(visitor.visit_expr(v.expr));
        }
        StmtKind::ActionCall(v) => {
            try_visit_by_id!(visitor.visit_ident(v.ident));
            for &expr in &v.args {
                try_visit_by_id!(visitor.visit_expr(expr));
            }
        }
        StmtKind::Publish(v) => {
            try_visit_by_id!(visitor.visit_expr(v.expr));
        }
        StmtKind::Create(v) => {
            try_visit!(visitor.visit_fact_lit(&v.fact));
        }
        StmtKind::Update(v) => {
            try_visit!(visitor.visit_fact_lit(&v.fact));
            for field in &v.to {
                try_visit_by_id!(visitor.visit_ident(field.ident));
                match &field.expr {
                    FactField::Expr(expr) => {
                        try_visit_by_id!(visitor.visit_expr(*expr));
                    }
                    FactField::Bind => {}
                }
            }
        }
        StmtKind::Delete(v) => {
            try_visit!(visitor.visit_fact_lit(&v.fact));
        }
        StmtKind::Emit(v) => {
            try_visit_by_id!(visitor.visit_expr(v.expr));
        }
        StmtKind::FunctionCall(v) => {
            try_visit_by_id!(visitor.visit_ident(v.ident));
            for &expr in &v.args {
                try_visit_by_id!(visitor.visit_expr(expr));
            }
        }
        StmtKind::DebugAssert(v) => {
            try_visit_by_id!(visitor.visit_expr(v.expr));
        }
    }
    V::Result::output()
}

/// Walks an expression.
///
/// This performs a DFS.
pub fn walk_expr<'hir, V>(visitor: &mut V, expr: &'hir Expr) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_expr_id(expr.id));
    try_visit!(visitor.visit_expr_kind(&expr.kind));
    V::Result::output()
}

/// Broken out for HIR lowering.
///
/// This performs a DFS.
pub fn walk_expr_kind<'hir, V>(visitor: &mut V, kind: &'hir ExprKind) -> V::Result
where
    V: Visitor<'hir>,
{
    match kind {
        ExprKind::Lit(v) => {
            try_visit!(visitor.visit_lit(v));
        }
        ExprKind::Ternary(v) => {
            try_visit_by_id!(visitor.visit_expr(v.cond));
            try_visit_by_id!(visitor.visit_expr(v.true_expr));
            try_visit_by_id!(visitor.visit_expr(v.false_expr));
        }
        ExprKind::Intrinsic(v) => match v {
            Intrinsic::Query(fact) => {
                try_visit!(visitor.visit_fact_lit(fact));
            }
            Intrinsic::FactCount(_, _, fact) => {
                try_visit!(visitor.visit_fact_lit(fact));
            }
            Intrinsic::Serialize(expr) | Intrinsic::Deserialize(expr) => {
                try_visit_by_id!(visitor.visit_expr(*expr));
            }
        },
        ExprKind::FunctionCall(v) => {
            try_visit_by_id!(visitor.visit_ident(v.ident));
            for &arg in &v.args {
                try_visit_by_id!(visitor.visit_expr(arg));
            }
        }
        ExprKind::ForeignFunctionCall(v) => {
            try_visit_by_id!(visitor.visit_ident(v.module));
            try_visit_by_id!(visitor.visit_ident(v.ident));
            for &arg in &v.args {
                try_visit_by_id!(visitor.visit_expr(arg));
            }
        }
        ExprKind::Identifier(v) => {
            try_visit_by_id!(visitor.visit_ident(*v));
        }
        ExprKind::EnumRef(v) => {
            try_visit_by_id!(visitor.visit_ident(v.ident));
            try_visit_by_id!(visitor.visit_ident(v.value));
        }
        ExprKind::Dot(expr, ident) => {
            try_visit_by_id!(visitor.visit_expr(*expr));
            try_visit_by_id!(visitor.visit_ident(*ident));
        }
        ExprKind::Binary(_, lhs, rhs) => {
            try_visit_by_id!(visitor.visit_expr(*lhs));
            try_visit_by_id!(visitor.visit_expr(*rhs));
        }
        ExprKind::Unary(_, expr) => {
            try_visit_by_id!(visitor.visit_expr(*expr));
        }
        ExprKind::Is(expr, true | false) => {
            try_visit_by_id!(visitor.visit_expr(*expr));
        }
        ExprKind::Block(block, expr) => {
            try_visit_by_id!(visitor.visit_block(*block));
            try_visit_by_id!(visitor.visit_expr(*expr));
        }
        ExprKind::Substruct(expr, ident) => {
            try_visit_by_id!(visitor.visit_expr(*expr));
            try_visit_by_id!(visitor.visit_ident(*ident));
        }
        ExprKind::Match(v) => {
            try_visit_by_id!(visitor.visit_expr(v.scrutinee));
            for arm in &v.arms {
                match &arm.pattern {
                    MatchPattern::Default => {}
                    MatchPattern::Values(values) => {
                        for &expr in values {
                            try_visit_by_id!(visitor.visit_expr(expr));
                        }
                    }
                }
                try_visit_by_id!(visitor.visit_expr(arm.expr));
            }
        }
    }
    V::Result::output()
}

/// Walks the literal.
///
/// This performs a DFS.
pub fn walk_lit<'hir, V>(visitor: &mut V, lit: &'hir Lit) -> V::Result
where
    V: Visitor<'hir>,
{
    match &lit.kind {
        LitKind::String(_) | LitKind::Int(_) | LitKind::Bool(_) => {}
        LitKind::Optional(v) => {
            if let Some(v) = v {
                try_visit_by_id!(visitor.visit_expr(*v));
            }
        }
        LitKind::NamedStruct(v) => {
            try_visit!(visitor.visit_named_struct_lit(v));
        }
        LitKind::Fact(v) => {
            try_visit!(visitor.visit_fact_lit(v));
        }
    }
    V::Result::output()
}

/// Walks the named struct literal.
///
/// This performs a DFS.
pub fn walk_named_struct_lit<'hir, V>(visitor: &mut V, lit: &'hir NamedStruct) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit_by_id!(visitor.visit_ident(lit.ident));
    for field in &lit.fields {
        try_visit!(visitor.visit_named_struct_lit_field(field));
    }
    V::Result::output()
}

/// Walks the fact literal.
///
/// This performs a DFS.
pub fn walk_fact_lit<'hir, V>(visitor: &mut V, fact: &'hir FactLiteral) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit_by_id!(visitor.visit_ident(fact.ident));
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
pub fn walk_fact_field<'hir, V>(visitor: &mut V, field: &'hir FactField) -> V::Result
where
    V: Visitor<'hir>,
{
    match field {
        FactField::Expr(expr) => {
            try_visit_by_id!(visitor.visit_expr(*expr));
        }
        FactField::Bind => {}
    }
    V::Result::output()
}

/// Walks an effect field.
///
/// This performs a DFS.
pub fn walk_effect_field<'hir, V>(visitor: &mut V, field: &'hir EffectField) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_effect_field_id(field.id));
    match &field.kind {
        EffectFieldKind::Field { ident, ty } => {
            try_visit_by_id!(visitor.visit_ident(*ident));
            try_visit_by_id!(visitor.visit_vtype(*ty));
        }
        EffectFieldKind::StructRef(ident) => {
            try_visit_by_id!(visitor.visit_ident(*ident));
        }
    }
    V::Result::output()
}

/// This performs a DFS.
pub fn walk_struct_field<'hir, V>(visitor: &mut V, field: &'hir StructField) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_struct_field_id(field.id));
    match &field.kind {
        StructFieldKind::Field { ident, ty } => {
            try_visit_by_id!(visitor.visit_ident(*ident));
            try_visit_by_id!(visitor.visit_vtype(*ty));
        }
        StructFieldKind::StructRef(ident) => {
            try_visit_by_id!(visitor.visit_ident(*ident));
        }
    }
    V::Result::output()
}

/// Walks a specific effect.
///
/// This performs a DFS.
pub fn walk_effect<'hir, V>(visitor: &mut V, def: &'hir EffectDef) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_effect_id(def.id));
    for &id in &def.items {
        try_visit_by_id!(visitor.visit_effect_field(id));
    }
    V::Result::output()
}

/// Walks a specific enum.
///
/// This performs a DFS.
pub fn walk_enum<'hir, V>(visitor: &mut V, def: &'hir EnumDef) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_enum_id(def.id));
    V::Result::output()
}

/// Walks a specific finish function.
///
/// This performs a DFS.
pub fn walk_finish_func<'hir, V>(visitor: &mut V, def: &'hir FinishFuncDef) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_finish_func_id(def.id));
    try_visit!(visitor.visit_finish_func_sig(&def.sig));
    try_visit_by_id!(visitor.visit_block(def.block));
    V::Result::output()
}

pub fn walk_finish_func_sig<'hir, V>(visitor: &mut V, sig: &'hir FinishFuncSig) -> V::Result
where
    V: Visitor<'hir>,
{
    for &id in &sig.args {
        try_visit_by_id!(visitor.visit_finish_func_arg(id));
    }
    V::Result::output()
}

pub fn walk_finish_func_arg<'hir, V>(visitor: &mut V, arg: &'hir FinishFuncArg) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit_by_id!(visitor.visit_ident(arg.ident));
    try_visit_by_id!(visitor.visit_vtype(arg.ty));
    V::Result::output()
}

/// Walks a specific function.
///
/// This performs a DFS.
pub fn walk_func<'hir, V>(visitor: &mut V, def: &'hir FuncDef) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_func_id(def.id));
    try_visit!(visitor.visit_func_sig(&def.sig));
    try_visit_by_id!(visitor.visit_block(def.block));
    V::Result::output()
}

pub fn walk_func_sig<'hir, V>(visitor: &mut V, sig: &'hir FuncSig) -> V::Result
where
    V: Visitor<'hir>,
{
    for &id in &sig.args {
        try_visit_by_id!(visitor.visit_func_arg(id));
    }
    try_visit_by_id!(visitor.visit_vtype(sig.result));
    V::Result::output()
}

pub fn walk_func_arg<'hir, V>(visitor: &mut V, arg: &'hir FuncArg) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_func_arg_id(arg.id));
    try_visit_by_id!(visitor.visit_ident(arg.ident));
    try_visit_by_id!(visitor.visit_vtype(arg.ty));
    V::Result::output()
}

/// Walks a specific global let.
///
/// This performs a DFS.
pub fn walk_global_let<'hir, V>(visitor: &mut V, def: &'hir GlobalLetDef) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_global_id(def.id));
    try_visit_by_id!(visitor.visit_expr(def.expr));
    V::Result::output()
}

/// Walks a specific struct.
///
/// This performs a DFS.
pub fn walk_struct<'hir, V>(visitor: &mut V, def: &'hir StructDef) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_struct_id(def.id));
    for &id in &def.items {
        try_visit_by_id!(visitor.visit_struct_field(id));
    }
    V::Result::output()
}

pub fn walk_fact<'hir, V>(visitor: &mut V, def: &'hir FactDef) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_fact_id(def.id));
    for &id in &def.keys {
        try_visit_by_id!(visitor.visit_fact_key(id));
    }
    for &id in &def.vals {
        try_visit_by_id!(visitor.visit_fact_val(id));
    }
    V::Result::output()
}

pub fn walk_fact_key<'hir, V>(visitor: &mut V, key: &'hir FactKey) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_fact_key_id(key.id));
    try_visit_by_id!(visitor.visit_ident(key.ident));
    try_visit_by_id!(visitor.visit_vtype(key.ty));
    V::Result::output()
}

/// Walks a fact field.
///
/// This performs a DFS.
pub fn walk_fact_val<'hir, V>(visitor: &mut V, val: &'hir FactVal) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_fact_val_id(val.id));
    try_visit_by_id!(visitor.visit_ident(val.ident));
    try_visit_by_id!(visitor.visit_vtype(val.ty));
    V::Result::output()
}

pub fn walk_fact_field_expr<'hir, V>(visitor: &mut V, field: &'hir FactFieldExpr) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit_by_id!(visitor.visit_ident(field.ident));
    match &field.expr {
        FactField::Expr(expr) => {
            try_visit_by_id!(visitor.visit_expr(*expr));
        }
        FactField::Bind => {}
    }
    V::Result::output()
}

pub fn walk_struct_field_expr<'hir, V>(visitor: &mut V, field: &'hir StructFieldExpr) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit_by_id!(visitor.visit_ident(field.ident));
    try_visit_by_id!(visitor.visit_expr(field.expr));
    V::Result::output()
}
