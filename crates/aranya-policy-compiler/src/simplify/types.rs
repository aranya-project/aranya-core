use serde::{Deserialize, Serialize};

use crate::{
    arena::Arena,
    hir::{self, IdentId, Pure, TextRef},
    typecheck::types::TypeRef,
};

macro_rules! new_key_type {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident;
    ) => {
        $crate::arena::new_key_type! {
            $(#[$meta])*
            $vis struct $name;
        }
    };
}

/// Simplified HIR root.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Hir {
    pub exprs: Arena<ExprId, Expr>,
    pub blocks: Arena<BlockId, Block>,
}

impl Hir {
    pub fn index(&self, id: ExprId) -> &Expr {
        &self.exprs[id]
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Expr {
    pub id: ExprId,
    pub kind: ExprKind,
    pub ty: TypeRef,
    pub pure: Pure,
}

new_key_type! {
    pub struct ExprId;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ExprKind {
    // Structured control
    Block(BlockId),
    If {
        cond: ExprId,
        then_expr: ExprId,
        else_expr: ExprId,
    },
    Return(ExprId),
    Binary(hir::BinOp, ExprId, ExprId),
    Unary(hir::UnaryOp, ExprId),
    Is(ExprId, bool),
    LitInt(i64),
    LitBool(bool),
    LitString(TextRef),
    // Structured values
    NamedStruct(NamedStruct),
    // Simple values and selectors
    Ident(IdentId),
    Dot(Dot),
    EnumRef(EnumRef),
    Substruct(Substruct),
    Cast(Cast),
    Intrinsic(Intrinsic),
    // Statement-to-expression forms
    Let(Let),
    Check(Check),
    DebugAssert(DebugAssert),
    Discard(Discard),

    // Calls and side-effecting ops (baseline shape)
    ActionCall(ActionCall),
    FunctionCall(FunctionCall),
    ForeignFunctionCall(ForeignFunctionCall),
    Publish(Publish),
    Emit(Emit),

    // Facts (baseline shape)
    Create(Create),
    Update(Update),
    Delete(Delete),

    // Temporary passthrough for unhandled expression forms
    Hir(hir::ExprId),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub id: BlockId,
    pub exprs: Vec<ExprId>,
}

new_key_type! {
    pub struct BlockId;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dot {
    pub expr: ExprId,
    pub ident: IdentId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnumRef {
    pub ident: IdentId,
    pub value: IdentId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Substruct {
    pub expr: ExprId,
    pub ident: IdentId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cast {
    pub expr: ExprId,
    pub ident: IdentId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Intrinsic {
    Query(FactLiteral),
    FactCount(hir::FactCountType, i64, FactLiteral),
    Serialize(ExprId),
    Deserialize(ExprId),
    Todo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Let {
    pub ident: IdentId,
    pub value: ExprId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Check {
    pub expr: ExprId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DebugAssert {
    pub expr: ExprId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Discard {
    pub expr: ExprId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionCall {
    pub ident: IdentId,
    pub args: Vec<ExprId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FunctionCall {
    pub ident: IdentId,
    pub args: Vec<ExprId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForeignFunctionCall {
    pub module: IdentId,
    pub ident: IdentId,
    pub args: Vec<ExprId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Publish {
    pub value: NamedStruct,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Emit {
    pub value: NamedStruct,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Create {
    pub fact: FactLiteral,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Update {
    pub fact: FactLiteral,
    pub to: Vec<FactFieldExpr>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Delete {
    pub fact: FactLiteral,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FactLiteral {
    pub ident: IdentId,
    pub keys: Vec<FactFieldExpr>,
    pub vals: Vec<FactFieldExpr>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FactFieldExpr {
    pub ident: IdentId,
    pub expr: FactField,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FactField {
    Expr(ExprId),
    Bind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NamedStruct {
    pub ident: IdentId,
    pub fields: Vec<NamedFieldExpr>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NamedFieldExpr {
    pub ident: IdentId,
    pub expr: ExprId,
    /// Optional resolved field id from HIR for faster MIR lowering
    pub resolved: Option<ResolvedField>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ResolvedField {
    Cmd(hir::CmdFieldId),
    Effect(hir::EffectFieldId),
    Struct(hir::StructFieldId),
}
