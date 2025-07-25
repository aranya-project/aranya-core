use std::{fmt, hash::Hash};

use aranya_policy_ast::{self as ast};
use slotmap::SlotMap;

/// High-level Intermediate Representation (HIR).
///
/// The HIR is a simplified, desugared representation of the
/// [`Policy`][ast::Policy] AST that makes semantic analysis and
/// code generation easier. It stores all policy definitions in
/// arena-allocated collections indexed by typed IDs.
#[derive(Clone, Default, Debug)]
pub(crate) struct Hir {
    pub actions: SlotMap<ActionId, ActionDef>,
    pub action_args: SlotMap<ActionArgId, ActionArg>,
    pub cmds: SlotMap<CmdId, CmdDef>,
    pub cmd_fields: SlotMap<CmdFieldId, CmdField>,
    pub effects: SlotMap<EffectId, EffectDef>,
    pub effect_fields: SlotMap<EffectFieldId, EffectField>,
    pub enums: SlotMap<EnumId, EnumDef>,
    pub facts: SlotMap<FactId, FactDef>,
    pub fact_keys: SlotMap<FactKeyId, FactKey>,
    pub fact_vals: SlotMap<FactValId, FactVal>,
    pub finish_funcs: SlotMap<FinishFuncId, FinishFuncDef>,
    pub finish_func_args: SlotMap<FinishFuncArgId, FinishFuncArg>,
    pub funcs: SlotMap<FuncId, FuncDef>,
    pub func_args: SlotMap<FuncArgId, FuncArg>,
    pub global_lets: SlotMap<GlobalId, GlobalLetDef>,
    pub structs: SlotMap<StructId, StructDef>,
    pub struct_fields: SlotMap<StructFieldId, StructField>,
    pub stmts: SlotMap<StmtId, Stmt>,
    pub exprs: SlotMap<ExprId, Expr>,
    pub idents: SlotMap<IdentId, Ident>,
    pub blocks: SlotMap<BlockId, Block>,
    pub types: SlotMap<VTypeId, VType>,
}

pub(crate) trait Node {
    type Id: fmt::Debug;
}

/// An identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Ident {
    pub id: IdentId,
    pub ident: ast::Identifier,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VType {
    pub id: VTypeId,
    pub kind: VTypeKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum VTypeKind {
    String,
    Bytes,
    Int,
    Bool,
    Id,
    Struct(IdentId),
    Enum(IdentId),
    Optional(VTypeId),
}

/// An expression.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Expr {
    pub id: ExprId,
    pub kind: ExprKind,
}

/// An expression.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ExprKind {
    /// An integer literal.
    Int,
    /// A text string.
    String,
    /// A boolean literal.
    Bool,
    /// An optional literal.
    Optional(Option<ExprId>),
    /// A named struct literal.
    NamedStruct(NamedStruct),
    InternalFunction(InternalFunction),
    FunctionCall(FunctionCall),
    ForeignFunctionCall(ForeignFunctionCall),
    Identifier(IdentId),
    EnumReference(EnumReference),
    Add(ExprId, ExprId),
    Sub(ExprId, ExprId),
    And(ExprId, ExprId),
    Or(ExprId, ExprId),
    Dot(ExprId, IdentId),
    Equal(ExprId, ExprId),
    NotEqual(ExprId, ExprId),
    GreaterThan(ExprId, ExprId),
    LessThan(ExprId, ExprId),
    GreaterThanOrEqual(ExprId, ExprId),
    LessThanOrEqual(ExprId, ExprId),
    Negative(ExprId),
    Not(ExprId),
    Unwrap(ExprId),
    CheckUnwrap(ExprId),
    Is(ExprId, bool),
    Block(BlockId, ExprId),
    Substruct(ExprId, IdentId),
    Match(ExprId),
}

/// A named struct.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NamedStruct {
    pub ident: IdentId,
    pub fields: Vec<(IdentId, ExprId)>,
}

/// How many facts to expect when counting
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum FactCountType {
    /// Up to
    UpTo,
    /// At least
    AtLeast,
    /// At most
    AtMost,
    /// Exactly
    Exactly,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum InternalFunction {
    Query(FactLiteral),
    Exists(FactLiteral),
    FactCount(FactCountType, i64, FactLiteral),
    If(ExprId, ExprId, ExprId),
    Serialize(ExprId),
    Deserialize(ExprId),
}

/// A function call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FunctionCall {
    pub ident: IdentId,
    pub args: Vec<ExprId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ForeignFunctionCall {
    pub module: IdentId,
    pub ident: IdentId,
    pub args: Vec<ExprId>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct EnumReference {
    pub ident: IdentId,
    pub value: IdentId,
}

/// A named struct literal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FactLiteral {
    pub ident: IdentId,
    pub keys: Vec<(IdentId, FactField)>,
    pub vals: Vec<(IdentId, FactField)>,
}

/// A statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Stmt {
    pub id: StmtId,
    pub kind: StmtKind,
}

/// The kind of a statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StmtKind {
    Let(LetStmt),
    Check(CheckStmt),
    Match(MatchStmt),
    If(IfStmt),
    Finish(BlockId),
    Map(MapStmt),
    Return(ReturnStmt),
    ActionCall(ActionCall),
    Publish(Publish),
    Create(Create),
    Update(Update),
    Delete(Delete),
    Emit(Emit),
    FunctionCall(FunctionCall),
    DebugAssert(DebugAssert),
}

/// A let statement.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct LetStmt {
    pub ident: IdentId,
    pub expr: ExprId,
}

/// A check statement.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct CheckStmt {
    pub expr: ExprId,
}

/// A match statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MatchStmt {
    pub expr: ExprId,
    pub arms: Vec<MatchArm>,
}

/// A match statement arm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MatchArm {
    pub pattern: MatchPattern,
    pub stmts: Vec<StmtId>,
}

/// A match arm pattern.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MatchPattern {
    Default,
    Values(Vec<ExprId>),
}

/// An if statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IfStmt {
    pub branches: Vec<IfBranch>,
    pub else_block: Option<BlockId>,
}

/// An if statement branch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IfBranch {
    pub expr: ExprId,
    pub stmts: Vec<StmtId>,
}

/// A map statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MapStmt {
    pub fact: FactLiteral,
    pub ident: IdentId,
    pub stmts: Vec<StmtId>,
}

/// A return statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReturnStmt {
    pub expr: ExprId,
}

/// Calling an action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActionCall {
    pub ident: IdentId,
    pub args: Vec<ExprId>,
}

/// A publish statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Publish {
    pub exor: ExprId,
}

/// A create statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Create {
    pub fact: FactLiteral,
}

/// An update statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Update {
    pub fact: FactLiteral,
    pub to: Vec<(IdentId, FactField)>,
}

/// Either an expression or "?".
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum FactField {
    Expr(ExprId),
    Bind,
}

/// A delete statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Delete {
    pub fact: FactLiteral,
}

/// An emit statement.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Emit {
    pub expr: ExprId,
}

/// A debug assert statement.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct DebugAssert {
    pub expr: ExprId,
}

/// A block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Block {
    pub id: BlockId,
    pub stmts: Vec<StmtId>,
}

/// An action definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActionDef {
    pub id: ActionId,
    pub args: Vec<ActionArgId>,
    pub block: BlockId,
}

/// An action argument
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActionArg {
    pub id: ActionArgId,
    pub ident: IdentId,
    pub ty: VTypeId,
}

/// A finish function argument
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct FinishFuncArg {
    pub id: FinishFuncArgId,
    pub ident: IdentId,
    pub ty: VTypeId,
}

/// A function argument
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct FuncArg {
    pub id: FuncArgId,
    pub ident: IdentId,
    pub ty: VTypeId,
}

/// A command definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CmdDef {
    pub id: CmdId,
    pub fields: Vec<CmdFieldId>,
    pub seal: BlockId,
    pub open: BlockId,
    pub policy: BlockId,
    pub recall: BlockId,
}

/// A command field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CmdField {
    pub id: CmdFieldId,
    pub kind: CmdFieldKind,
}

/// The kind of a command field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CmdFieldKind {
    /// A regular field with an identifier and type
    Field { ident: IdentId, ty: VTypeId },
    /// A reference to another struct whose fields should be included
    StructRef(IdentId),
}

/// An effect definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectDef {
    pub id: EffectId,
    pub items: Vec<EffectFieldId>,
}

/// An effect field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectField {
    pub id: EffectFieldId,
    pub kind: EffectFieldKind,
}

/// The kind of an effect field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EffectFieldKind {
    /// A regular field with an identifier and type
    Field { ident: IdentId, ty: VTypeId },
    /// A reference to another struct whose fields should be included
    StructRef(IdentId),
}

/// An enum definition.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct EnumDef {
    pub id: EnumId,
}

/// A fact definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FactDef {
    pub id: FactId,
    pub keys: Vec<FactKeyId>,
    pub vals: Vec<FactValId>,
}

/// A fact key.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct FactKey {
    pub id: FactKeyId,
    pub ident: IdentId,
    pub ty: VTypeId,
}

/// A fact value.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct FactVal {
    pub id: FactValId,
    pub ident: IdentId,
    pub ty: VTypeId,
}

/// A finish function definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FinishFuncDef {
    pub id: FinishFuncId,
    pub args: Vec<FinishFuncArgId>,
    pub stmts: Vec<StmtId>,
}

/// A function definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FuncDef {
    pub id: FuncId,
    pub args: Vec<FuncArgId>,
    pub result: VTypeId,
    pub stmts: Vec<StmtId>,
}

/// A global let definition.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct GlobalLetDef {
    pub id: GlobalId,
    pub expr: ExprId,
}

/// A struct definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StructDef {
    pub id: StructId,
    pub items: Vec<StructFieldId>,
}

/// A struct field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StructField {
    pub id: StructFieldId,
    pub kind: StructFieldKind,
}

/// The kind of an struct field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StructFieldKind {
    /// A regular field with an identifier and type
    Field { ident: IdentId, ty: VTypeId },
    /// A reference to another struct whose fields should be included
    StructRef(IdentId),
}

/// Uniquely identifies a HIR node.
pub(crate) trait NodeId:
    Copy + Clone + Default + Eq + PartialEq + Ord + PartialOrd + Hash + fmt::Debug
{
    /// The underlying type.
    // TODO(eric): Into<Item<'ast>> isn't really needed since you
    // could convert it to `NodeId` whose `Type` is `Item`.
    type Node<'ast>: PartialEq + fmt::Debug;
}

macro_rules! new_id_type {
    ($(#[$outer:meta])* $vis:vis struct $name:ident; $($rest:tt)*) => {
        slotmap::new_key_type! {
            $(#[$outer])*
            $vis struct $name;
        }
        new_id_type!($($rest)*);
    };
    () => {};
}
new_id_type! {
    /// Uniquely identifies an action.
    pub(crate) struct ActionId;
    /// Uniquely identifies an action parameter.
    pub(crate) struct ActionArgId;

    /// Uniquely identifies a command.
    pub(crate) struct CmdId;
    /// Uniquely identifies a command field.
    pub(crate) struct CmdFieldId;

    /// Uniquely identifies an effect.
    pub(crate) struct EffectId;
    /// Uniquely identifies an effect field.
    pub(crate) struct EffectFieldId;

    /// Uniquely identifies an enum.
    pub(crate) struct EnumId;

    /// Uniquely identifies a fact.
    pub(crate) struct FactId;
    /// Uniquely identifies a fact key.
    pub(crate) struct FactKeyId;
    /// Uniquely identifies a fact value.
    pub(crate) struct FactValId;

    /// Uniquely identifies a finish function.
    pub(crate) struct FinishFuncId;
    /// Uniquely identifies a finish function argument.
    pub(crate) struct FinishFuncArgId;

    /// Uniquely identifies a function.
    pub(crate) struct FuncId;
    /// Uniquely identifies a function argument.
    pub(crate) struct FuncArgId;

    /// Uniquely identifies a global variable.
    pub(crate) struct GlobalId;

    /// Uniquely identifies a struct.
    pub(crate) struct StructId;
    /// Uniquely identifies a struct field.
    pub(crate) struct StructFieldId;

    /// Uniquely identifies a block.
    pub(crate) struct BlockId;
    /// Uniquely identifies an expression.
    pub(crate) struct ExprId;
    /// Uniquely identifies a statement.
    pub(crate) struct StmtId;
    /// Uniquely identifies a variable type.
    pub(crate) struct VTypeId;

    /// Uniquely identifies an identifier in the HIR.
    pub(crate) struct IdentId;
}
