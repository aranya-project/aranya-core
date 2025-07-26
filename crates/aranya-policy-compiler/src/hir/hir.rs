//! High-level Intermediate Representation (HIR) for Aranya
//! policy code.
//!
//! All HIR nodes are stored in flat collections and can be
//! referenced with stable IDs (e.g., [`ActionId`], [`ExprId`]).
//!
//! # Example Structure
//!
//! An action like
//!
//! ```text
//! action foo(x int) {
//!     let y = x + 1
//!     check y > 0
//! }
//! ```
//!
//! Becomes the following HIR nodes:
//! - `ActionDef` with ID referencing:
//!   - `ActionArg` for parameter `x`
//!   - `Block` containing:
//!     - `Stmt::Let` referencing `Expr::Add`
//!     - `Stmt::Check` referencing `Expr::GreaterThan`

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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct Hir {
    /// Action definitions.
    pub actions: SlotMap<ActionId, ActionDef>,
    /// Arguments for action definitions
    pub action_args: SlotMap<ActionArgId, ActionArg>,
    /// Command definitions.
    pub cmds: SlotMap<CmdId, CmdDef>,
    /// Fields within command definitions
    pub cmd_fields: SlotMap<CmdFieldId, CmdField>,
    /// Effect definitions
    pub effects: SlotMap<EffectId, EffectDef>,
    /// Fields within effect definitions
    pub effect_fields: SlotMap<EffectFieldId, EffectField>,
    /// Enumeration type definitions
    pub enums: SlotMap<EnumId, EnumDef>,
    /// Fact definitions
    pub facts: SlotMap<FactId, FactDef>,
    /// Key fields for fact definitions
    pub fact_keys: SlotMap<FactKeyId, FactKey>,
    /// Value fields for fact definitions
    pub fact_vals: SlotMap<FactValId, FactVal>,
    /// Finish function definitions
    pub finish_funcs: SlotMap<FinishFuncId, FinishFuncDef>,
    /// Arguments for finish function definitions
    pub finish_func_args: SlotMap<FinishFuncArgId, FinishFuncArg>,
    /// Regular function definitions
    pub funcs: SlotMap<FuncId, FuncDef>,
    /// Arguments for function definitions
    pub func_args: SlotMap<FuncArgId, FuncArg>,
    /// Global constant definitions
    pub global_lets: SlotMap<GlobalId, GlobalLetDef>,
    /// Structure type definitions
    pub structs: SlotMap<StructId, StructDef>,
    /// Fields within structure definitions
    pub struct_fields: SlotMap<StructFieldId, StructField>,
    /// All statements
    pub stmts: SlotMap<StmtId, Stmt>,
    /// All expressions
    pub exprs: SlotMap<ExprId, Expr>,
    /// All identifiers
    pub idents: SlotMap<IdentId, Ident>,
    /// Statement blocks (collections of statements)
    pub blocks: SlotMap<BlockId, Block>,
    /// Type definitions and references
    pub types: SlotMap<VTypeId, VType>,
}

/// Trait for HIR nodes.
pub(crate) trait Node {
    /// The ID type for this node.
    type Id: fmt::Debug;
}

/// Generates a HIR node struct with consistent derives and an ID
/// field.
///
/// This macro ensures all HIR nodes have:
/// - A unique `id` field of the specified type
/// - Consistent derive attributes (Clone, Debug, Eq, PartialEq)
/// - Optional serde support when the feature is enabled
macro_rules! hir_node {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            pub id: $id:ty,
            $(pub $field:ident: $ty:ty),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        $vis struct $name {
            pub id: $id,
            $(pub $field: $ty),*
        }
    };
}

/// Generates typed ID structs for use with SlotMap.
///
/// This macro creates newtype wrappers that serve as keys for
/// the arena-allocated collections in the HIR.
macro_rules! make_node_id {
    ($(#[$outer:meta])* $vis:vis struct $name:ident; $($rest:tt)*) => {
        slotmap::new_key_type! {
            $(#[$outer])*
            $vis struct $name;
        }
        make_node_id!($($rest)*);
    };
    () => {};
}

/// Generates HIR helper types with consistent derives.
///
/// This macro ensures all HIR helper types (structs and enums
/// that aren't nodes themselves) have consistent derive
/// attributes.
macro_rules! hir_type {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $($body:tt)*
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        $vis struct $name {
            $($body)*
        }
    };
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($body:tt)*
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        $vis enum $name {
            $($body)*
        }
    };
}

make_node_id! {
    /// Uniquely identifies an action.
    pub(crate) struct ActionId;
}

hir_node! {
    /// An action definition.
    pub(crate) struct ActionDef {
        pub id: ActionId,
        pub args: Vec<ActionArgId>,
        pub block: BlockId,
    }
}

make_node_id! {
    /// Uniquely identifies an action parameter.
    pub(crate) struct ActionArgId;
}

hir_node! {
    /// An action argument
    pub(crate) struct ActionArg {
        pub id: ActionArgId,
        pub ident: IdentId,
        pub ty: VTypeId,
    }
}

make_node_id! {
    /// Uniquely identifies a block.
    pub(crate) struct BlockId;
}

hir_node! {
    /// A block.
    pub(crate) struct Block {
        pub id: BlockId,
        pub stmts: Vec<StmtId>,
    }
}

make_node_id! {
    /// Uniquely identifies a command.
    pub(crate) struct CmdId;
}

hir_node! {
    /// A command definition.
    pub(crate) struct CmdDef {
        pub id: CmdId,
        pub fields: Vec<CmdFieldId>,
        pub seal: BlockId,
        pub open: BlockId,
        pub policy: BlockId,
        pub recall: BlockId,
    }
}

make_node_id! {
    /// Uniquely identifies a command field.
    pub(crate) struct CmdFieldId;
}

hir_node! {
    /// A command field.
    pub(crate) struct CmdField {
        pub id: CmdFieldId,
        pub kind: CmdFieldKind,
    }
}

hir_type! {
    /// The kind of a command field.
    pub(crate) enum CmdFieldKind {
        /// A regular field with an identifier and type
        Field { ident: IdentId, ty: VTypeId },
        /// A reference to another struct whose fields should be included
        StructRef(IdentId),
    }
}

make_node_id! {
    /// Uniquely identifies an effect.
    pub(crate) struct EffectId;
}

hir_node! {
    /// An effect definition.
    pub(crate) struct EffectDef {
        pub id: EffectId,
        pub items: Vec<EffectFieldId>,
    }
}

make_node_id! {
    /// Uniquely identifies an effect field.
    pub(crate) struct EffectFieldId;
}

hir_node! {
    /// An effect field.
    pub(crate) struct EffectField {
        pub id: EffectFieldId,
        pub kind: EffectFieldKind,
    }
}

hir_type! {
    /// The kind of an effect field.
    pub(crate) enum EffectFieldKind {
        /// A regular field with an identifier and type
        Field { ident: IdentId, ty: VTypeId },
        /// A reference to another struct whose fields should be included
        StructRef(IdentId),
    }
}

make_node_id! {
    /// Uniquely identifies an enum.
    pub(crate) struct EnumId;
}

hir_node! {
    /// An enum definition.
    pub(crate) struct EnumDef {
        pub id: EnumId,
    }
}

make_node_id! {
    /// Uniquely identifies an expression.
    pub(crate) struct ExprId;
}

hir_node! {
    /// An expression.
    pub(crate) struct Expr {
        pub id: ExprId,
        pub kind: ExprKind,
    }
}

hir_type! {
    /// An expression.
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
}

hir_type! {
    /// A named struct.
    pub(crate) struct NamedStruct {
        pub ident: IdentId,
        pub fields: Vec<(IdentId, ExprId)>,
    }
}

hir_type! {
    pub(crate) enum InternalFunction {
        Query(FactLiteral),
        Exists(FactLiteral),
        FactCount(FactCountType, i64, FactLiteral),
        If(ExprId, ExprId, ExprId),
        Serialize(ExprId),
        Deserialize(ExprId),
    }
}

hir_type! {
    /// How many facts to expect when counting
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
}

hir_type! {
    /// A named struct literal.
    pub(crate) struct FactLiteral {
        pub ident: IdentId,
        pub keys: Vec<(IdentId, FactField)>,
        pub vals: Vec<(IdentId, FactField)>,
    }
}

hir_type! {
    /// Either an expression or "?".
    pub(crate) enum FactField {
        Expr(ExprId),
        Bind,
    }
}

hir_type! {
    /// A function call.
    pub(crate) struct FunctionCall {
        pub ident: IdentId,
        pub args: Vec<ExprId>,
    }
}

hir_type! {
    pub(crate) struct ForeignFunctionCall {
        pub module: IdentId,
        pub ident: IdentId,
        pub args: Vec<ExprId>,
    }
}

hir_type! {
    pub(crate) struct EnumReference {
        pub ident: IdentId,
        pub value: IdentId,
    }
}

make_node_id! {
    /// Uniquely identifies a fact.
    pub(crate) struct FactId;
}

hir_node! {
    /// A fact definition.
    pub(crate) struct FactDef {
        pub id: FactId,
        pub keys: Vec<FactKeyId>,
        pub vals: Vec<FactValId>,
    }
}

make_node_id! {
    /// Uniquely identifies a fact key.
    pub(crate) struct FactKeyId;
}

hir_node! {
    /// A fact key.
    pub(crate) struct FactKey {
        pub id: FactKeyId,
        pub ident: IdentId,
        pub ty: VTypeId,
    }
}

make_node_id! {
    /// Uniquely identifies a fact value.
    pub(crate) struct FactValId;
}

hir_node! {
    /// A fact value.
    pub(crate) struct FactVal {
        pub id: FactValId,
        pub ident: IdentId,
        pub ty: VTypeId,
    }
}

make_node_id! {
    /// Uniquely identifies a finish function.
    pub(crate) struct FinishFuncId;
}

hir_node! {
    /// A finish function definition.
    pub(crate) struct FinishFuncDef {
        pub id: FinishFuncId,
        pub args: Vec<FinishFuncArgId>,
        // TODO(eric): Make this `BlockId`.
        pub stmts: Vec<StmtId>,
    }
}

make_node_id! {
    /// Uniquely identifies a finish function argument.
    pub(crate) struct FinishFuncArgId;
}

hir_node! {
    /// A finish function argument
    pub(crate) struct FinishFuncArg {
        pub id: FinishFuncArgId,
        pub ident: IdentId,
        pub ty: VTypeId,
    }
}

make_node_id! {
    /// Uniquely identifies a function.
    pub(crate) struct FuncId;
}

hir_node! {
    /// A function definition.
    pub(crate) struct FuncDef {
        pub id: FuncId,
        pub args: Vec<FuncArgId>,
        pub result: VTypeId,
        // TODO(eric): Make this `BlockId`.
        pub stmts: Vec<StmtId>,
    }
}

make_node_id! {
    /// Uniquely identifies a function argument.
    pub(crate) struct FuncArgId;
}

hir_node! {
    /// A function argument
    pub(crate) struct FuncArg {
        pub id: FuncArgId,
        pub ident: IdentId,
        pub ty: VTypeId,
    }
}

make_node_id! {
    /// Uniquely identifies a global variable.
    pub(crate) struct GlobalId;
}

hir_node! {
    /// A global let definition.
    pub(crate) struct GlobalLetDef {
        pub id: GlobalId,
        pub expr: ExprId,
    }
}

make_node_id! {
    /// Uniquely identifies a statement.
    pub(crate) struct StmtId;
}

hir_node! {
    /// A statement.
    pub(crate) struct Stmt {
        pub id: StmtId,
        pub kind: StmtKind,
    }
}

hir_type! {
    /// The kind of a statement.
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
}

hir_type! {
    /// A let statement.
    pub(crate) struct LetStmt {
        pub ident: IdentId,
        pub expr: ExprId,
    }
}

hir_type! {
    /// A check statement.
    pub(crate) struct CheckStmt {
        pub expr: ExprId,
    }
}

hir_type! {
    /// A match statement.
    pub(crate) struct MatchStmt {
        pub expr: ExprId,
        pub arms: Vec<MatchArm>,
    }
}

hir_type! {
    /// A match statement arm.
    pub(crate) struct MatchArm {
        pub pattern: MatchPattern,
        // TODO(eric): Make this `BlockId`.
        pub stmts: Vec<StmtId>,
    }
}

hir_type! {
    /// A match arm pattern.
    pub(crate) enum MatchPattern {
        Default,
        Values(Vec<ExprId>),
    }
}

hir_type! {
    /// An if statement.
    pub(crate) struct IfStmt {
        pub branches: Vec<IfBranch>,
        pub else_block: Option<BlockId>,
    }
}

hir_type! {
    /// An if statement branch.
    pub(crate) struct IfBranch {
        pub expr: ExprId,
        // TODO(eric): Make this `BlockId`.
        pub stmts: Vec<StmtId>,
    }
}

hir_type! {
    /// A map statement.
    pub(crate) struct MapStmt {
        pub fact: FactLiteral,
        pub ident: IdentId,
        // TODO(eric): Make this `BlockId`.
        pub stmts: Vec<StmtId>,
    }
}

hir_type! {
    /// A return statement.
    pub(crate) struct ReturnStmt {
        pub expr: ExprId,
    }
}

hir_type! {
    /// Calling an action.
    pub(crate) struct ActionCall {
        pub ident: IdentId,
        pub args: Vec<ExprId>,
    }
}

hir_type! {
    /// A publish statement.
    pub(crate) struct Publish {
        pub exor: ExprId,
    }
}

hir_type! {
    /// A create statement.
    pub(crate) struct Create {
        pub fact: FactLiteral,
    }
}

hir_type! {
    /// An update statement.
    pub(crate) struct Update {
        pub fact: FactLiteral,
        pub to: Vec<(IdentId, FactField)>,
    }
}

hir_type! {
    /// A delete statement.
    pub(crate) struct Delete {
        pub fact: FactLiteral,
    }
}

hir_type! {
    /// An emit statement.
    pub(crate) struct Emit {
        pub expr: ExprId,
    }
}

hir_type! {
    /// A debug assert statement.
    pub(crate) struct DebugAssert {
        pub expr: ExprId,
    }
}

make_node_id! {
    /// Uniquely identifies a struct.
    pub(crate) struct StructId;
}

hir_node! {
    /// A struct definition.
    pub(crate) struct StructDef {
        pub id: StructId,
        pub items: Vec<StructFieldId>,
    }
}

make_node_id! {
    /// Uniquely identifies a struct field.
    pub(crate) struct StructFieldId;
}

hir_node! {
    /// A struct field.
    pub(crate) struct StructField {
        pub id: StructFieldId,
        pub kind: StructFieldKind,
    }
}

hir_type! {
    /// The kind of an struct field.
    pub(crate) enum StructFieldKind {
        /// A regular field with an identifier and type
        Field { ident: IdentId, ty: VTypeId },
        /// A reference to another struct whose fields should be included
        StructRef(IdentId),
    }
}

make_node_id! {
    /// Uniquely identifies an identifier in the HIR.
    pub(crate) struct IdentId;
}

hir_node! {
    /// An identifier.
    pub(crate) struct Ident {
        pub id: IdentId,
        pub ident: ast::Identifier,
    }
}

make_node_id! {
    /// Uniquely identifies a variable type.
    pub(crate) struct VTypeId;
}

hir_node! {
    pub(crate) struct VType {
        pub id: VTypeId,
        pub kind: VTypeKind,
    }
}

hir_type! {
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
