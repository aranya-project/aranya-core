use std::{
    hash::Hash,
    ops::{BitAnd, BitAndAssign},
};

use aranya_policy_ast::{self as ast, Text};
use serde::{Deserialize, Serialize};
use slotmap::SlotMap;

/// A span representing a range in the source text.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Span {
    /// The start position in the source text (in bytes).
    pub start: usize,
    /// The end position in the source text (in bytes).
    pub end: usize,
}

impl Span {
    /// Creates a new span with the given start and end positions.
    pub fn new(start: usize, end: usize) -> Self {
        debug_assert!(start >= end);

        Self { start, end }
    }

    /// Creates a span where start and end positions are the
    /// same.
    pub fn point(pos: usize) -> Self {
        Self::new(pos, pos)
    }

    /// Creates a dummy span for testing purposes.
    pub fn dummy() -> Self {
        Self::new(0, 0)
    }
}

/// High-level Intermediate Representation (HIR).
///
/// The HIR is a simplified, desugared representation of the
/// [`Policy`][ast::Policy] AST that makes semantic analysis and
/// code generation easier. It stores all policy definitions in
/// arena-allocated collections indexed by typed IDs.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
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
    /// FFI import statements from the policy
    pub ffi_imports: SlotMap<FfiImportId, FfiImportDef>,
    /// FFI module definitions
    pub ffi_modules: SlotMap<FfiModuleId, FfiModuleDef>,
    /// FFI function definitions
    pub ffi_funcs: SlotMap<FfiFuncId, FfiFuncDef>,
    /// FFI struct definitions
    pub ffi_structs: SlotMap<FfiStructId, FfiStructDef>,
    /// FFI enum definitions
    pub ffi_enums: SlotMap<FfiEnumId, FfiEnumDef>,
}

/// Generates an ID type for a HIR node.
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

/// Generates a HIR node.
///
/// It ensures that all HIR nodes have:
/// - An `id` field
/// - A `span` field
/// - Consistent derive attributes (Clone, Debug, Eq, PartialEe,
///   etc.)
macro_rules! hir_node {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            pub id: $id:ident,
            $(
                $(#[$field_meta:meta])*
                pub $field:ident: $ty:ty
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
        $vis struct $name {
            /// Uniquely identifies the HIR node.
            pub id: $id,
            /// Where the node appears in the source text.
            pub span: Span,
            $(
                $(#[$field_meta])*
                pub $field: $ty
            ),*
        }
        make_node_id! {
            /// Uniquely identifies a
            #[doc = concat!("`", stringify!($name), "`")]
            $vis struct $id;
        }
    };
}

/// Generates a HIR "helper" type. That is, a type that is used
/// by a HIR node but is not a HIR node itself.
macro_rules! hir_type {
    // `struct`
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $($body:tt)*
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
        $vis struct $name {
            $($body)*
        }
    };
    // `enum`
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($body:tt)*
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
        $vis enum $name {
            $($body)*
        }
    };
}

hir_node! {
    /// An action definition.
    pub(crate) struct ActionDef {
        pub id: ActionId,
        pub ident: IdentId,
        pub args: Vec<ActionArgId>,
        pub block: BlockId,
    }
}

hir_node! {
    /// An argument to an action.
    pub(crate) struct ActionArg {
        pub id: ActionArgId,
        pub ident: IdentId,
        pub ty: VTypeId,
    }
}

hir_node! {
    /// A block is a collection of statements.
    pub(crate) struct Block {
        pub id: BlockId,
        pub stmts: Vec<StmtId>,
        /// `true` it any of the statements in the block contain
        /// a [`ReturnStmt`].
        pub returns: bool,
    }
}

hir_node! {
    /// A command definition.
    pub(crate) struct CmdDef {
        pub id: CmdId,
        pub ident: IdentId,
        pub fields: Vec<CmdFieldId>,
        pub seal: BlockId,
        pub open: BlockId,
        pub policy: BlockId,
        pub recall: BlockId,
    }
}

hir_node! {
    /// A field in a command`s fields block.
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

hir_node! {
    /// An effect definition.
    pub(crate) struct EffectDef {
        pub id: EffectId,
        pub ident: IdentId,
        pub items: Vec<EffectFieldId>,
    }
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

hir_node! {
    /// An enum definition.
    pub(crate) struct EnumDef {
        pub id: EnumId,
        pub ident: IdentId,
        pub variants: Vec<IdentId>,
    }
}

hir_node! {
    /// An expression.
    pub(crate) struct Expr {
        pub id: ExprId,
        pub kind: ExprKind,
        /// An expression is pure iff it has no side effects.
        ///
        /// A side effect is defined as:
        ///
        /// - Calling an action.
        /// - Calling a foreign function.
        /// - Calling a finish function.
        /// - `create`, `update`, `delete`, `emit`, or `publish`
        ///
        /// Note that foreign functions *should* be pure, but it
        /// is impossible to guarantee that they are.
        pub pure: Pure,
        /// `true` if this expression contains at least one
        /// [`ReturnStmt`].
        ///
        /// NB: This means that the expression contains at least
        /// one [`ExprKind::Block`].
        pub returns: bool,
    }
}

hir_type! {
    /// Is this pure?
    #[derive(Copy, Default)]
    pub(crate) enum Pure {
        Yes,
        No,
        /// We don't have enough information to determine its
        /// purity.
        #[default]
        Maybe,
    }
}

impl BitAnd for Pure {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Pure::Yes, Pure::Yes) => Pure::Yes,
            (Pure::No, _) | (_, Pure::No) => Pure::No,
            _ => Pure::Maybe,
        }
    }
}

impl BitAndAssign for Pure {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

hir_type! {
    /// An expression.
    pub(crate) enum ExprKind {
        /// A 64-bit signed integer literal.
        Int(i64),
        /// A text string literal.
        String(Text),
        /// A boolean literal.
        Bool(bool),
        /// An optional literal.
        ///
        /// For example:
        ///
        /// ```policy
        /// let x = Some(42);
        ///         ^^^^^^^^ ExprKind::Optional(Some(...))
        /// return None
        ///        ^^^^ ExprKind::Optional(None)
        /// ```
        Optional(Option<ExprId>),
        /// A named struct literal.
        NamedStruct(NamedStruct),
        /// A VM intrinsic.
        Intrinsic(Intrinsic),
        /// A function call expression.
        FunctionCall(FunctionCall),
        /// A foreign function call expression.
        ForeignFunctionCall(ForeignFunctionCall),
        /// An identifier reference.
        Identifier(IdentId),
        /// An enum reference.
        ///
        /// ```policy
        /// let x = MyEnum::Variant;
        ///         ^^^^^^^^^^^^^^^ ExprKind::EnumReference(...)
        /// ```
        EnumReference(EnumRef),
        /// A binary [add] expression.
        ///
        /// [add]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        Add(ExprId, ExprId),
        /// A binary [sub] expression.
        ///
        /// [sub]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        Sub(ExprId, ExprId),
        /// A binary [and] expression.
        ///
        /// [and]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        And(ExprId, ExprId),
        /// A binary [or] expression.
        ///
        /// [or]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        Or(ExprId, ExprId),
        /// A [field access] expression.
        ///
        /// [field access]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        // TODO(eric): Make this Dot(Dot) so it's more clear.
        Dot(ExprId, IdentId),
        /// A binary [equal] expression.
        ///
        /// [equal]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        Equal(ExprId, ExprId),
        /// A binary ["not equal"][ne] expression.
        ///
        /// [not equal][ne]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        NotEqual(ExprId, ExprId),
        /// A binary ["greater than"][gt] expression.
        ///
        /// [gt]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        GreaterThan(ExprId, ExprId),
        /// A binary ["less than"][lt] expression.
        ///
        /// [lt]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        LessThan(ExprId, ExprId),
        /// A binary ["greater than or equal to"][gte] expression.
        ///
        /// [gte]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        GreaterThanOrEqual(ExprId, ExprId),
        /// A binary ["less than or equal to"][lte] expression.
        ///
        /// [lte]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        LessThanOrEqual(ExprId, ExprId),
        /// A unary [negation] expression.
        ///
        /// [negation]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#prefix-operators
        Negative(ExprId),
        /// A unary logical [negation] expression.
        ///
        /// [negation]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#prefix-operators
        Not(ExprId),
        /// A unary [`unwrap`] expression.
        ///
        /// [`unwrap`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#prefix-operators
        Unwrap(ExprId),
        /// A unary [`check_unwrap`] expression.
        ///
        /// [`check_unwrap`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#prefix-operators
        CheckUnwrap(ExprId),
        /// The `is Some` and `is None` postfix [expressions].
        ///
        /// The second argument is `true` for `is Some` and false
        /// for `is None`.
        ///
        /// [expressions]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#postfix-operators
        Is(ExprId, bool),
        /// A [block] expression.
        ///
        /// [block]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v2.md#block-expressions
        Block(BlockId, ExprId),
        /// A [`substruct`] expression.
        ///
        /// [`substruct`]: https://github.com/aranya-project/aranya-docs/blob/main/docs/policy-v2.md#struct-subselection
        Substruct(ExprId, IdentId),
        /// `match` used as an expression.
        ///
        /// ```policy
        /// let foo = match bar {
        ///     MyEnum::A => { "A" },
        ///     MyEnum::B => { "B" },
        ///     _ => { "C" },
        /// }
        /// ```
        Match(MatchExpr),
        /// A ternary [`if`] expression.
        ///
        /// [`if`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#if
        Ternary(Ternary),
    }
}

hir_type! {
    /// `match` used as an expression.
    pub(crate) struct MatchExpr {
        pub scrutinee: ExprId,
        pub arms: Vec<MatchExprArm>,
    }
}

hir_type! {
    /// An arm in a [`MatchExpr`].
    pub(crate) struct MatchExprArm {
        pub pattern: MatchPattern,
        pub expr: ExprId,
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
    /// An intrinsic implemented by the VM.
    pub(crate) enum Intrinsic {
        /// A [`query`] expression.
        ///
        /// [`query`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#query
        Query(FactLiteral),
        /// One of the [`count_up_to`], `at_least`, `at_most`, or
        /// `exactly` expressions.
        ///
        /// NB: [`exists`] is desugared to `at_least 1`.
        ///
        /// [`count_up_to`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#count_up_to
        /// [`exists`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#exists
        FactCount(FactCountType, i64, FactLiteral),
        /// A `serialize` expression.
        ///
        /// [`serialize`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#serializedeserialize
        Serialize(ExprId),
        /// A `deserialize` expression.
        ///
        /// [`deserialize`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#serializedeserialize
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
    /// An enum reference.
    ///
    /// ```policy
    /// let x = MyEnum::Variant;
    ///         ^^^^^^^^^^^^^^^
    /// ```
    pub(crate) struct EnumRef {
        /// The enum's identifier.
        pub ident: IdentId,
        /// The enum's variant.
        pub value: IdentId,
    }
}

hir_node! {
    /// A fact definition.
    pub(crate) struct FactDef {
        pub id: FactId,
        pub ident: IdentId,
        pub keys: Vec<FactKeyId>,
        pub vals: Vec<FactValId>,
    }
}

hir_node! {
    /// A fact key.
    pub(crate) struct FactKey {
        pub id: FactKeyId,
        pub ident: IdentId,
        pub ty: VTypeId,
    }
}

hir_node! {
    /// A fact value.
    pub(crate) struct FactVal {
        pub id: FactValId,
        pub ident: IdentId,
        pub ty: VTypeId,
    }
}

hir_node! {
    /// A finish function definition.
    pub(crate) struct FinishFuncDef {
        pub id: FinishFuncId,
        pub ident: IdentId,
        pub args: Vec<FinishFuncArgId>,
        pub block: BlockId,
    }
}

hir_node! {
    /// A finish function argument
    pub(crate) struct FinishFuncArg {
        pub id: FinishFuncArgId,
        pub ident: IdentId,
        pub ty: VTypeId,
    }
}

hir_node! {
    /// A function definition.
    pub(crate) struct FuncDef {
        pub id: FuncId,
        pub ident: IdentId,
        pub args: Vec<FuncArgId>,
        pub result: VTypeId,
        pub block: BlockId,
    }
}

hir_node! {
    /// A function argument
    pub(crate) struct FuncArg {
        pub id: FuncArgId,
        pub ident: IdentId,
        pub ty: VTypeId,
    }
}

hir_node! {
    /// A global let definition.
    pub(crate) struct GlobalLetDef {
        pub id: GlobalId,
        pub ident: IdentId,
        pub expr: ExprId,
    }
}

hir_node! {
    /// A statement.
    pub(crate) struct Stmt {
        pub id: StmtId,
        pub kind: StmtKind,
        /// `true` if this statement could return.
        ///
        /// NB: This could be true for more than just
        /// [`StmtKind::Return`].
        pub returns: bool,
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
        pub block: BlockId,
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
        pub block: BlockId,
    }
}

hir_type! {
    /// A map statement.
    pub(crate) struct MapStmt {
        pub fact: FactLiteral,
        pub ident: IdentId,
        pub block: BlockId,
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

hir_node! {
    /// A struct definition.
    pub(crate) struct StructDef {
        pub id: StructId,
        pub ident: IdentId,
        pub items: Vec<StructFieldId>,
    }
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

hir_node! {
    /// An identifier.
    pub(crate) struct Ident {
        pub id: IdentId,
        pub ident: ast::Identifier,
    }
}

hir_type! {
    /// A ternary [`if`] expression.
    ///
    /// [`if`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#if
    pub(crate) struct Ternary {
        /// The condition being evaluated.
        pub cond: ExprId,
        /// The result when `cond` is true.
        pub true_expr: ExprId,
        /// The result when `cond` is false.
        pub false_expr: ExprId,
    }
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

hir_node! {
    /// An FFI import statement (e.g., `use crypto`).
    pub(crate) struct FfiImportDef {
        pub id: FfiImportId,
        pub module: IdentId,
    }
}

hir_node! {
    /// An FFI module definition.
    pub(crate) struct FfiModuleDef {
        pub id: FfiModuleId,
        pub name: IdentId,
        pub functions: Vec<FfiFuncId>,
        pub structs: Vec<FfiStructId>,
        pub enums: Vec<FfiEnumId>,
    }
}

hir_node! {
    /// An FFI function definition.
    pub(crate) struct FfiFuncDef {
        pub id: FfiFuncId,
        pub name: IdentId,
        pub args: Vec<(IdentId, VTypeId)>,
        pub return_type: VTypeId,
    }
}

hir_node! {
    /// An FFI struct definition.
    pub(crate) struct FfiStructDef {
        pub id: FfiStructId,
        pub name: IdentId,
        pub fields: Vec<(IdentId, VTypeId)>,
    }
}

hir_node! {
    /// An FFI enum definition.
    pub(crate) struct FfiEnumDef {
        pub id: FfiEnumId,
        pub name: IdentId,
        pub variants: Vec<IdentId>,
    }
}
