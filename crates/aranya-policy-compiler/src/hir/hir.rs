use std::{
    hash::Hash,
    ops::{BitAnd, BitAndAssign},
};

use aranya_policy_ast::Text;
use serde::{Deserialize, Serialize};
use slotmap::SlotMap;

use crate::ctx::{Idents, InternedIdent};

/// A span representing a range in the source text.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
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
    // TODO(eric): This is used throughout the code. Make the
    // code use `Default::default` instead.
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
#[derive(Clone, Default, Debug, Serialize)]
pub(crate) struct Hir<'ctx> {
    /// Action definitions.
    pub actions: SlotMap<ActionId, ActionDef<'ctx>>,
    /// Arguments for action definitions
    pub action_args: SlotMap<ActionArgId, ActionArg<'ctx>>,
    /// Command definitions.
    pub cmds: SlotMap<CmdId, CmdDef<'ctx>>,
    /// Fields within command definitions
    pub cmd_fields: SlotMap<CmdFieldId, CmdField<'ctx>>,
    /// Effect definitions
    pub effects: SlotMap<EffectId, EffectDef<'ctx>>,
    /// Fields within effect definitions
    pub effect_fields: SlotMap<EffectFieldId, EffectField<'ctx>>,
    /// Enumeration type definitions
    pub enums: SlotMap<EnumId, EnumDef<'ctx>>,
    /// Fact definitions
    pub facts: SlotMap<FactId, FactDef<'ctx>>,
    /// Key fields for fact definitions
    pub fact_keys: SlotMap<FactKeyId, FactKey<'ctx>>,
    /// Value fields for fact definitions
    pub fact_vals: SlotMap<FactValId, FactVal<'ctx>>,
    /// Finish function definitions
    pub finish_funcs: SlotMap<FinishFuncId, FinishFuncDef<'ctx>>,
    /// Arguments for finish function definitions
    pub finish_func_args: SlotMap<FinishFuncArgId, FinishFuncArg<'ctx>>,
    /// Regular function definitions
    pub funcs: SlotMap<FuncId, FuncDef<'ctx>>,
    /// Arguments for function definitions
    pub func_args: SlotMap<FuncArgId, FuncArg<'ctx>>,
    /// Global constant definitions
    pub global_lets: SlotMap<GlobalId, GlobalLetDef<'ctx>>,
    /// Structure type definitions
    pub structs: SlotMap<StructId, StructDef<'ctx>>,
    /// Fields within structure definitions
    pub struct_fields: SlotMap<StructFieldId, StructField<'ctx>>,
    /// All statements
    pub stmts: SlotMap<StmtId, Stmt<'ctx>>,
    /// All expressions
    pub exprs: SlotMap<ExprId, Expr<'ctx>>,
    /// All identifiers
    pub idents: SlotMap<IdentId, Ident>,
    /// Statement blocks (collections of statements)
    pub blocks: SlotMap<BlockId, Block<'ctx>>,
    /// Type definitions and references
    pub types: SlotMap<VTypeId, VType<'ctx>>,
    /// FFI import statements from the policy
    pub ffi_imports: SlotMap<FfiImportId, FfiImportDef>,
    /// FFI module definitions
    pub ffi_modules: SlotMap<FfiModuleId, FfiModuleDef<'ctx>>,
    /// FFI function definitions
    pub ffi_funcs: SlotMap<FfiFuncId, FfiFuncDef<'ctx>>,
    /// FFI struct definitions
    pub ffi_structs: SlotMap<FfiStructId, FfiStructDef<'ctx>>,
    /// FFI enum definitions
    pub ffi_enums: SlotMap<FfiEnumId, FfiEnumDef<'ctx>>,
    /// Interned identifiers.
    pub intern: Idents,
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
        $vis:vis struct $name:ident $(<$lt:lifetime>)? {
            pub id: $id:ident,
            $(
                $(#[$field_meta:meta])*
                pub $field:ident: $ty:ty
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize)]
        $vis struct $name $(<$lt>)? {
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
        $vis:vis struct $name:ident $(<$lt:lifetime>)? { $($body:tt)* }
    ) => {
        $(#[$meta])*
        #[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize)]
        $vis struct $name $(<$lt>)? { $($body)* }
    };
    // `struct`
    (@nocopy
        $(#[$meta:meta])*
        $vis:vis struct $name:ident $(<$lt:lifetime>)? { $($body:tt)* }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        $vis struct $name $(<$lt>)? { $($body)* }
    };
    // `enum`
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident $(<$lt:lifetime>)? { $($body:tt)* }
    ) => {
        $(#[$meta])*
        #[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize)]
        $vis enum $name $(<$lt>)? { $($body)* }
    };
    // `enum`
    (@nocopy
        $(#[$meta:meta])*
        $vis:vis enum $name:ident $(<$lt:lifetime>)? { $($body:tt)* }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        $vis enum $name $(<$lt>)? { $($body)* }
    };
}

hir_node! {
    /// An action definition.
    pub(crate) struct ActionDef<'ctx> {
        pub id: ActionId,
        pub ident: Ident,
        pub sig: &'ctx ActionSig<'ctx>,
        pub block: &'ctx Block<'ctx>,
    }
}

hir_type! {
    pub(crate) struct ActionSig<'ctx> {
        pub args: &'ctx [ActionArg<'ctx>],
    }
}

hir_node! {
    /// An argument to an action.
    pub(crate) struct ActionArg<'ctx> {
        pub id: ActionArgId,
        pub ident: Ident,
        pub ty: &'ctx VType<'ctx>,
    }
}

hir_node! {
    /// A block is a collection of statements.
    pub(crate) struct Block<'ctx> {
        pub id: BlockId,
        pub stmts: &'ctx [Stmt<'ctx>],
        pub expr: Option<&'ctx Expr<'ctx>>,
        /// `true` it any of the statements in the block contain
        /// a [`ReturnStmt`].
        pub returns: bool,
    }
}

hir_node! {
    /// A command definition.
    pub(crate) struct CmdDef<'ctx> {
        pub id: CmdId,
        pub ident: Ident,
        pub fields: &'ctx [CmdField<'ctx>],
        pub seal: &'ctx Block<'ctx>,
        pub open: &'ctx Block<'ctx>,
        pub policy: &'ctx Block<'ctx>,
        pub recall: &'ctx Block<'ctx>,
    }
}

hir_node! {
    /// A field in a command`s fields block.
    pub(crate) struct CmdField<'ctx> {
        pub id: CmdFieldId,
        pub kind: CmdFieldKind<'ctx>,
    }
}

hir_type! {
    /// The kind of a command field.
    pub(crate) enum CmdFieldKind<'ctx> {
        /// A regular field with an identifier and type.
        Field { ident: Ident, ty: &'ctx VType<'ctx> },
        /// A reference to another struct whose fields should be
        /// included.
        StructRef(Ident),
    }
}

hir_type! {
    pub(crate) struct FieldDef<'ctx> {
        pub ident: Ident,
        pub ty: &'ctx VType<'ctx>,
    }
}

hir_node! {
    /// An effect definition.
    pub(crate) struct EffectDef<'ctx> {
        pub id: EffectId,
        pub ident: Ident,
        pub items: &'ctx [EffectField<'ctx>],
    }
}

hir_node! {
    /// An effect field.
    pub(crate) struct EffectField<'ctx> {
        pub id: EffectFieldId,
        pub kind: EffectFieldKind<'ctx>,
    }
}

hir_type! {
    /// The kind of an effect field.
    pub(crate) enum EffectFieldKind<'ctx> {
        /// A regular field with an identifier and type.
        Field { ident: Ident, ty: &'ctx VType<'ctx> },
        /// A reference to another struct whose fields should be
        /// included.
        StructRef(Ident),
    }
}

hir_node! {
    /// An enum definition.
    pub(crate) struct EnumDef<'ctx> {
        pub id: EnumId,
        pub ident: Ident,
        pub variants: &'ctx [Ident],
    }
}

hir_node! {
    /// An expression.
    pub(crate) struct Expr<'ctx> {
        pub id: ExprId,
        pub kind: ExprKind<'ctx>,
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
    #[derive(Default)]
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

hir_type! { @nocopy
    /// A literal.
    pub(crate) struct Lit<'ctx> {
        pub kind: LitKind<'ctx>,
    }
}

hir_type! { @nocopy
    pub(crate) enum LitKind<'ctx> {
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
        // TODO(eric): This really isn't a literal per-se.
        Optional(Option<&'ctx Expr<'ctx>>),
        /// A named struct literal.
        // TODO(eric): This isn't a literal per-se.
        NamedStruct(NamedStruct<'ctx>),
        /// A fact literal.
        // TODO(eric): This isn't a literal per-se.
        Fact(FactLiteral<'ctx>),
    }
}

hir_type! {
    /// An expression.
    pub(crate) enum ExprKind<'ctx> {
        /// A literal.
        Lit(&'ctx Lit<'ctx>),
        /// A VM intrinsic.
        Intrinsic(Intrinsic<'ctx>),
        /// A function call expression.
        FunctionCall(FunctionCall<'ctx>),
        /// A foreign function call expression.
        ForeignFunctionCall(ForeignFunctionCall<'ctx>),
        /// An identifier reference.
        Identifier(Ident),
        /// An enum reference.
        ///
        /// ```policy
        /// let x = MyEnum::Variant;
        ///         ^^^^^^^^^^^^^^^ ExprKind::EnumReference(...)
        /// ```
        EnumRef(EnumRef),
        /// A binary operation.
        Binary(BinOp, &'ctx Expr<'ctx>, &'ctx Expr<'ctx>),
        /// A unary operation.
        Unary(UnaryOp, &'ctx Expr<'ctx>),
        /// A [field access] expression.
        ///
        /// [field access]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        // TODO(eric): Make this Dot(Dot) so it's more clear.
        Dot(&'ctx Expr<'ctx>, Ident),
        /// The `is Some` and `is None` postfix [expressions].
        ///
        /// The second argument is `true` for `is Some` and false
        /// for `is None`.
        ///
        /// [expressions]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#postfix-operators
        Is(&'ctx Expr<'ctx>, bool),
        /// A [block] expression.
        ///
        /// [block]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v2.md#block-expressions
        Block(&'ctx Block<'ctx>, &'ctx Expr<'ctx>),
        /// A [`substruct`] expression.
        ///
        /// [`substruct`]: https://github.com/aranya-project/aranya-docs/blob/main/docs/policy-v2.md#struct-subselection
        Substruct(&'ctx Expr<'ctx>, Ident),
        /// `match` used as an expression.
        ///
        /// ```policy
        /// let foo = match bar {
        ///     MyEnum::A => { "A" },
        ///     MyEnum::B => { "B" },
        ///     _ => { "C" },
        /// }
        /// ```
        Match(MatchExpr<'ctx>),
        /// A ternary [`if`] expression.
        ///
        /// [`if`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#if
        Ternary(Ternary<'ctx>),
    }
}

hir_type! {
    /// A binary opeation.
    pub(crate) enum BinOp {
        /// A binary [add] expression.
        ///
        /// [add]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        Add,
        /// A binary [sub] expression.
        ///
        /// [sub]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        Sub,
        /// A binary [and] expression.
        ///
        /// [and]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        And,
        /// A binary [or] expression.
        ///
        /// [or]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        Or,
        /// A binary [equal] expression.
        ///
        /// [equal]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        Eq,
        /// A binary ["not equal"][ne] expression.
        ///
        /// [not equal][ne]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        Neq,
        /// A binary ["greater than"][gt] expression.
        ///
        /// [gt]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        Gt,
        /// A binary ["less than"][lt] expression.
        ///
        /// [lt]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        Lt,
        /// A binary ["greater than or equal to"][gte] expression.
        ///
        /// [gte]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        GtEq,
        /// A binary ["less than or equal to"][lte] expression.
        ///
        /// [lte]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        LtEq,
    }
}

hir_type! {
    /// A unary operation.
    pub(crate) enum UnaryOp {
        /// A unary [negation] operation.
        ///
        /// [negation]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#prefix-operators
        Neg,
        /// A unary logical [negation] operation.
        ///
        /// [negation]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#prefix-operators
        Not,
        /// A unary [`unwrap`] operation.
        ///
        /// [`unwrap`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#prefix-operators
        Check,
        /// A unary [`check_unwrap`] operation.
        ///
        /// [`check_unwrap`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#prefix-operators
        CheckUnwrap,
    }
}

hir_type! {
    /// `match` used as an expression.
    pub(crate) struct MatchExpr<'ctx> {
        pub scrutinee: &'ctx Expr<'ctx>,
        pub arms: &'ctx [MatchExprArm<'ctx>],
    }
}

hir_type! {
    /// An arm in a [`MatchExpr`].
    pub(crate) struct MatchExprArm<'ctx> {
        pub pattern: MatchPattern<'ctx>,
        pub expr: &'ctx Expr<'ctx>,
    }
}

hir_type! {
    /// A named struct.
    pub(crate) struct NamedStruct<'ctx> {
        pub ident: Ident,
        pub fields: &'ctx [StructFieldExpr<'ctx>],
    }
}

hir_type! {
    /// A field expression.
    pub(crate) struct StructFieldExpr<'ctx> {
        pub ident: IdentId,
        pub expr: &'ctx Expr<'ctx>,
    }
}

hir_type! {
    /// An intrinsic implemented by the VM.
    pub(crate) enum Intrinsic<'ctx> {
        /// A [`query`] expression.
        ///
        /// [`query`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#query
        Query(&'ctx FactLiteral<'ctx>),
        /// One of the [`count_up_to`], `at_least`, `at_most`, or
        /// `exactly` expressions.
        ///
        /// NB: [`exists`] is desugared to `at_least 1`.
        ///
        /// [`count_up_to`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#count_up_to
        /// [`exists`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#exists
        FactCount(FactCountType, i64, &'ctx FactLiteral<'ctx>),
        /// A `serialize` expression.
        ///
        /// [`serialize`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#serializedeserialize
        Serialize(&'ctx Expr<'ctx>),
        /// A `deserialize` expression.
        ///
        /// [`deserialize`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#serializedeserialize
        Deserialize(&'ctx Expr<'ctx>),
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
    // TODO(eric): rename to FactLit
    pub(crate) struct FactLiteral<'ctx> {
        pub ident: Ident,
        pub keys: &'ctx [FactFieldExpr<'ctx>],
        pub vals: &'ctx [FactFieldExpr<'ctx>],
    }
}

hir_type! {
    /// A fact field expression.
    ///
    /// ```policy
    /// query Foo[x: 42]=>{y: true}
    ///           ^^^^^    ^^^^^^^
    /// ```
    pub(crate) struct FactFieldExpr<'ctx> {
        pub ident: IdentId,
        pub expr: FactField<'ctx>,
    }
}

hir_type! {
    /// Either an expression or "?".
    pub(crate) enum FactField<'ctx> {
        Expr(&'ctx Expr<'ctx>),
        Bind,
    }
}

hir_type! {
    /// A function call.
    pub(crate) struct FunctionCall<'ctx> {
        pub ident: Ident,
        pub args: &'ctx [Expr<'ctx>],
    }
}

hir_type! {
    pub(crate) struct ForeignFunctionCall<'ctx> {
        pub module: IdentId,
        pub ident: Ident,
        pub args: &'ctx [Expr<'ctx>],
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
        pub ident: Ident,
        /// The enum's variant.
        pub value: Ident,
    }
}

hir_node! {
    /// A fact definition.
    pub(crate) struct FactDef<'ctx> {
        pub id: FactId,
        pub ident: Ident,
        pub keys: &'ctx [FactKey<'ctx>],
        pub vals: &'ctx [FactVal<'ctx>],
    }
}

hir_node! {
    /// A fact key.
    pub(crate) struct FactKey<'ctx> {
        pub id: FactKeyId,
        pub ident: Ident,
        pub ty: &'ctx VType<'ctx>,
    }
}

hir_node! {
    /// A fact value.
    pub(crate) struct FactVal<'ctx> {
        pub id: FactValId,
        pub ident: Ident,
        pub ty: &'ctx VType<'ctx>,
    }
}

hir_node! {
    /// A finish function definition.
    pub(crate) struct FinishFuncDef<'ctx> {
        pub id: FinishFuncId,
        pub ident: Ident,
        pub sig: &'ctx FinishFuncSig<'ctx>,
        pub block: &'ctx Block<'ctx>,
    }
}

hir_type! {
    pub(crate) struct FinishFuncSig<'ctx> {
        pub args: &'ctx [FinishFuncArg<'ctx>],
    }
}

hir_node! {
    /// A finish function argument
    pub(crate) struct FinishFuncArg<'ctx> {
        pub id: FinishFuncArgId,
        pub ident: Ident,
        pub ty: &'ctx VType<'ctx>,
    }
}

hir_node! {
    /// A function definition.
    pub(crate) struct FuncDef<'ctx> {
        pub id: FuncId,
        pub ident: Ident,
        pub sig: &'ctx FuncSig<'ctx>,
        pub block: &'ctx Block<'ctx>,
    }
}

hir_type! {
    pub(crate) struct FuncSig<'ctx> {
        pub args: &'ctx [FuncArg<'ctx>],
        pub result: &'ctx VType<'ctx>,
    }
}

hir_node! {
    /// A function argument
    pub(crate) struct FuncArg<'ctx> {
        pub id: FuncArgId,
        pub ident: Ident,
        pub ty: &'ctx VType<'ctx>,
    }
}

hir_node! {
    /// A global let definition.
    pub(crate) struct GlobalLetDef<'ctx> {
        pub id: GlobalId,
        pub ident: Ident,
        pub expr: &'ctx Expr<'ctx>,
    }
}

hir_node! {
    /// A statement.
    pub(crate) struct Stmt<'ctx> {
        pub id: StmtId,
        pub kind: StmtKind<'ctx>,
        /// `true` if this statement could return.
        ///
        /// NB: This could be true for more than just
        /// [`StmtKind::Return`].
        pub returns: bool,
    }
}

hir_type! {
    /// The kind of a statement.
    pub(crate) enum StmtKind<'ctx> {
        Let(LetStmt<'ctx>),
        Check(CheckStmt<'ctx>),
        Match(MatchStmt<'ctx>),
        If(IfStmt<'ctx>),
        Finish(&'ctx Block<'ctx>),
        Map(MapStmt<'ctx>),
        Return(ReturnStmt<'ctx>),
        ActionCall(ActionCall<'ctx>),
        Publish(Publish<'ctx>),
        Create(Create<'ctx>),
        Update(Update<'ctx>),
        Delete(Delete<'ctx>),
        Emit(Emit<'ctx>),
        FunctionCall(FunctionCall<'ctx>),
        DebugAssert(DebugAssert<'ctx>),
    }
}

hir_type! {
    /// A let statement.
    ///
    /// ```policy
    /// let foo = 42;
    ///     ^^^   ^^
    ///    ident  expr
    /// ```
    pub(crate) struct LetStmt<'ctx> {
        pub ident: Ident,
        pub expr: &'ctx Expr<'ctx>,
    }
}

hir_type! {
    /// A check statement.
    ///
    /// ```policy
    /// check x > 0;
    ///       ^^^^^ expr
    /// ```
    pub(crate) struct CheckStmt<'ctx> {
        pub expr: &'ctx Expr<'ctx>,
    }
}

hir_type! {
    /// A match statement.
    pub(crate) struct MatchStmt<'ctx> {
        pub expr: &'ctx Expr<'ctx>,
        pub arms: &'ctx [MatchArm<'ctx>],
    }
}

hir_type! {
    /// A match statement arm.
    pub(crate) struct MatchArm<'ctx> {
        pub pattern: &'ctx MatchPattern<'ctx>,
        pub block: &'ctx Block<'ctx>,
    }
}

hir_type! {
    /// A match arm pattern.
    pub(crate) enum MatchPattern<'ctx> {
        Default,
        Values(&'ctx [Expr<'ctx>]),
    }
}

hir_type! {
    /// An if statement.
    pub(crate) struct IfStmt<'ctx> {
        pub branches: &'ctx [IfBranch<'ctx>],
        pub else_block: Option<&'ctx Block<'ctx>>,
    }
}

hir_type! {
    /// An if statement branch.
    pub(crate) struct IfBranch<'ctx> {
        pub expr: &'ctx Expr<'ctx>,
        pub block: &'ctx Block<'ctx>,
    }
}

hir_type! {
    /// A map statement.
    pub(crate) struct MapStmt<'ctx> {
        pub fact: &'ctx FactLiteral<'ctx> ,
        pub ident: Ident,
        pub block: &'ctx Block<'ctx>,
    }
}

hir_type! {
    /// A return statement.
    pub(crate) struct ReturnStmt<'ctx> {
        pub expr: &'ctx Expr<'ctx>,
    }
}

hir_type! {
    /// Calling an action.
    pub(crate) struct ActionCall<'ctx> {
        pub ident: Ident,
        pub args: &'ctx [Expr<'ctx>],
    }
}

hir_type! {
    /// A publish statement.
    pub(crate) struct Publish<'ctx> {
        pub expr: &'ctx Expr<'ctx>,
    }
}

hir_type! {
    /// A create statement.
    pub(crate) struct Create<'ctx> {
        pub fact: &'ctx FactLiteral<'ctx>,
    }
}

hir_type! {
    /// An update statement.
    pub(crate) struct Update<'ctx> {
        pub fact: &'ctx FactLiteral<'ctx>,
        pub to: &'ctx [(Ident, &'ctx FactField<'ctx>)],
    }
}

hir_type! {
    /// A delete statement.
    pub(crate) struct Delete<'ctx> {
        pub fact: &'ctx FactLiteral<'ctx>,
    }
}

hir_type! {
    /// An emit statement.
    pub(crate) struct Emit<'ctx> {
        pub expr: &'ctx Expr<'ctx>,
    }
}

hir_type! {
    /// A debug assert statement.
    pub(crate) struct DebugAssert<'ctx> {
        pub expr: &'ctx Expr<'ctx>,
    }
}

hir_node! {
    /// A struct definition.
    pub(crate) struct StructDef<'ctx> {
        pub id: StructId,
        pub ident: Ident,
        pub items: &'ctx [StructField<'ctx>],
    }
}

hir_node! {
    /// A struct field.
    pub(crate) struct StructField<'ctx> {
        pub id: StructFieldId,
        pub kind: StructFieldKind<'ctx>,
    }
}

hir_type! {
    /// The kind of an struct field.
    pub(crate) enum StructFieldKind<'ctx> {
        /// A regular field with an identifier and type
        Field { ident: Ident, ty: &'ctx VType<'ctx> },
        /// A reference to another struct whose fields should be included
        StructRef(Ident),
    }
}

hir_node! {
    /// An identifier.
    ///
    /// NB: All `Ident`s are unique, even if they refer to the
    /// same [`Identifier`][ast::Identifier] string.
    pub(crate) struct Ident {
        pub id: IdentId,
        pub ident: InternedIdent,
    }
}

hir_type! {
    /// A ternary [`if`] expression.
    ///
    /// [`if`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#if
    pub(crate) struct Ternary<'ctx> {
        /// The condition being evaluated.
        pub cond: &'ctx Expr<'ctx>,
        /// The result when `cond` is true.
        pub true_expr: &'ctx Expr<'ctx>,
        /// The result when `cond` is false.
        pub false_expr: &'ctx Expr<'ctx>,
    }
}

hir_node! {
    pub(crate) struct VType<'ctx> {
        pub id: VTypeId,
        pub kind: VTypeKind<'ctx>,
    }
}

hir_type! {
    pub(crate) enum VTypeKind<'ctx> {
        String,
        Bytes,
        Int,
        Bool,
        Id,
        Struct(Ident),
        Enum(Ident),
        Optional(&'ctx VType<'ctx>),
    }
}

hir_node! {
    /// An FFI import statement (e.g., `use crypto`).
    pub(crate) struct FfiImportDef {
        pub id: FfiImportId,
        pub module: Ident,
    }
}

hir_node! {
    /// An FFI module definition.
    pub(crate) struct FfiModuleDef<'ctx> {
        pub id: FfiModuleId,
        pub ident: Ident,
        pub functions: &'ctx [FfiFuncDef<'ctx>],
        pub structs: &'ctx [FfiStructDef<'ctx>],
        pub enums: &'ctx [FfiEnumDef<'ctx>],
    }
}

hir_node! {
    /// An FFI function definition.
    pub(crate) struct FfiFuncDef<'ctx> {
        pub id: FfiFuncId,
        pub ident: Ident,
        pub args: &'ctx [(Ident, &'ctx VType<'ctx>)],
        pub return_type: &'ctx VType<'ctx>,
    }
}

hir_node! {
    /// An FFI struct definition.
    pub(crate) struct FfiStructDef<'ctx> {
        pub id: FfiStructId,
        pub ident: Ident,
        pub fields: &'ctx [(Ident, &'ctx VType<'ctx>)],
    }
}

hir_node! {
    /// An FFI enum definition.
    pub(crate) struct FfiEnumDef<'ctx> {
        pub id: FfiEnumId,
        pub ident: Ident,
        pub variants: &'ctx [Ident],
    }
}
