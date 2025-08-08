use std::{
    fmt,
    hash::Hash,
    ops::{BitAnd, BitAndAssign, Index, Range},
};

use aranya_policy_ast as ast;
use serde::{Deserialize, Serialize};

use crate::{arena::Arena, intern::typed_interner};

typed_interner! {
    pub(crate) struct IdentInterner(ast::Identifier) => IdentRef;
}

typed_interner! {
    pub(crate) struct TextInterner(ast::Text) => TextRef;
}

macro_rules! hir {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[$field_meta:meta])*
                pub $field:ident: Arena<$key:ident, $val:ident>
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis struct $name {
            $(
                $(#[$field_meta])*
                pub $field: Arena<$key, $val>,
            )*
        }

        impl $name {
            pub fn lookup(&self, id: NodeId) -> Node<'_> {
                match id {
                    $(NodeId::$key(id) => Node::$val(self.index(id))),*
                }
            }
        }

        $(
            impl Index<$key> for $name {
                type Output = $val;
                fn index(&self, id: $key) -> &Self::Output {
                    &self.$field[id]
                }
            }
            impl<'hir> Index<$key> for &'hir $name {
                type Output = $val;
                fn index(&self, id: $key) -> &Self::Output {
                    &self.$field[id]
                }
            }
        )*

        #[derive(
            Clone,
            Debug,
            Eq,
            PartialEq,
        )]
        $vis enum Node<'hir> {
            $($val(&'hir $val)),*
        }

        #[derive(
            Copy,
            Clone,
            Debug,
            Eq,
            PartialEq,
            Ord,
            PartialOrd,
            Hash,
            Serialize,
            Deserialize,
        )]
        $vis enum NodeId {
            $($key($key)),*
        }
        $(impl From<$key> for NodeId {
            fn from(id: $key) -> Self {
                Self::$key(id)
            }
        })*
    };
}

hir! {
    /// High-level Intermediate Representation (HIR).
    ///
    /// The HIR is a simplified, desugared representation of the
    /// [`Policy`][ast::Policy] AST that makes semantic analysis
    /// and code generation easier. It stores all policy
    /// definitions in arena-allocated collections indexed by
    /// typed IDs.
    #[derive(Clone, Default, Debug, Serialize, Deserialize)]
    pub(crate) struct Hir {
        /// Action definitions.
        pub actions: Arena<ActionId, ActionDef>,
        /// Arguments for action definitions
        pub action_args: Arena<ActionArgId, ActionArg>,
        /// Command definitions.
        pub cmds: Arena<CmdId, CmdDef>,
        /// Fields within command definitions
        pub cmd_fields: Arena<CmdFieldId, CmdField>,
        /// Effect definitions
        pub effects: Arena<EffectId, EffectDef>,
        /// Fields within effect definitions
        pub effect_fields: Arena<EffectFieldId, EffectField>,
        /// Enumeration type definitions
        pub enums: Arena<EnumId, EnumDef>,
        /// Fact definitions
        pub facts: Arena<FactId, FactDef>,
        /// Key fields for fact definitions
        pub fact_keys: Arena<FactKeyId, FactKey>,
        /// Value fields for fact definitions
        pub fact_vals: Arena<FactValId, FactVal>,
        /// Finish function definitions
        pub finish_funcs: Arena<FinishFuncId, FinishFuncDef>,
        /// Arguments for finish function definitions
        pub finish_func_args: Arena<FinishFuncArgId, FinishFuncArg>,
        /// Regular function definitions
        pub funcs: Arena<FuncId, FuncDef>,
        /// Arguments for function definitions
        pub func_args: Arena<FuncArgId, FuncArg>,
        /// Global constant definitions
        pub global_lets: Arena<GlobalId, GlobalLetDef>,
        /// Structure type definitions
        pub structs: Arena<StructId, StructDef>,
        /// Fields within structure definitions
        pub struct_fields: Arena<StructFieldId, StructField>,
        /// All statements
        pub stmts: Arena<StmtId, Stmt>,
        /// All expressions
        pub exprs: Arena<ExprId, Expr>,
        /// All identifiers
        pub idents: Arena<IdentId, Ident>,
        /// Statement blocks (collections of statements)
        pub blocks: Arena<BlockId, Block>,
        /// Type definitions and references
        pub types: Arena<VTypeId, VType>,
        /// FFI import statements from the policy
        pub ffi_imports: Arena<FfiImportId, FfiImportDef>,
        /// FFI module definitions
        pub ffi_modules: Arena<FfiModuleId, FfiModuleDef>,
        /// FFI function definitions
        pub ffi_funcs: Arena<FfiFuncId, FfiFuncDef>,
        /// FFI function arguments
        pub ffi_func_args: Arena<FfiFuncArgId, FfiFuncArg>,
        /// FFI struct definitions
        pub ffi_structs: Arena<FfiStructId, FfiStructDef>,
        /// FFI struct fields.
        pub ffi_struct_fields: Arena<FfiStructFieldId, FfiStructField>,
        /// FFI enum definitions
        pub ffi_enums: Arena<FfiEnumId, FfiEnumDef>,
    }
}

/// A span representing a range in the source text.
#[derive(Copy, Clone, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Span {
    /// The start position in the source text (in bytes).
    pub start: usize,
    /// The end position in the source text (in bytes).
    pub end: usize,
}

impl Span {
    /// Creates a new span with the given start and end
    /// positions.
    pub fn new(start: usize, end: usize) -> Self {
        debug_assert!(start <= end, "{start} {end}");

        Self { start, end }
    }

    /// Creates a span where start and end positions are the
    /// same.
    pub fn point(pos: usize) -> Self {
        Self::new(pos, pos)
    }

    /// Merges the two spans.
    pub fn merge(self, rhs: Self) -> Self {
        Self::new(self.start.min(rhs.start), self.end.max(rhs.end))
    }

    /// Reports whether `start == end`.
    pub fn is_empty(self) -> bool {
        self.start == self.end
    }

    /// Converts the span into a [`Range`].
    pub fn into_range(self) -> Range<usize> {
        self.start..self.end
    }
}

impl From<Span> for Range<usize> {
    fn from(span: Span) -> Self {
        span.start..span.end
    }
}

impl From<aranya_policy_module::Span<'_>> for Span {
    fn from(span: aranya_policy_module::Span<'_>) -> Self {
        Self::new(span.start(), span.end())
    }
}

impl fmt::Debug for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
    }
}

/// Generates an ID type for a HIR node.
macro_rules! make_node_id {
    ($(#[$meta:meta])* $vis:vis struct $name:ident; $($rest:tt)*) => {
        $crate::arena::new_key_type! {
            $(#[$meta])*
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
        impl From<$name> for Span {
            fn from(node: $name) -> Self {
                node.span
            }
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
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
        $vis struct $name $(<$lt>)? { $($body)* }
    };
    // `enum`
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident $(<$lt:lifetime>)? { $($body:tt)* }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
        $vis enum $name $(<$lt>)? { $($body)* }
    };
}

hir_node! {
    /// An action definition.
    pub(crate) struct ActionDef {
        pub id: ActionId,
        pub ident: IdentId,
        pub sig: ActionSig,
        /// The body of the action.
        pub block: BlockId,
    }
}

hir_type! {
    pub(crate) struct ActionSig {
        pub args: Vec<ActionArgId>,
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
        pub expr: Option<ExprId>,
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
        /// A regular field with an identifier and type.
        Field { ident: IdentId, ty: VTypeId },
        /// A reference to another struct whose fields should be
        /// included.
        StructRef(IdentId),
    }
}

hir_type! {
    pub(crate) struct FieldDef {
        pub ident: IdentId,
        pub ty: VTypeId,
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
        /// A regular field with an identifier and type.
        Field { ident: IdentId, ty: VTypeId },
        /// A reference to another struct whose fields should be
        /// included.
        StructRef(IdentId),
    }
}

hir_node! {
    /// An [enum] definition.
    ///
    /// [enum]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#enumerations
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
    /// A literal.
    pub(crate) struct Lit {
        pub kind: LitKind,
    }
}

hir_type! {
    pub(crate) enum LitKind {
        /// A 64-bit signed integer literal.
        Int(i64),
        /// A text string literal.
        String(TextRef),
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
        Optional(Option<ExprId>),
        /// A named struct literal.
        // TODO(eric): This isn't a literal per-se.
        NamedStruct(NamedStruct),
        /// A fact literal.
        // TODO(eric): This isn't a literal per-se.
        Fact(FactLiteral),
    }
}

hir_type! {
    /// An expression.
    pub(crate) enum ExprKind {
        /// A literal.
        Lit(Lit),
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
        EnumRef(EnumRef),
        /// A binary operation.
        Binary(BinOp, ExprId, ExprId),
        /// A unary operation.
        Unary(UnaryOp, ExprId),
        /// A [field access] expression.
        ///
        /// [field access]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#binary-operators
        // TODO(eric): Make this Dot(Dot) so it's more clear.
        Dot(ExprId, IdentId),
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
    /// A binary opeation.
    #[derive(Copy)]
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
    #[derive(Copy)]
    pub(crate) enum UnaryOp {
        /// A unary [negation] operation.
        ///
        /// [negation]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#prefix-operators
        Neg,
        /// A unary logical [negation] operation.
        ///
        /// [negation]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#prefix-operators
        Not,
        /// A unary [`check`] operation.
        ///
        /// [`check`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#prefix-operators
        Check,
        /// A unary [`check_unwrap`] operation.
        ///
        /// [`check_unwrap`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#prefix-operators
        CheckUnwrap,
        /// A unary [`unwrap`] operation.
        ///
        /// [`unwrap`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#prefix-operators
        Unwrap,
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
    // TODO(eric): Rename this `StructExpr`?
    pub(crate) struct NamedStruct {
        pub ident: IdentId,
        pub fields: Vec<StructFieldExpr>,
    }
}

hir_type! {
    /// A field expression.
    pub(crate) struct StructFieldExpr {
        pub ident: IdentId,
        pub expr: ExprId,
    }
}

hir_type! {
    /// An intrinsic implemented by the VM.
    pub(crate) enum Intrinsic {
        /// A [`query`] expression.
        ///
        /// [`query`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#query
        Query( FactLiteral),
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
        Serialize( ExprId),
        /// A `deserialize` expression.
        ///
        /// [`deserialize`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#serializedeserialize
        Deserialize( ExprId),
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
    pub(crate) struct FactLiteral {
        pub ident: IdentId,
        pub keys: Vec<FactFieldExpr>,
        pub vals: Vec<FactFieldExpr>,
    }
}

hir_type! {
    /// A fact field expression.
    ///
    /// ```policy
    /// query Foo[x: 42]=>{y: true}
    ///           ^^^^^    ^^^^^^^
    /// ```
    pub(crate) struct FactFieldExpr {
        pub ident: IdentId,
        pub expr: FactField,
    }
}

hir_type! {
    /// Either an expression or "?".
    // TODO(eric): Rename this `FactFieldExprKind`.
    #[derive(Copy)]
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
        // TODO(eric): Rename this to `variant`.
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
    /// A [finish function] definition.
    ///
    /// [finish function]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#functions
    pub(crate) struct FinishFuncDef {
        pub id: FinishFuncId,
        pub ident: IdentId,
        pub sig: FinishFuncSig,
        /// The body of the finish function.
        pub block: BlockId,
    }
}

hir_type! {
    /// A finish function signature.
    pub(crate) struct FinishFuncSig {
        pub args: Vec<FinishFuncArgId>,
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
    /// A [function] definition.
    ///
    /// [function]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#functions
    pub(crate) struct FuncDef {
        pub id: FuncId,
        pub ident: IdentId,
        pub sig: FuncSig,
        /// The body of the function.
        pub block: BlockId,
    }
}

hir_type! {
    /// A function signature.
    pub(crate) struct FuncSig {
        pub args: Vec<FuncArgId>,
        pub result: VTypeId,
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
    /// A [let] statement.
    ///
    /// ```policy
    /// let foo = 42;
    ///     ^^^   ^^
    ///    ident  expr
    /// ```
    ///
    /// [let]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#let
    pub(crate) struct LetStmt {
        pub ident: IdentId,
        pub expr: ExprId,
    }
}

hir_type! {
    /// A [check] statement.
    ///
    /// ```policy
    /// check x > 0;
    ///       ^^^^^ expr
    /// ```
    ///
    /// [check]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#check
    pub(crate) struct CheckStmt {
        pub expr: ExprId,
    }
}

hir_type! {
    /// A [match] statement.
    ///
    /// [match]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#match
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
    /// A [publish] statement.
    ///
    /// [publish]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#publish
    pub(crate) struct Publish {
        pub expr: ExprId,
    }
}

hir_type! {
    /// A [create] statement.
    ///
    /// [create]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#create
    pub(crate) struct Create {
        pub fact: FactLiteral,
    }
}

hir_type! {
    /// An [update] statement.
    ///
    /// [update]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#update
    pub(crate) struct Update {
        pub fact: FactLiteral,
        pub to: Vec<FactFieldExpr>,
    }
}

hir_type! {
    /// A [delete] statement.
    ///
    /// [delete]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#delete
    pub(crate) struct Delete {
        pub fact: FactLiteral,
    }
}

hir_type! {
    /// An [emit] statement.
    ///
    /// [emit]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#emit
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
    /// A [struct] definition.
    ///
    /// [struct]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#structs
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
    /// The kind of a struct field.
    pub(crate) enum StructFieldKind {
        /// A regular field with an identifier and type.
        Field { ident: IdentId, ty: VTypeId },
        /// A reference to another struct whose fields should be
        /// included.
        StructRef(IdentId),
    }
}

hir_node! {
    /// An identifier.
    ///
    /// All `Ident`s have a unique ID, even if they refer to the
    /// same [`Identifier`]. To determine if two `Ident`s refer
    /// to the same [`Identifier`], compare their `xref` fields.
    ///
    /// An `Ident` can refer to either a definition or usage. For
    /// example:
    ///
    /// ```policy
    /// function foo() int { return 42 }
    ///          ^^^
    ///          └ definition of `foo`
    ///
    /// function bar(x int) int {
    ///          ^^^ ^
    ///          │   └ definition of `x`
    ///          └ definition of `bar`
    ///     return foo() + x
    ///            ^^^     ^
    ///            │       └ usage of `x`
    ///            └ usage of `foo`
    /// }
    /// ```
    ///
    /// The code snippet above has five `Ident`s:
    ///
    /// 1 `foo` (definition)
    /// 2. `bar` (definition)
    /// 3. `x` (definition)
    /// 4. `foo` (usage)
    /// 5. `x` (usage)
    ///
    /// [`Identifier`]: [ast::Identifier]
    pub(crate) struct Ident {
        pub id: IdentId,
        /// The interned identifier.
        pub xref: IdentRef,
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
    /// The type of a value (variable, argument, field, etc.).
    pub(crate) struct VType {
        pub id: VTypeId,
        pub kind: VTypeKind,
    }
}

hir_type! {
    pub(crate) enum VTypeKind {
        /// A UTF-8 [string].
        ///
        /// It cannot contain null bytes.
        ///
        /// [string]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#string
        String,
        /// An arbitrary sequence of [bytes].
        ///
        /// [bytes]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#bytes
        Bytes,
        /// A signed, 64-bit [integer].
        ///
        /// [integer]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#int
        Int,
        /// Either true or false.
        Bool,
        /// An opaque type for [identifiers].
        ///
        /// Cannot be used as a literal.
        ///
        /// [identifiers]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#id
        Id,
        /// An ordered collection of fields.
        ///
        /// The `IdentId` refers to one of:
        ///
        /// - A [`StructDef`].
        /// - An [`FfiStructDef`].
        /// - A [`CmdDef`].
        /// - An [`EffectDef`].
        /// - A [`FactDef`].
        Struct(IdentId),
        /// An enumeration.
        ///
        /// The `IdentId` refers to one of:
        ///
        /// - An [`EnumDef`].
        /// - An [`FfiEnumDef`].
        Enum(IdentId),
        /// An [optional] type.
        ///
        /// [optiona]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#optional-type
        Optional(VTypeId),
    }
}

hir_node! {
    /// An FFI import statement (e.g., `use crypto`).
    pub(crate) struct FfiImportDef {
        pub id: FfiImportId,
        pub ident: IdentId,
    }
}

hir_node! {
    /// An FFI module definition.
    pub(crate) struct FfiModuleDef {
        pub id: FfiModuleId,
        pub ident: IdentId,
        pub funcs: Vec<FfiFuncId>,
        pub structs: Vec<FfiStructId>,
        pub enums: Vec<FfiEnumId>,
    }
}

hir_node! {
    /// An FFI function definition.
    pub(crate) struct FfiFuncDef {
        pub id: FfiFuncId,
        pub ident: IdentId,
        pub sig: FfiFuncSig,
    }
}

hir_type! {
    pub(crate) struct FfiFuncSig {
        pub args: Vec<FfiFuncArgId>,
        pub result: VTypeId,
    }
}

hir_node! {
    /// An FFI function argument.
    pub(crate) struct FfiFuncArg {
        pub id: FfiFuncArgId,
        pub ident: IdentId,
        pub ty: VTypeId,
    }
}

hir_node! {
    /// An FFI struct definition.
    pub(crate) struct FfiStructDef {
        pub id: FfiStructId,
        pub ident: IdentId,
        pub fields: Vec<FfiStructFieldId>,
    }
}

hir_node! {
    /// An FFI struct field.
    pub(crate) struct FfiStructField {
        pub id: FfiStructFieldId,
        pub kind: FfiStructFieldKind,
    }
}

hir_type! {
    /// The kind of an FFI struct field.
    pub(crate) enum FfiStructFieldKind {
        /// A regular field with an identifier and type.
        Field { ident: IdentId, ty: VTypeId },
        /// A reference to another struct whose fields should be
        /// included.
        StructRef(IdentId),
    }
}

hir_node! {
    /// An FFI enum definition.
    pub(crate) struct FfiEnumDef {
        pub id: FfiEnumId,
        pub ident: IdentId,
        pub variants: Vec<IdentId>,
    }
}
