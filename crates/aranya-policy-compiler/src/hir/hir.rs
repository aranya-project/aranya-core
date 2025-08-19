#![expect(clippy::enum_variant_names)]

use std::{
    fmt,
    hash::Hash,
    ops::{BitAnd, BitAndAssign, Index, Range},
};

use aranya_policy_ast as ast;
use serde::{Deserialize, Serialize};

use crate::{
    arena::{Arena, Key},
    intern::typed_interner,
};

typed_interner! {
    pub struct IdentInterner(ast::Identifier) => IdentRef;
}

typed_interner! {
    pub struct TextInterner(ast::Text) => TextRef;
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

        /// TODO: docs
        #[derive(
            Clone,
            Debug,
            Eq,
            PartialEq,
        )]
        $vis enum Node<'hir> {
            $($val(&'hir $val)),*
        }

        $(impl<'hir> From<&'hir $val> for Node<'hir> {
            fn from(val: &'hir $val) -> Self {
                Self::$val(val)
            }
        })*

        /// TODO: docs
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
    pub struct Hir {
        /// Action definitions.
        pub actions: Arena<ActionId, ActionDef>,
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
        /// Regular function definitions
        pub funcs: Arena<FuncId, FuncDef>,
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
        /// Function/action bodies.
        pub bodies: Arena<BodyId, Body>,
        /// Function/action parameters.
        pub params: Arena<ParamId, Param>,
        /// Type definitions and references
        pub types: Arena<VTypeId, VType>,
        /// FFI import statements from the policy
        pub ffi_imports: Arena<FfiImportId, FfiImportDef>,
        /// FFI module definitions
        pub ffi_modules: Arena<FfiModuleId, FfiModuleDef>,
        /// FFI function definitions
        pub ffi_funcs: Arena<FfiFuncId, FfiFuncDef>,
        /// FFI struct definitions
        pub ffi_structs: Arena<FfiStructId, FfiStructDef>,
        /// FFI struct fields.
        pub ffi_struct_fields: Arena<FfiStructFieldId, FfiStructField>,
        /// FFI enum definitions
        pub ffi_enums: Arena<FfiEnumId, FfiEnumDef>,
    }
}

impl Node<'_> {
    pub fn ident(&self) -> Option<IdentId> {
        let ident = match self {
            Self::ActionDef(ActionDef { ident, .. })
            | Self::CmdDef(CmdDef { ident, .. })
            | Self::EffectDef(EffectDef { ident, .. })
            | Self::EnumDef(EnumDef { ident, .. })
            | Self::FactDef(FactDef { ident, .. })
            | Self::FinishFuncDef(FinishFuncDef { ident, .. })
            | Self::FuncDef(FuncDef { ident, .. })
            | Self::GlobalLetDef(GlobalLetDef { ident, .. })
            | Self::StructDef(StructDef { ident, .. })
            | Self::FfiImportDef(FfiImportDef { ident, .. })
            | Self::FfiModuleDef(FfiModuleDef { ident, .. })
            | Self::FfiFuncDef(FfiFuncDef { ident, .. })
            | Self::FfiStructDef(FfiStructDef { ident, .. })
            | Self::FfiEnumDef(FfiEnumDef { ident, .. }) => *ident,
            Self::CmdField(node) => match &node.kind {
                CmdFieldKind::Field { ident, .. } | CmdFieldKind::StructRef(ident) => *ident,
            },
            Self::EffectField(node) => match &node.kind {
                EffectFieldKind::Field { ident, .. } | EffectFieldKind::StructRef(ident) => *ident,
            },
            Self::StructField(node) => match &node.kind {
                StructFieldKind::Field { ident, .. } | StructFieldKind::StructRef(ident) => *ident,
            },
            Self::FfiStructField(node) => match &node.kind {
                FfiStructFieldKind::Field { ident, .. } | FfiStructFieldKind::StructRef(ident) => {
                    *ident
                }
            },
            Self::FactKey(FactKey { ident, .. })
            | Self::FactVal(FactVal { ident, .. })
            | Self::Param(Param { ident, .. }) => *ident,
            Self::Ident(Ident { id, .. }) => *id,
            Self::Block(_) | Self::Body(_) | Self::Expr(_) | Self::Stmt(_) | Self::VType(_) => {
                return None;
            }
        };
        Some(ident)
    }
}

/// Generates a HIR node.
///
/// It ensures that all HIR nodes have:
/// - An `id` field
/// - A `span` field
/// - Consistent derive attributes (Clone, Debug, Eq, PartialEe,
///   etc.)
macro_rules! hir_node {
    // With `ident`.
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            pub id: $id:ident,
            pub ident: IdentId,
            $(
                $(#[$field_meta:meta])*
                pub $field:ident: $ty:ty
            ),* $(,)?
        }
    ) => {
        hir_node! { @inner
            $(#[$meta])*
            $vis struct $name {
                pub id: $id,
                pub ident: IdentId,
                $(
                    $(#[$field_meta])*
                    pub $field: $ty
                ),*
            }
        }
        impl Named for $name {
            fn ident(&self) -> IdentId {
                self.ident
            }
        }
    };

    // Without `ident`.
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
        hir_node! { @inner
            $(#[$meta])*
            $vis struct $name {
                pub id: $id,
                $(
                    $(#[$field_meta])*
                    pub $field: $ty
                ),*
            }
        }
    };

    (@inner
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

        $crate::arena::new_key_type! {
            /// Uniquely identifies a
            #[doc = concat!("`", stringify!($name), "`")]
            $vis struct $id;
        }

        impl HirNode for $name {
            type Id = $id;

            fn id(&self) -> Self::Id {
                self.id
            }
        }

        impl Spanned for $name {
            fn span(&self) -> Span {
                self.span
            }
        }

        impl From<$name> for Span {
            fn from(node: $name) -> Self {
                node.span
            }
        }
    };
}

/// Implemented by all HIR nodes.
pub trait HirNode: Spanned {
    /// The node's ID.
    type Id: Key;

    /// Returns the node's ID.
    fn id(&self) -> Self::Id;
}

impl<T: HirNode> HirNode for &T {
    type Id = T::Id;
    fn id(&self) -> Self::Id {
        (*self).id()
    }
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
    pub struct Param {
        pub id: ParamId,
        /// The identifier of the parameter.
        pub ident: IdentId,
        /// The type of the parameter.
        pub ty: VTypeId,
    }
}

hir_node! {
    pub struct Body {
        pub id: BodyId,
        /// Function or action parameters.
        pub params: Vec<ParamId>,
        /// The statements in the body.
        pub stmts: Vec<StmtId>,
        /// `true` it any of the statements in the body contain
        /// a [`ReturnStmt`].
        pub returns: bool,
    }
}

hir_node! {
    /// An action definition.
    pub struct ActionDef {
        pub id: ActionId,
        pub ident: IdentId,
        pub body: BodyId,
    }
}

hir_node! {
    /// A block is a collection of statements.
    pub struct Block {
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
    pub struct CmdDef {
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
    pub struct CmdField {
        pub id: CmdFieldId,
        pub kind: CmdFieldKind,
    }
}

hir_type! {
    /// The kind of a command field.
    pub enum CmdFieldKind {
        /// A regular field with an identifier and type.
        Field { ident: IdentId, ty: VTypeId },
        /// A reference to another struct whose fields should be
        /// included.
        StructRef(IdentId),
    }
}

hir_type! {
    pub struct FieldDef {
        pub ident: IdentId,
        pub ty: VTypeId,
    }
}

hir_node! {
    /// An effect definition.
    pub struct EffectDef {
        pub id: EffectId,
        pub ident: IdentId,
        pub items: Vec<EffectFieldId>,
    }
}

hir_node! {
    /// An effect field.
    pub struct EffectField {
        pub id: EffectFieldId,
        pub kind: EffectFieldKind,
    }
}

hir_type! {
    /// The kind of an effect field.
    pub enum EffectFieldKind {
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
    pub struct EnumDef {
        pub id: EnumId,
        pub ident: IdentId,
        pub variants: Vec<IdentId>,
    }
}

hir_node! {
    /// An expression.
    pub struct Expr {
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
    pub enum Pure {
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
    pub struct Lit {
        pub kind: LitKind,
    }
}

hir_type! {
    pub enum LitKind {
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
    pub enum ExprKind {
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
    pub enum BinOp {
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
    pub enum UnaryOp {
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
    pub struct MatchExpr {
        pub scrutinee: ExprId,
        pub arms: Vec<MatchExprArm>,
    }
}

hir_type! {
    /// An arm in a [`MatchExpr`].
    pub struct MatchExprArm {
        pub pattern: MatchPattern,
        pub expr: ExprId,
    }
}

hir_type! {
    /// A named struct.
    // TODO(eric): Rename this `StructExpr`?
    pub struct NamedStruct {
        pub ident: IdentId,
        pub fields: Vec<StructFieldExpr>,
    }
}

hir_type! {
    /// A field expression.
    #[derive(Copy)]
    pub struct StructFieldExpr {
        pub ident: IdentId,
        pub expr: ExprId,
    }
}

hir_type! {
    /// An intrinsic implemented by the VM.
    pub enum Intrinsic {
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
    pub enum FactCountType {
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
    pub struct FactLiteral {
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
    pub struct FactFieldExpr {
        pub ident: IdentId,
        pub expr: FactField,
    }
}

hir_type! {
    /// Either an expression or "?".
    // TODO(eric): Rename this `FactFieldExprKind`.
    #[derive(Copy)]
    pub enum FactField {
        Expr(ExprId),
        Bind,
    }
}

hir_type! {
    /// A function call.
    pub struct FunctionCall {
        pub ident: IdentId,
        pub args: Vec<ExprId>,
    }
}

hir_type! {
    pub struct ForeignFunctionCall {
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
    pub struct EnumRef {
        /// The enum's identifier.
        pub ident: IdentId,
        /// The enum's variant.
        // TODO(eric): Rename this to `variant`.
        pub value: IdentId,
    }
}

hir_node! {
    /// A fact definition.
    pub struct FactDef {
        pub id: FactId,
        pub ident: IdentId,
        pub keys: Vec<FactKeyId>,
        pub vals: Vec<FactValId>,
    }
}

hir_node! {
    /// A fact key.
    pub struct FactKey {
        pub id: FactKeyId,
        pub ident: IdentId,
        pub ty: VTypeId,
    }
}

hir_node! {
    /// A fact value.
    pub struct FactVal {
        pub id: FactValId,
        pub ident: IdentId,
        pub ty: VTypeId,
    }
}

hir_node! {
    /// A [finish function] definition.
    ///
    /// [finish function]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#functions
    pub struct FinishFuncDef {
        pub id: FinishFuncId,
        pub ident: IdentId,
        pub body: BodyId,
    }
}

hir_node! {
    /// A [function] definition.
    ///
    /// [function]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#functions
    pub struct FuncDef {
        pub id: FuncId,
        pub ident: IdentId,
        pub result: VTypeId,
        pub body: BodyId,
    }
}

hir_node! {
    /// A global let definition.
    pub struct GlobalLetDef {
        pub id: GlobalId,
        pub ident: IdentId,
        pub expr: ExprId,
    }
}

hir_node! {
    /// A statement.
    pub struct Stmt {
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
    pub enum StmtKind {
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
    pub struct LetStmt {
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
    pub struct CheckStmt {
        pub expr: ExprId,
    }
}

hir_type! {
    /// A [match] statement.
    ///
    /// [match]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#match
    pub struct MatchStmt {
        pub expr: ExprId,
        pub arms: Vec<MatchArm>,
    }
}

hir_type! {
    /// A match statement arm.
    pub struct MatchArm {
        pub pattern: MatchPattern,
        pub block: BlockId,
    }
}

hir_type! {
    /// A match arm pattern.
    pub enum MatchPattern {
        Default,
        Values(Vec<ExprId>),
    }
}

hir_type! {
    /// An if statement.
    pub struct IfStmt {
        pub branches: Vec<IfBranch>,
        pub else_block: Option<BlockId>,
    }
}

hir_type! {
    /// An if statement branch.
    pub struct IfBranch {
        pub expr: ExprId,
        pub block: BlockId,
    }
}

hir_type! {
    /// A map statement.
    pub struct MapStmt {
        pub fact: FactLiteral,
        pub ident: IdentId,
        pub block: BlockId,
    }
}

hir_type! {
    /// A return statement.
    pub struct ReturnStmt {
        pub expr: ExprId,
    }
}

hir_type! {
    /// Calling an action.
    pub struct ActionCall {
        pub ident: IdentId,
        pub args: Vec<ExprId>,
    }
}

hir_type! {
    /// A [publish] statement.
    ///
    /// [publish]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#publish
    pub struct Publish {
        pub expr: ExprId,
    }
}

hir_type! {
    /// A [create] statement.
    ///
    /// [create]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#create
    pub struct Create {
        pub fact: FactLiteral,
    }
}

hir_type! {
    /// An [update] statement.
    ///
    /// [update]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#update
    pub struct Update {
        pub fact: FactLiteral,
        pub to: Vec<FactFieldExpr>,
    }
}

hir_type! {
    /// A [delete] statement.
    ///
    /// [delete]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#delete
    pub struct Delete {
        pub fact: FactLiteral,
    }
}

hir_type! {
    /// An [emit] statement.
    ///
    /// [emit]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#emit
    pub struct Emit {
        pub expr: ExprId,
    }
}

hir_type! {
    /// A debug assert statement.
    pub struct DebugAssert {
        pub expr: ExprId,
    }
}

hir_node! {
    /// A [struct] definition.
    ///
    /// [struct]: https://github.com/aranya-project/aranya-docs/blob/1ecf718ca179a431db724a4ada45129d96edcbf2/docs/policy-v1.md#structs
    pub struct StructDef {
        pub id: StructId,
        pub ident: IdentId,
        pub items: Vec<StructFieldId>,
    }
}

hir_node! {
    /// A struct field.
    pub struct StructField {
        pub id: StructFieldId,
        pub kind: StructFieldKind,
    }
}

hir_type! {
    /// The kind of a struct field.
    pub enum StructFieldKind {
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
    pub struct Ident {
        pub id: IdentId,
        /// The interned identifier.
        pub xref: IdentRef,
    }
}

/// Implemented by types that have a name (identifier).
pub trait Named {
    fn ident(&self) -> IdentId;
}

impl<T: Named> Named for &T {
    fn ident(&self) -> IdentId {
        (*self).ident()
    }
}

/// Marker trait for HIR nodes that represent global symbols.
///
/// Global symbols are top-level items that can be referenced
/// from anywhere in the program (e.g., actions, structs, enums).
///
/// NOTE: This list must be kept in sync with the types in
/// `for_each_top_level_item` macro in `visit.rs`.
pub trait GlobalSymbol: HirNode + Named {}

impl<T: GlobalSymbol> GlobalSymbol for &T {}

// Implement for all the top-level types
// Keep this list in sync with for_each_top_level_item macro in visit.rs
impl GlobalSymbol for ActionDef {}
impl GlobalSymbol for CmdDef {}
impl GlobalSymbol for EffectDef {}
impl GlobalSymbol for EnumDef {}
impl GlobalSymbol for FactDef {}
impl GlobalSymbol for FfiEnumDef {}
impl GlobalSymbol for FfiImportDef {}
impl GlobalSymbol for FfiModuleDef {}
impl GlobalSymbol for FfiStructDef {}
impl GlobalSymbol for FinishFuncDef {}
impl GlobalSymbol for FuncDef {}
impl GlobalSymbol for GlobalLetDef {}
impl GlobalSymbol for StructDef {}

hir_type! {
    /// A ternary [`if`] expression.
    ///
    /// [`if`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#if
    pub struct Ternary {
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
    pub struct VType {
        pub id: VTypeId,
        pub kind: VTypeKind,
    }
}

hir_type! {
    pub enum VTypeKind {
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
    pub struct FfiImportDef {
        pub id: FfiImportId,
        pub ident: IdentId,
    }
}

hir_node! {
    /// An FFI module definition.
    pub struct FfiModuleDef {
        pub id: FfiModuleId,
        pub ident: IdentId,
        pub funcs: Vec<FfiFuncId>,
        pub structs: Vec<FfiStructId>,
        pub enums: Vec<FfiEnumId>,
    }
}

hir_node! {
    /// An FFI function definition.
    pub struct FfiFuncDef {
        pub id: FfiFuncId,
        pub ident: IdentId,
        pub sig: FfiFuncSig,
    }
}

hir_type! {
    pub struct FfiFuncSig {
        pub args: Vec<ParamId>,
        pub result: VTypeId,
    }
}

hir_node! {
    /// An FFI struct definition.
    pub struct FfiStructDef {
        pub id: FfiStructId,
        pub ident: IdentId,
        pub fields: Vec<FfiStructFieldId>,
    }
}

hir_node! {
    /// An FFI struct field.
    pub struct FfiStructField {
        pub id: FfiStructFieldId,
        pub kind: FfiStructFieldKind,
    }
}

hir_type! {
    /// The kind of an FFI struct field.
    pub enum FfiStructFieldKind {
        /// A regular field with an identifier and type.
        Field { ident: IdentId, ty: VTypeId },
        /// A reference to another struct whose fields should be
        /// included.
        StructRef(IdentId),
    }
}

hir_node! {
    /// An FFI enum definition.
    pub struct FfiEnumDef {
        pub id: FfiEnumId,
        pub ident: IdentId,
        pub variants: Vec<IdentId>,
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

/// Implemented by types that have a span.
pub trait Spanned {
    fn span(&self) -> Span;
}

impl<T: Spanned> Spanned for &T {
    fn span(&self) -> Span {
        (*self).span()
    }
}
