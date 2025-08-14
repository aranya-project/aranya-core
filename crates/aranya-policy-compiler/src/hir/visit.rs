//#[cfg(test)]
//mod tests;

use std::{convert::Infallible, ops::ControlFlow};

use tracing::instrument;

use super::types::{
    ActionDef, ActionId, Block, BlockId, Body, BodyId, CmdDef, CmdField, CmdFieldId, CmdFieldKind,
    CmdId, EffectDef, EffectField, EffectFieldId, EffectFieldKind, EffectId, EnumDef, EnumId, Expr,
    ExprId, ExprKind, FactDef, FactField, FactFieldExpr, FactId, FactKey, FactKeyId, FactLiteral,
    FactVal, FactValId, FfiEnumDef, FfiEnumId, FfiFuncDef, FfiFuncId, FfiFuncSig, FfiImportDef,
    FfiImportId, FfiModuleDef, FfiModuleId, FfiStructDef, FfiStructField, FfiStructFieldId,
    FfiStructFieldKind, FfiStructId, FinishFuncDef, FinishFuncId, FuncDef, FuncId, GlobalId,
    GlobalLetDef, Hir, Ident, IdentId, IdentRef, Intrinsic, Lit, LitKind, MatchPattern,
    NamedStruct, Param, ParamId, Stmt, StmtId, StmtKind, StructDef, StructField, StructFieldExpr,
    StructFieldId, StructFieldKind, StructId, VType, VTypeId, VTypeKind,
};

/// Exits early if the [`VisitorResult`] asks to break.
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

macro_rules! visitor_method {
    // For types that implement `Walkable`.
    (@walk $name:ident, $ty:ty) => {
        // TODO(eric): Use autoref specialization to so that we
        // can write something like this:
        //    #[instrument(skip_all, fields(hir_id = %hir_node_id!(v.id)))]
        // Specialize on `HirNode`.
        #[instrument(skip_all)]
        fn $name(&mut self, v: &'hir $ty) -> Self::Result {
            v.walk(self)
        }
    };
    // For HIR ID types.
    (@id $name:ident, $ty:ty) => {
        #[instrument(skip_all, fields(hir_id = %id))]
        fn $name(&mut self, id: $ty) -> Self::Result {
            Self::Result::output()
        }
    };
    // For other types.
    (@other $name:ident, $ty:ty) => {
        #[instrument(skip_all)]
        fn $name(&mut self, _v: $ty) -> Self::Result {
            Self::Result::output()
        }
    };
}

/// Visits HIR nodes.
///
/// # Usage
pub(crate) trait Visitor<'hir>: Sized {
    /// The result from a "visit_" method.
    type Result: VisitorResult;

    /// Returns the HIR being visited.
    fn hir(&self) -> &'hir Hir;

    /// Visits all the top-level items.
    ///
    /// Do not override this method.
    fn visit_all(&mut self) -> Self::Result {
        visit_all(self)
    }

    //
    // Actions
    //

    visitor_method!(@walk visit_action, ActionDef);
    visitor_method!(@id visit_action_id, ActionId);

    //
    // Commands
    //

    visitor_method!(@walk visit_cmd, CmdDef);
    visitor_method!(@id visit_cmd_id, CmdId);
    visitor_method!(@walk visit_cmd_field, CmdField);
    visitor_method!(@id visit_cmd_field_id, CmdFieldId);
    visitor_method!(@walk visit_cmd_field_kind, CmdFieldKind);
    visitor_method!(@walk visit_cmd_seal_block, Block);
    visitor_method!(@walk visit_cmd_open_block, Block);
    visitor_method!(@walk visit_cmd_policy_block, Block);
    visitor_method!(@walk visit_cmd_recall_block, Block);

    //
    // Effects
    //

    visitor_method!(@walk visit_effect_def, EffectDef);
    visitor_method!(@id visit_effect_id, EffectId);
    visitor_method!(@walk visit_effect_field, EffectField);
    visitor_method!(@id visit_effect_field_id, EffectFieldId);
    visitor_method!(@walk visit_effect_field_kind, EffectFieldKind);

    //
    // Enums
    //

    visitor_method!(@walk visit_enum_def, EnumDef);
    visitor_method!(@id visit_enum_id, EnumId);

    //
    // Facts
    //

    visitor_method!(@walk visit_fact_def, FactDef);
    visitor_method!(@id visit_fact_id, FactId);
    visitor_method!(@walk visit_fact_key, FactKey);
    visitor_method!(@id visit_fact_key_id, FactKeyId);
    visitor_method!(@walk visit_fact_val, FactVal);
    visitor_method!(@id visit_fact_val_id, FactValId);

    //
    // Finish functions
    //

    visitor_method!(@walk visit_finish_func_def, FinishFuncDef);
    visitor_method!(@id visit_finish_func_id, FinishFuncId);

    //
    // Functions
    //

    visitor_method!(@walk visit_func_def, FuncDef);
    visitor_method!(@id visit_func_id, FuncId);
    visitor_method!(@walk visit_func_result, VType);

    //
    // Globals
    //

    visitor_method!(@walk visit_global_def, GlobalLetDef);
    visitor_method!(@id visit_global_id, GlobalId);

    //
    // Structs
    //

    visitor_method!(@walk visit_struct_def, StructDef);
    visitor_method!(@id visit_struct_id, StructId);
    visitor_method!(@walk visit_struct_field, StructField);
    visitor_method!(@id visit_struct_field_id, StructFieldId);
    visitor_method!(@walk visit_struct_field_kind, StructFieldKind);

    //
    // Ident
    //

    visitor_method!(@walk visit_ident, Ident);
    visitor_method!(@id visit_ident_id, IdentId);
    visitor_method!(@other visit_ident_ident, IdentRef);

    //
    // Blocks
    //

    visitor_method!(@walk visit_block, Block);
    visitor_method!(@id visit_block_id, BlockId);

    //
    // Exprs
    //

    visitor_method!(@walk visit_expr, Expr);
    visitor_method!(@id visit_expr_id, ExprId);
    visitor_method!(@walk visit_expr_kind, ExprKind);

    //
    // Statements
    //

    visitor_method!(@walk visit_stmt, Stmt);
    visitor_method!(@id visit_stmt_id, StmtId);
    visitor_method!(@walk visit_stmt_kind, StmtKind);

    //
    // VType
    //

    visitor_method!(@walk visit_vtype, VType);
    visitor_method!(@id visit_vtype_id, VTypeId);
    visitor_method!(@walk visit_vtype_kind, VTypeKind);

    //
    // Literals
    //

    visitor_method!(@walk visit_lit, Lit);
    // TODO(eric): implement this
    // visitor_method!(@walk visit_lit_kind, LitKind);

    visitor_method!(@walk visit_named_struct_lit, NamedStruct);
    visitor_method!(@walk visit_named_struct_lit_field, StructFieldExpr);

    visitor_method!(@walk visit_fact_lit, FactLiteral);
    visitor_method!(@walk visit_fact_lit_key, FactFieldExpr);
    visitor_method!(@walk visit_fact_lit_val, FactFieldExpr);

    //
    // FFI
    //

    visitor_method!(@walk visit_ffi_import_def, FfiImportDef);
    visitor_method!(@id visit_ffi_import_id, FfiImportId);

    visitor_method!(@walk visit_ffi_module, FfiModuleDef);
    visitor_method!(@id visit_ffi_module_id, FfiModuleId);

    visitor_method!(@walk visit_ffi_func, FfiFuncDef);
    visitor_method!(@id visit_ffi_func_id, FfiFuncId);
    visitor_method!(@walk visit_ffi_func_sig, FfiFuncSig);

    visitor_method!(@walk visit_ffi_struct, FfiStructDef);
    visitor_method!(@id visit_ffi_struct_id, FfiStructId);
    visitor_method!(@walk visit_ffi_struct_field, FfiStructField);
    visitor_method!(@id visit_ffi_struct_field_id, FfiStructFieldId);
    visitor_method!(@walk visit_ffi_struct_field_kind, FfiStructFieldKind);

    visitor_method!(@walk visit_ffi_enum, FfiEnumDef);
    visitor_method!(@id visit_ffi_enum_id, FfiEnumId);

    //
    // Body and Params
    //

    visitor_method!(@walk visit_body, Body);
    visitor_method!(@id visit_body_id, BodyId);

    visitor_method!(@walk visit_param, Param);
    visitor_method!(@id visit_param_id, ParamId);
}

/// Visits all top-level items.
pub fn visit_all<'hir, V>(visitor: &mut V) -> V::Result
where
    V: Visitor<'hir>,
{
    macro_rules! visit {
        ($field:ident => $visit:ident => $ty:ty) => {
            for (_, def) in &visitor.hir().$field {
                try_visit!(visitor.$visit(def));
            }
        };
    }
    for_each_top_level_item!(@visit_all visit);
    V::Result::output()
}

/// Invokes `callback` for each top level HIR node (i.e., each
/// node that can appear in the global scope).
///
/// `callback` must be a macro with the following signature:
///
/// ```ignore
/// macro_rules! example_callback {
///     ($visit:ident => $ty:ty) => { ... };
/// }
/// ```
///
/// where `visit` is the `visit_*` [`Visitor`] method and `ty` is
/// the method's argument.
///
/// NOTE: This list must be kept in sync with the GlobalSymbol trait
/// implementations in `hir.rs`.
macro_rules! for_each_top_level_item {
    ($callback:ident) => {
        $crate::hir::visit::for_each_top_level_item!(@impl [partial] $callback);
    };
    // For `visit_all`.
    (@visit_all $callback:ident) => {
        $crate::hir::visit::for_each_top_level_item!(@impl [full] $callback);
    };
    (@impl [$what:tt] $callback:ident) => {
        $crate::hir::visit::for_each_top_level_item!(@apply [$what]
            $callback,
            actions, visit_action, ActionDef;
            cmds, visit_cmd, CmdDef;
            effects, visit_effect_def, EffectDef;
            enums, visit_enum_def, EnumDef;
            facts, visit_fact_def, FactDef;
            // We add FFI enums shere because, unlike FFI
            // functions, FFI enums are referenced without the
            // FFI module's name.
            ffi_enums, visit_ffi_enum, FfiEnumDef;
            ffi_imports, visit_ffi_import_def, FfiImportDef;
            ffi_modules, visit_ffi_module, FfiModuleDef;
            // We add FFI structs shere because, unlike FFI
            // functions, FFI structs are referenced without the
            // FFI module's name.
            ffi_structs, visit_ffi_struct, FfiStructDef;
            finish_funcs, visit_finish_func_def, FinishFuncDef;
            funcs, visit_func_def, FuncDef;
            global_lets, visit_global_def, GlobalLetDef;
            structs, visit_struct_def, StructDef;
        );
    };
    (@apply [partial] $callback:ident, $($field:ident, $visit:ident, $ty:ident);* $(;)?) => {
        $( $callback!($visit => $crate::hir::$ty); )*
    };
    (@apply [full] $callback:ident, $($field:ident, $visit:ident, $ty:ident);* $(;)?) => {
        $( $callback!($field => $visit => $crate::hir::$ty); )*
    };
}
pub(crate) use for_each_top_level_item;

/// Invokes `callback` for each item that has an identifier
/// (i.e., implements [`Named`][crate::hir::Named]).
///
/// `callback` must be a macro with the following signature:
///
/// ```ignore
/// macro_rules! example_callback {
///     ($visit:ident => $ty:ty) => { ... };
/// }
/// ```
macro_rules! for_each_named_item {
    ($callback:ident) => {
        $crate::hir::visit::for_each_named_item!(@apply $callback,
            visit_action, ActionDef;
            visit_cmd, CmdDef;
            visit_effect_def, EffectDef;
            visit_enum_def, EnumDef;
            visit_named_struct_lit, NamedStruct;
            visit_named_struct_lit_field, StructFieldExpr;
            visit_fact_lit, FactLiteral;
            visit_fact_lit_key, FactFieldExpr;
            visit_fact_lit_val, FactFieldExpr;
            visit_fact_def, FactDef;
            visit_fact_key, FactKey;
            visit_fact_val, FactVal;
            visit_finish_func_def, FinishFuncDef;
            visit_func_def, FuncDef;
            visit_global_def, GlobalLetDef;
            visit_struct_def, StructDef;
            visit_ffi_import_def, FfiImportDef;
            visit_ffi_module, FfiModuleDef;
            visit_ffi_func, FfiFuncDef;
            visit_ffi_struct, FfiStructDef;
            visit_ffi_enum, FfiEnumDef;
        );
    };
    (@apply $callback:ident, $($visit:ident, $ty:ident);* $(;)?) => {
        $( $callback!($visit => $crate::hir::$ty); )*
    };
}
pub(crate) use for_each_named_item;

/// The result from a [`Visitor`] method.
pub(crate) trait VisitorResult {
    /// The type of the value passed to
    /// [`from_residual`][Self::from_residual] when
    /// short-circuiting (exiting early).
    type Residual;

    /// Constructs the type from a successful visit.
    fn output() -> Self;
    /// Constructs the type from a visit that exited early.
    fn from_residual(residual: Self::Residual) -> Self;
    /// Constructs the type from the result of
    /// [`branch`][Self::branch].
    fn from_branch(b: ControlFlow<Self::Residual>) -> Self;
    /// Used to decide whether to continue visiting this item or
    /// exit early.
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

/// A type that can be visited by a [`Visitor`].
pub(crate) trait Visitable<'hir> {
    /// Invokes the visitor on this type.
    fn visit<V>(self, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>;
}

impl<'hir, T> Visitable<'hir> for &'hir [T]
where
    &'hir T: Visitable<'hir>,
{
    fn visit<V>(self, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        for item in self {
            try_visit!(item.visit(visitor));
        }
        V::Result::output()
    }
}

impl<'hir, T> Visitable<'hir> for Option<T>
where
    T: Visitable<'hir>,
{
    fn visit<V>(self, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        if let Some(item) = self {
            try_visit!(item.visit(visitor));
        }
        V::Result::output()
    }
}

/// Implements [`Visitable`] for a reference type.
macro_rules! visitable_ref {
    ($($name:ident => $f:ident),* $(,)?) => {
        $(impl<'hir> Visitable<'hir> for &'hir $name {
            fn visit<V>(self, visitor: &mut V) -> V::Result
            where
                V: Visitor<'hir>,
            {
                visitor.$f(self)
            }
        })*
    };
}

/// A type that can be walked.
pub(crate) trait Walkable<'hir> {
    /// Walks this type using the given visitor.
    fn walk<V>(self, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>;
}

impl<'hir, T> Walkable<'hir> for &'hir [T]
where
    &'hir T: Walkable<'hir>,
{
    fn walk<V>(self, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        for item in self {
            try_visit!(item.walk(visitor));
        }
        V::Result::output()
    }
}

impl<'hir, T> Walkable<'hir> for Option<T>
where
    T: Walkable<'hir>,
{
    fn walk<V>(self, visitor: &mut V) -> V::Result
    where
        V: Visitor<'hir>,
    {
        if let Some(item) = self {
            try_visit!(item.walk(visitor));
        }
        V::Result::output()
    }
}

/// Implements [`Walkable`] for a reference type.
macro_rules! walkable_ref {
    ($($name:ident => $f:ident),* $(,)?) => {
        $(impl<'hir> Walkable<'hir> for &'hir $name {
            fn walk<V>(self, visitor: &mut V) -> V::Result
            where
                V: Visitor<'hir>,
            {
                $crate::hir::visit::$f(visitor, self)
            }
        })*
    };
}
walkable_ref! {
    FactFieldExpr => walk_fact_field_expr,
}

/// Implements both [`Visitable`] and [`Walkable`] for a type.
macro_rules! visitable_and_walkable_ref {
    ($($name:ident, $visit:ident, $walk:ident);* $(;)?) => {
        visitable_ref!($($name => $visit),*);
        walkable_ref!($($name => $walk),*);
    };
}
// TODO(eric): FactFieldExpr for visit_fact_lit_key and
// visit_fact_lit_val.
visitable_and_walkable_ref! {
    ActionDef, visit_action, walk_action;
    Block, visit_block, walk_block;
    Body, visit_body, walk_body;
    CmdDef, visit_cmd, walk_cmd;
    CmdField, visit_cmd_field, walk_cmd_field;
    CmdFieldKind, visit_cmd_field_kind, walk_cmd_field_kind;
    EffectDef, visit_effect_def, walk_effect;
    EffectField, visit_effect_field, walk_effect_field;
    EffectFieldKind, visit_effect_field_kind, walk_effect_field_kind;
    EnumDef, visit_enum_def, walk_enum;
    Expr, visit_expr, walk_expr;
    ExprKind, visit_expr_kind, walk_expr_kind;
    FactDef, visit_fact_def, walk_fact;
    FactKey, visit_fact_key, walk_fact_key;
    FactLiteral, visit_fact_lit, walk_fact_lit;
    FactVal, visit_fact_val, walk_fact_val;
    FfiEnumDef, visit_ffi_enum, walk_ffi_enum;
    FfiFuncDef, visit_ffi_func, walk_ffi_func;
    FfiFuncSig, visit_ffi_func_sig, walk_ffi_func_sig;
    FfiImportDef, visit_ffi_import_def, walk_ffi_import_def;
    FfiModuleDef, visit_ffi_module, walk_ffi_module;
    FfiStructDef, visit_ffi_struct, walk_ffi_struct;
    FfiStructField, visit_ffi_struct_field, walk_ffi_struct_field;
    FfiStructFieldKind, visit_ffi_struct_field_kind, walk_ffi_struct_field_kind;
    FinishFuncDef, visit_finish_func_def, walk_finish_func;
    FuncDef, visit_func_def, walk_func;
    GlobalLetDef, visit_global_def, walk_global_let;
    Ident, visit_ident, walk_ident;
    Lit, visit_lit, walk_lit;
    NamedStruct, visit_named_struct_lit, walk_named_struct_lit;
    Param, visit_param, walk_param;
    Stmt, visit_stmt, walk_stmt;
    StmtKind, visit_stmt_kind, walk_stmt_kind;
    StructDef, visit_struct_def, walk_struct;
    StructField, visit_struct_field, walk_struct_field;
    StructFieldExpr, visit_named_struct_lit_field, walk_struct_field_expr;
    StructFieldKind, visit_struct_field_kind, walk_struct_field_kind;
    VType, visit_vtype, walk_vtype;
    VTypeKind, visit_vtype_kind, walk_vtype_kind;
}

/// Walks a specific action.
///
/// This performs a DFS.
pub(crate) fn walk_action<'hir, V>(visitor: &mut V, def: &'hir ActionDef) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_action_id(def.id));
    try_visit_by_id!(visitor.visit_body(def.body));
    V::Result::output()
}

/// Walks a specific command.
///
/// This performs a DFS.
pub(crate) fn walk_cmd<'hir, V>(visitor: &mut V, def: &'hir CmdDef) -> V::Result
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

/// Walks a specific command field.
///
/// This performs a DFS.
pub(crate) fn walk_cmd_field<'hir, V>(visitor: &mut V, field: &'hir CmdField) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_cmd_field_id(field.id));
    try_visit!(visitor.visit_cmd_field_kind(&field.kind));
    V::Result::output()
}

/// Walks a specific command field kind.
///
/// This performs a DFS.
pub(crate) fn walk_cmd_field_kind<'hir, V>(visitor: &mut V, kind: &'hir CmdFieldKind) -> V::Result
where
    V: Visitor<'hir>,
{
    match kind {
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
pub(crate) fn walk_ident<'hir, V>(visitor: &mut V, ident: &'hir Ident) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_ident_id(ident.id));
    try_visit!(visitor.visit_ident_ident(ident.xref));
    V::Result::output()
}

/// Walks a variable type.
///
/// This performs a DFS.
pub(crate) fn walk_vtype<'hir, V>(visitor: &mut V, ty: &'hir VType) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_vtype_id(ty.id));
    try_visit!(visitor.visit_vtype_kind(&ty.kind));
    V::Result::output()
}

pub(crate) fn walk_vtype_kind<'hir, V>(visitor: &mut V, kind: &'hir VTypeKind) -> V::Result
where
    V: Visitor<'hir>,
{
    match kind {
        VTypeKind::String | VTypeKind::Bytes | VTypeKind::Int | VTypeKind::Bool | VTypeKind::Id => {
        }
        VTypeKind::Struct(id) => {
            try_visit_by_id!(visitor.visit_ident(*id));
        }
        VTypeKind::Enum(id) => {
            try_visit_by_id!(visitor.visit_ident(*id));
        }
        VTypeKind::Optional(id) => {
            try_visit_by_id!(visitor.visit_vtype(*id));
        }
    }
    V::Result::output()
}

/// Walks a block.
///
/// This performs a DFS.
pub(crate) fn walk_block<'hir, V>(visitor: &mut V, block: &'hir Block) -> V::Result
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
pub(crate) fn walk_stmt<'hir, V>(visitor: &mut V, stmt: &'hir Stmt) -> V::Result
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
pub(crate) fn walk_stmt_kind<'hir, V>(visitor: &mut V, kind: &'hir StmtKind) -> V::Result
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
pub(crate) fn walk_expr<'hir, V>(visitor: &mut V, expr: &'hir Expr) -> V::Result
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
pub(crate) fn walk_expr_kind<'hir, V>(visitor: &mut V, kind: &'hir ExprKind) -> V::Result
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
pub(crate) fn walk_lit<'hir, V>(visitor: &mut V, lit: &'hir Lit) -> V::Result
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
pub(crate) fn walk_named_struct_lit<'hir, V>(visitor: &mut V, lit: &'hir NamedStruct) -> V::Result
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
pub(crate) fn walk_fact_lit<'hir, V>(visitor: &mut V, fact: &'hir FactLiteral) -> V::Result
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
pub(crate) fn walk_fact_field<'hir, V>(visitor: &mut V, field: &'hir FactField) -> V::Result
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

/// Walks a specific effect.
///
/// This performs a DFS.
pub(crate) fn walk_effect<'hir, V>(visitor: &mut V, def: &'hir EffectDef) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_effect_id(def.id));
    for &id in &def.items {
        try_visit_by_id!(visitor.visit_effect_field(id));
    }
    V::Result::output()
}

/// Walks an effect field.
///
/// This performs a DFS.
pub(crate) fn walk_effect_field<'hir, V>(visitor: &mut V, field: &'hir EffectField) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_effect_field_id(field.id));
    try_visit!(visitor.visit_effect_field_kind(&field.kind));
    V::Result::output()
}

/// Walks an effect field kind.
///
/// This performs a DFS.
pub(crate) fn walk_effect_field_kind<'hir, V>(
    visitor: &mut V,
    kind: &'hir EffectFieldKind,
) -> V::Result
where
    V: Visitor<'hir>,
{
    match kind {
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

/// Walks a specific enum.
///
/// This performs a DFS.
pub(crate) fn walk_enum<'hir, V>(visitor: &mut V, def: &'hir EnumDef) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_enum_id(def.id));
    V::Result::output()
}

/// Walks a specific finish function.
///
/// This performs a DFS.
pub(crate) fn walk_finish_func<'hir, V>(visitor: &mut V, def: &'hir FinishFuncDef) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_finish_func_id(def.id));
    try_visit_by_id!(visitor.visit_body(def.body));
    V::Result::output()
}

/// Walks a specific function.
///
/// This performs a DFS.
pub(crate) fn walk_func<'hir, V>(visitor: &mut V, def: &'hir FuncDef) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_func_id(def.id));
    try_visit_by_id!(visitor.visit_func_result(def.result));
    try_visit_by_id!(visitor.visit_body(def.body));
    V::Result::output()
}

/// Walks a specific global let.
///
/// This performs a DFS.
pub(crate) fn walk_global_let<'hir, V>(visitor: &mut V, def: &'hir GlobalLetDef) -> V::Result
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
pub(crate) fn walk_struct<'hir, V>(visitor: &mut V, def: &'hir StructDef) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_struct_id(def.id));
    for &id in &def.items {
        try_visit_by_id!(visitor.visit_struct_field(id));
    }
    V::Result::output()
}

/// This performs a DFS.
pub(crate) fn walk_struct_field<'hir, V>(visitor: &mut V, field: &'hir StructField) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_struct_field_id(field.id));
    try_visit!(visitor.visit_struct_field_kind(&field.kind));
    V::Result::output()
}

/// This performs a DFS.
pub(crate) fn walk_struct_field_kind<'hir, V>(
    visitor: &mut V,
    kind: &'hir StructFieldKind,
) -> V::Result
where
    V: Visitor<'hir>,
{
    match kind {
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

pub(crate) fn walk_fact<'hir, V>(visitor: &mut V, def: &'hir FactDef) -> V::Result
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

pub(crate) fn walk_fact_key<'hir, V>(visitor: &mut V, key: &'hir FactKey) -> V::Result
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
pub(crate) fn walk_fact_val<'hir, V>(visitor: &mut V, val: &'hir FactVal) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_fact_val_id(val.id));
    try_visit_by_id!(visitor.visit_ident(val.ident));
    try_visit_by_id!(visitor.visit_vtype(val.ty));
    V::Result::output()
}

pub(crate) fn walk_fact_field_expr<'hir, V>(
    visitor: &mut V,
    field: &'hir FactFieldExpr,
) -> V::Result
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

pub(crate) fn walk_struct_field_expr<'hir, V>(
    visitor: &mut V,
    field: &'hir StructFieldExpr,
) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit_by_id!(visitor.visit_ident(field.ident));
    try_visit_by_id!(visitor.visit_expr(field.expr));
    V::Result::output()
}

pub(crate) fn walk_ffi_module<'hir, V>(visitor: &mut V, def: &'hir FfiModuleDef) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_ffi_module_id(def.id));
    for &id in &def.funcs {
        try_visit_by_id!(visitor.visit_ffi_func(id));
    }
    for &id in &def.structs {
        try_visit_by_id!(visitor.visit_ffi_struct(id));
    }
    for &id in &def.enums {
        try_visit_by_id!(visitor.visit_ffi_enum(id));
    }
    V::Result::output()
}

pub(crate) fn walk_ffi_func<'hir, V>(visitor: &mut V, def: &'hir FfiFuncDef) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_ffi_func_id(def.id));
    try_visit_by_id!(visitor.visit_ident(def.ident));
    try_visit!(visitor.visit_ffi_func_sig(&def.sig));
    V::Result::output()
}

pub(crate) fn walk_ffi_func_sig<'hir, V>(visitor: &mut V, sig: &'hir FfiFuncSig) -> V::Result
where
    V: Visitor<'hir>,
{
    for &id in &sig.args {
        try_visit_by_id!(visitor.visit_param(id));
    }
    try_visit_by_id!(visitor.visit_vtype(sig.result));
    V::Result::output()
}

pub(crate) fn walk_ffi_struct<'hir, V>(visitor: &mut V, def: &'hir FfiStructDef) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_ffi_struct_id(def.id));
    for &id in &def.fields {
        try_visit_by_id!(visitor.visit_ffi_struct_field(id));
    }
    V::Result::output()
}

pub(crate) fn walk_ffi_struct_field<'hir, V>(
    visitor: &mut V,
    field: &'hir FfiStructField,
) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_ffi_struct_field_id(field.id));
    try_visit!(visitor.visit_ffi_struct_field_kind(&field.kind));
    V::Result::output()
}

pub(crate) fn walk_ffi_struct_field_kind<'hir, V>(
    visitor: &mut V,
    kind: &'hir FfiStructFieldKind,
) -> V::Result
where
    V: Visitor<'hir>,
{
    match kind {
        FfiStructFieldKind::Field { ident, ty } => {
            try_visit_by_id!(visitor.visit_ident(*ident));
            try_visit_by_id!(visitor.visit_vtype(*ty));
        }
        FfiStructFieldKind::StructRef(ident) => {
            try_visit_by_id!(visitor.visit_ident(*ident));
        }
    }
    V::Result::output()
}

pub(crate) fn walk_ffi_enum<'hir, V>(visitor: &mut V, def: &'hir FfiEnumDef) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_ffi_enum_id(def.id));
    for &id in &def.variants {
        try_visit_by_id!(visitor.visit_ident(id));
    }
    V::Result::output()
}

pub(crate) fn walk_ffi_import_def<'hir, V>(visitor: &mut V, def: &'hir FfiImportDef) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_ffi_import_id(def.id));
    try_visit_by_id!(visitor.visit_ident(def.ident));
    V::Result::output()
}

pub(crate) fn walk_param<'hir, V>(visitor: &mut V, param: &'hir Param) -> V::Result
where
    V: Visitor<'hir>,
{
    try_visit!(visitor.visit_param_id(param.id));
    try_visit_by_id!(visitor.visit_ident(param.ident));
    try_visit_by_id!(visitor.visit_vtype(param.ty));
    V::Result::output()
}

pub(crate) fn walk_body<'hir, V>(visitor: &mut V, body: &'hir Body) -> V::Result
where
    V: Visitor<'hir>,
{
    let Body {
        id,
        span: _,
        params,
        stmts,
        returns: _,
    } = body;
    try_visit!(visitor.visit_body_id(*id));
    for &id in params {
        try_visit_by_id!(visitor.visit_param(id));
    }
    for &id in stmts {
        try_visit_by_id!(visitor.visit_stmt(id));
    }
    V::Result::output()
}
