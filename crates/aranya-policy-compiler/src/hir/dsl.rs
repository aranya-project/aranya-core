//! Provides a convenient macro for constructing [`Hir`] in
//! tests.

#![cfg(test)]

use std::collections::BTreeMap;

use slotmap::KeyData;

use crate::hir::hir::{
    ActionArg, ActionArgId, ActionCall, ActionDef, ActionId, Block, BlockId, CheckStmt, CmdDef,
    CmdField, CmdFieldId, CmdId, DebugAssert, EffectDef, EffectField, EffectFieldId, EffectId,
    Emit, EnumDef, EnumId, EnumReference, Expr, ExprId, ExprKind, FactDef, FactId, FactKey,
    FactKeyId, FactVal, FactValId, FinishFuncArg, FinishFuncArgId, FinishFuncDef, FinishFuncId,
    ForeignFunctionCall, FuncArg, FuncArgId, FuncDef, FuncId, FunctionCall, GlobalId, GlobalLetDef,
    Hir, Ident, IdentId, IfBranch, IfStmt, LetStmt, NamedStruct, Publish, ReturnStmt, Stmt, StmtId,
    StmtKind, StructDef, StructField, StructFieldId, StructFieldKind, StructId, VType, VTypeId,
    VTypeKind,
};

/// Creates a [`TestHir`] for use in tests.
///
/// Most integers in the macro represent the various HIR node IDs
/// Each section must be defined in dependency order (e.g.,
/// idents and types before expressions that use them).
///
/// # Example
///
/// ```rust,ignore
/// let test_hir = hir! {
///     // Define identifiers first
///     idents: {
///         0 => "name",
///         1 => "age",
///     },
///     // Define types
///     types: {
///         0 => String,
///         1 => Int,
///     },
///     // Define expressions
///     exprs: {
///         0 => Int,
///         1 => Bool,
///     },
///     // Define statements that reference idents and exprs
///     stmts: {
///         0 => { Let { ident: 0, expr: 0 } },
///         1 => { Check { expr: 1 } },
///     },
///     // Define blocks that contain statements
///     blocks: {
///         0 => { stmts: [0, 1] },
///         1 => { stmts: [] },
///     },
///     // Define action arguments
///     action_args: {
///         0 => { ident: 0, ty: 0 },
///         1 => { ident: 1, ty: 1 },
///     },
///     // Define actions that use args and blocks
///     actions: {
///         0 => { args: [0, 1], block: 0 },
///         1 => { args: [], block: 1 },
///     },
/// };
/// ```
#[allow(unused_macros)] // TODO
macro_rules! hir {
    // Empty case - no fields
    () => {{ $crate::hir::dsl::HirBuilder::new().build() }};

    // General case with fields
    ( $( $field:ident: { $($idx:expr => $value:tt),* $(,)? } ),* $(,)? ) => {{
        let mut builder = $crate::hir::dsl::HirBuilder::new();
        $( hir!(@field &mut builder, $field, { $($idx => $value),* }); )*
        builder.build()
    }};

    // Process idents
    (@field $builder:expr, idents, { $($idx:expr => $name:literal),* }) => {
        $( $builder.ident($idx, $name); )*
    };

    // Process types
    (@field $builder:expr, types, { $($idx:expr => $kind:tt),* }) => {
        $( hir!(@process_type $builder, $idx, $kind); )*
    };

    (@process_type $builder:expr, $idx:expr, String) => { $builder.vtype_string($idx); };
    (@process_type $builder:expr, $idx:expr, Int) => { $builder.vtype_int($idx); };
    (@process_type $builder:expr, $idx:expr, Bool) => { $builder.vtype_bool($idx); };

    // Process exprs
    (@field $builder:expr, exprs, { $($idx:expr => $kind:tt),* }) => {
        $( hir!(@expr $builder, $idx, $kind); )*
    };

    (@expr $builder:expr, $idx:expr, Int) => { $builder.expr_int($idx); };
    (@expr $builder:expr, $idx:expr, Bool) => { $builder.expr_bool($idx); };
    (@expr $builder:expr, $idx:expr, String) => { $builder.expr_string($idx); };
    (@expr $builder:expr, $idx:expr, { Identifier($ident:expr) }) => { $builder.expr_ident($idx, $ident); };
    (@expr $builder:expr, $idx:expr, { Add($lhs:expr, $rhs:expr) }) => { $builder.expr_add($idx, $lhs, $rhs); };
    (@expr $builder:expr, $idx:expr, { Sub($lhs:expr, $rhs:expr) }) => { $builder.expr_sub($idx, $lhs, $rhs); };
    (@expr $builder:expr, $idx:expr, { And($lhs:expr, $rhs:expr) }) => { $builder.expr_and($idx, $lhs, $rhs); };
    (@expr $builder:expr, $idx:expr, { Or($lhs:expr, $rhs:expr) }) => { $builder.expr_or($idx, $lhs, $rhs); };
    (@expr $builder:expr, $idx:expr, { Dot($lhs:expr, $rhs:expr) }) => { $builder.expr_dot($idx, $lhs, $rhs); };
    (@expr $builder:expr, $idx:expr, { Equal($lhs:expr, $rhs:expr) }) => { $builder.expr_equal($idx, $lhs, $rhs); };
    (@expr $builder:expr, $idx:expr, { NotEqual($lhs:expr, $rhs:expr) }) => { $builder.expr_not_equal($idx, $lhs, $rhs); };
    (@expr $builder:expr, $idx:expr, { GreaterThan($lhs:expr, $rhs:expr) }) => { $builder.expr_greater_than($idx, $lhs, $rhs); };
    (@expr $builder:expr, $idx:expr, { LessThan($lhs:expr, $rhs:expr) }) => { $builder.expr_less_than($idx, $lhs, $rhs); };
    (@expr $builder:expr, $idx:expr, { GreaterThanOrEqual($lhs:expr, $rhs:expr) }) => { $builder.expr_greater_than_or_equal($idx, $lhs, $rhs); };
    (@expr $builder:expr, $idx:expr, { LessThanOrEqual($lhs:expr, $rhs:expr) }) => { $builder.expr_less_than_or_equal($idx, $lhs, $rhs); };
    (@expr $builder:expr, $idx:expr, { Negative($expr:expr) }) => { $builder.expr_negative($idx, $expr); };
    (@expr $builder:expr, $idx:expr, { Not($expr:expr) }) => { $builder.expr_not($idx, $expr); };
    (@expr $builder:expr, $idx:expr, { Unwrap($expr:expr) }) => { $builder.expr_unwrap($idx, $expr); };
    (@expr $builder:expr, $idx:expr, { CheckUnwrap($expr:expr) }) => { $builder.expr_check_unwrap($idx, $expr); };
    (@expr $builder:expr, $idx:expr, { Is($expr:expr, $val:expr) }) => { $builder.expr_is($idx, $expr, $val); };
    (@expr $builder:expr, $idx:expr, { Block($block:expr, $expr:expr) }) => { $builder.expr_block($idx, $block, $expr); };
    (@expr $builder:expr, $idx:expr, { Substruct($expr:expr, $ident:expr) }) => { $builder.expr_substruct($idx, $expr, $ident); };
    (@expr $builder:expr, $idx:expr, { Match($expr:expr) }) => { $builder.expr_match($idx, $expr); };
    (@expr $builder:expr, $idx:expr, { Optional($expr:expr) }) => { $builder.expr_optional($idx, $expr); };
    (@expr $builder:expr, $idx:expr, { NamedStruct { ident: $ident:expr, fields: [$(($field_ident:expr, $field_expr:expr)),*] } }) => { $builder.expr_named_struct($idx, $ident, vec![$(($field_ident, $field_expr)),*]); };
    (@expr $builder:expr, $idx:expr, { FunctionCall { ident: $ident:expr, args: [$($arg:expr),*] } }) => { $builder.expr_function_call($idx, $ident, vec![$($arg),*]); };
    (@expr $builder:expr, $idx:expr, { ForeignFunctionCall { module: $module:expr, ident: $ident:expr, args: [$($arg:expr),*] } }) => { $builder.expr_foreign_function_call($idx, $module, $ident, vec![$($arg),*]); };
    (@expr $builder:expr, $idx:expr, { EnumReference { ident: $ident:expr, value: $value:expr } }) => { $builder.expr_enum_reference($idx, $ident, $value); };

    // Process stmts
    (@field $builder:expr, stmts, { $($idx:expr => $kind:tt),* }) => {
        $( hir!(@stmt $builder, $idx, $kind); )*
    };

    (@stmt $builder:expr, $idx:expr, { Let { ident: $ident:expr, expr: $expr:expr } }) => { $builder.stmt_let($idx, $ident, $expr); };
    (@stmt $builder:expr, $idx:expr, { Check { expr: $expr:expr } }) => { $builder.stmt_check($idx, $expr); };
    (@stmt $builder:expr, $idx:expr, { Return { expr: $expr:expr } }) => { $builder.stmt_return($idx, $expr); };
    (@stmt $builder:expr, $idx:expr, { If { branches: [$(($cond:expr, [$($stmt:expr),* $(,)?])),* $(,)?], else_block: $else_block:expr } }) => { $builder.stmt_if($idx, vec![$(($cond, vec![$($stmt),*])),*], $else_block); };
    (@stmt $builder:expr, $idx:expr, { Finish { block: $block:expr } }) => { $builder.stmt_finish($idx, $block); };
    (@stmt $builder:expr, $idx:expr, { ActionCall { ident: $ident:expr, args: [$($arg:expr),*] } }) => { $builder.stmt_action_call($idx, $ident, vec![$($arg),*]); };
    (@stmt $builder:expr, $idx:expr, { Publish { expr: $expr:expr } }) => { $builder.stmt_publish($idx, $expr); };
    (@stmt $builder:expr, $idx:expr, { Emit { expr: $expr:expr } }) => { $builder.stmt_emit($idx, $expr); };
    (@stmt $builder:expr, $idx:expr, { FunctionCall { ident: $ident:expr, args: [$($arg:expr),*] } }) => { $builder.stmt_function_call($idx, $ident, vec![$($arg),*]); };
    (@stmt $builder:expr, $idx:expr, { DebugAssert { expr: $expr:expr } }) => { $builder.stmt_debug_assert($idx, $expr); };

    // Process blocks
    (@field $builder:expr, blocks, { $($idx:expr => { stmts: [$($stmt:expr),* $(,)?] }),* }) => {
        $( $builder.block($idx, vec![$($stmt),*]); )*
    };

    // Process action_args
    (@field $builder:expr, action_args, { $($idx:expr => { ident: $ident:expr, ty: $ty:expr }),* }) => {
        $( $builder.action_arg($idx, $ident, $ty); )*
    };

    // Process actions
    (@field $builder:expr, actions, { $($idx:expr => { args: [$($arg:expr),* $(,)?], block: $block:expr }),* }) => {
        $( $builder.action($idx, vec![$($arg),*], $block); )*
    };

    // Process struct_fields
    (@field $builder:expr, struct_fields, { $($idx:expr => $value:tt),* }) => {
        $( hir!(@struct_field $builder, $idx, $value); )*
    };

    (@struct_field $builder:expr, $idx:expr, { ident: $ident:expr, ty: $ty:expr }) => {
        $builder.struct_field($idx, $ident, $ty);
    };
    (@struct_field $builder:expr, $idx:expr, { struct_ref: $ident:expr }) => {
        $builder.struct_ref($idx, $ident);
    };

    // Process structs
    (@field $builder:expr, structs, { $($idx:expr => { items: [$($field:expr),* $(,)?] }),* }) => {
        $( $builder.struct_def($idx, vec![$($field),*]); )*
    };

    // Process func_args
    (@field $builder:expr, func_args, { $($idx:expr => { ident: $ident:expr, ty: $ty:expr }),* }) => {
        $( $builder.func_arg($idx, $ident, $ty); )*
    };

    // Process funcs
    (@field $builder:expr, funcs, { $($idx:expr => { args: [$($arg:expr),* $(,)?], result: $result:expr, stmts: [$($stmt:expr),* $(,)?] }),* }) => {
        $( $builder.func($idx, vec![$($arg),*], $result, vec![$($stmt),*]); )*
    };
}
#[allow(unused_imports)] // TODO
pub(crate) use hir;

/// Creates an ID from an index and version using slotmap's KeyData.
///
/// # Panics
/// - If idx is 0
/// - If version is 0
pub(crate) fn make_id<T: From<KeyData>>(idx: u32, version: u32) -> T {
    assert!(idx > 0, "idx must be greater than 0");
    assert!(version > 0, "version must be greater than 0");
    let v = (idx as u64) | ((version as u64) << 32);
    KeyData::from_ffi(v).into()
}

/// Test representation of HIR that uses BTreeMaps with predictable IDs.
///
/// This struct mirrors [`Hir`] but uses [`BTreeMap`] instead of
/// [`SlotMap`], allowing tests to specify exact IDs.
#[derive(Clone, Default, Debug)]
pub(crate) struct TestHir {
    pub actions: BTreeMap<ActionId, ActionDef>,
    pub action_args: BTreeMap<ActionArgId, ActionArg>,
    pub cmds: BTreeMap<CmdId, CmdDef>,
    pub cmd_fields: BTreeMap<CmdFieldId, CmdField>,
    pub effects: BTreeMap<EffectId, EffectDef>,
    pub effect_fields: BTreeMap<EffectFieldId, EffectField>,
    pub enums: BTreeMap<EnumId, EnumDef>,
    pub facts: BTreeMap<FactId, FactDef>,
    pub fact_keys: BTreeMap<FactKeyId, FactKey>,
    pub fact_vals: BTreeMap<FactValId, FactVal>,
    pub finish_funcs: BTreeMap<FinishFuncId, FinishFuncDef>,
    pub finish_func_args: BTreeMap<FinishFuncArgId, FinishFuncArg>,
    pub funcs: BTreeMap<FuncId, FuncDef>,
    pub func_args: BTreeMap<FuncArgId, FuncArg>,
    pub global_lets: BTreeMap<GlobalId, GlobalLetDef>,
    pub structs: BTreeMap<StructId, StructDef>,
    pub struct_fields: BTreeMap<StructFieldId, StructField>,
    pub stmts: BTreeMap<StmtId, Stmt>,
    pub exprs: BTreeMap<ExprId, Expr>,
    pub idents: BTreeMap<IdentId, Ident>,
    pub blocks: BTreeMap<BlockId, Block>,
    pub types: BTreeMap<VTypeId, VType>,
}

/// Helper function to compare a BTreeMap and SlotMap with the
/// same key and value types.
fn collections_eq<K, V>(btree: &BTreeMap<K, V>, slot: &slotmap::SlotMap<K, V>) -> bool
where
    K: slotmap::Key + Ord,
    V: PartialEq,
{
    if btree.len() != slot.len() {
        return false;
    }

    for (id, value) in btree {
        if slot.get(*id) != Some(value) {
            return false;
        }
    }

    true
}

impl PartialEq<TestHir> for Hir {
    fn eq(&self, other: &TestHir) -> bool {
        collections_eq(&other.actions, &self.actions)
            && collections_eq(&other.action_args, &self.action_args)
            && collections_eq(&other.cmds, &self.cmds)
            && collections_eq(&other.cmd_fields, &self.cmd_fields)
            && collections_eq(&other.effects, &self.effects)
            && collections_eq(&other.effect_fields, &self.effect_fields)
            && collections_eq(&other.enums, &self.enums)
            && collections_eq(&other.facts, &self.facts)
            && collections_eq(&other.fact_keys, &self.fact_keys)
            && collections_eq(&other.fact_vals, &self.fact_vals)
            && collections_eq(&other.finish_funcs, &self.finish_funcs)
            && collections_eq(&other.finish_func_args, &self.finish_func_args)
            && collections_eq(&other.funcs, &self.funcs)
            && collections_eq(&other.func_args, &self.func_args)
            && collections_eq(&other.global_lets, &self.global_lets)
            && collections_eq(&other.structs, &self.structs)
            && collections_eq(&other.struct_fields, &self.struct_fields)
            && collections_eq(&other.stmts, &self.stmts)
            && collections_eq(&other.exprs, &self.exprs)
            && collections_eq(&other.idents, &self.idents)
            && collections_eq(&other.blocks, &self.blocks)
            && collections_eq(&other.types, &self.types)
    }
}

/// Builder for creating [`TestHir`] in tests.
///
/// Do not use this directly; use the [`hir!`] macro instead.
///
/// # Important: SlotMap ID Generation
///
/// SlotMap reserves index 0 as a sentinel value, so the first actual element
/// gets index 1. This means:
/// - When creating idents with index 0 in the macro, the actual ID will be 1
/// - When referencing ident IDs, we add +1 to match the created IDs
/// - Other types (types, exprs, etc.) start at index 0 as they use BTreeMap
///
/// Example:
/// ```ignore
/// hir! {
///     idents: {
///         0 => "foo",  // This creates an ident with ID 1
///         1 => "bar",  // This creates an ident with ID 2
///     },
///     stmts: {
///         0 => { Let { ident: 0, expr: 0 } },  // References ident ID 1
///     }
/// }
/// ```
#[derive(Default)]
pub(crate) struct HirBuilder {
    hir: TestHir,
}

impl HirBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(self) -> TestHir {
        self.hir
    }

    pub fn ident(&mut self, idx: u32, name: &str) -> IdentId {
        let id = make_id(idx, 1);
        self.hir.idents.insert(
            id,
            Ident {
                id,
                ident: name.parse().expect("invalid identifier"),
            },
        );
        id
    }

    pub fn vtype(&mut self, idx: u32, kind: VTypeKind) -> VTypeId {
        let id = make_id(idx, 1);
        self.hir.types.insert(id, VType { id, kind });
        id
    }

    pub fn vtype_string(&mut self, idx: u32) -> VTypeId {
        self.vtype(idx, VTypeKind::String)
    }

    pub fn vtype_int(&mut self, idx: u32) -> VTypeId {
        self.vtype(idx, VTypeKind::Int)
    }

    pub fn vtype_bool(&mut self, idx: u32) -> VTypeId {
        self.vtype(idx, VTypeKind::Bool)
    }

    pub fn expr(&mut self, idx: u32, kind: ExprKind) -> ExprId {
        let id = make_id(idx, 1);
        self.hir.exprs.insert(id, Expr { id, kind });
        id
    }

    pub fn expr_int(&mut self, idx: u32) -> ExprId {
        self.expr(idx, ExprKind::Int)
    }

    pub fn expr_bool(&mut self, idx: u32) -> ExprId {
        self.expr(idx, ExprKind::Bool)
    }

    pub fn expr_string(&mut self, idx: u32) -> ExprId {
        self.expr(idx, ExprKind::String)
    }

    pub fn expr_ident(&mut self, idx: u32, ident_idx: u32) -> ExprId {
        let ident_id = make_id(ident_idx, 1);
        self.expr(idx, ExprKind::Identifier(ident_id))
    }

    fn expr_binary(
        &mut self,
        idx: u32,
        lhs_idx: u32,
        rhs_idx: u32,
        f: impl Fn(ExprId, ExprId) -> ExprKind,
    ) -> ExprId {
        let lhs = make_id(lhs_idx, 1);
        let rhs = make_id(rhs_idx, 1);
        self.expr(idx, f(lhs, rhs))
    }

    fn expr_unary(&mut self, idx: u32, expr_idx: u32, f: impl Fn(ExprId) -> ExprKind) -> ExprId {
        let expr = make_id(expr_idx, 1);
        self.expr(idx, f(expr))
    }

    pub fn expr_add(&mut self, idx: u32, lhs_idx: u32, rhs_idx: u32) -> ExprId {
        self.expr_binary(idx, lhs_idx, rhs_idx, ExprKind::Add)
    }

    pub fn expr_sub(&mut self, idx: u32, lhs_idx: u32, rhs_idx: u32) -> ExprId {
        self.expr_binary(idx, lhs_idx, rhs_idx, ExprKind::Sub)
    }

    pub fn expr_and(&mut self, idx: u32, lhs_idx: u32, rhs_idx: u32) -> ExprId {
        self.expr_binary(idx, lhs_idx, rhs_idx, ExprKind::And)
    }

    pub fn expr_or(&mut self, idx: u32, lhs_idx: u32, rhs_idx: u32) -> ExprId {
        self.expr_binary(idx, lhs_idx, rhs_idx, ExprKind::Or)
    }

    pub fn expr_dot(&mut self, idx: u32, lhs_idx: u32, rhs_idx: u32) -> ExprId {
        let lhs = make_id(lhs_idx, 1);
        let rhs = make_id(rhs_idx, 1);
        self.expr(idx, ExprKind::Dot(lhs, rhs))
    }

    pub fn expr_equal(&mut self, idx: u32, lhs_idx: u32, rhs_idx: u32) -> ExprId {
        self.expr_binary(idx, lhs_idx, rhs_idx, ExprKind::Equal)
    }

    pub fn expr_not_equal(&mut self, idx: u32, lhs_idx: u32, rhs_idx: u32) -> ExprId {
        self.expr_binary(idx, lhs_idx, rhs_idx, ExprKind::NotEqual)
    }

    pub fn expr_greater_than(&mut self, idx: u32, lhs_idx: u32, rhs_idx: u32) -> ExprId {
        self.expr_binary(idx, lhs_idx, rhs_idx, ExprKind::GreaterThan)
    }

    pub fn expr_less_than(&mut self, idx: u32, lhs_idx: u32, rhs_idx: u32) -> ExprId {
        self.expr_binary(idx, lhs_idx, rhs_idx, ExprKind::LessThan)
    }

    pub fn expr_greater_than_or_equal(&mut self, idx: u32, lhs_idx: u32, rhs_idx: u32) -> ExprId {
        self.expr_binary(idx, lhs_idx, rhs_idx, ExprKind::GreaterThanOrEqual)
    }

    pub fn expr_less_than_or_equal(&mut self, idx: u32, lhs_idx: u32, rhs_idx: u32) -> ExprId {
        self.expr_binary(idx, lhs_idx, rhs_idx, ExprKind::LessThanOrEqual)
    }

    pub fn expr_negative(&mut self, idx: u32, expr_idx: u32) -> ExprId {
        self.expr_unary(idx, expr_idx, ExprKind::Negative)
    }

    pub fn expr_not(&mut self, idx: u32, expr_idx: u32) -> ExprId {
        self.expr_unary(idx, expr_idx, ExprKind::Not)
    }

    pub fn expr_unwrap(&mut self, idx: u32, expr_idx: u32) -> ExprId {
        self.expr_unary(idx, expr_idx, ExprKind::Unwrap)
    }

    pub fn expr_check_unwrap(&mut self, idx: u32, expr_idx: u32) -> ExprId {
        self.expr_unary(idx, expr_idx, ExprKind::CheckUnwrap)
    }

    pub fn expr_is(&mut self, idx: u32, expr_idx: u32, val: bool) -> ExprId {
        let expr = make_id(expr_idx, 1);
        self.expr(idx, ExprKind::Is(expr, val))
    }

    pub fn expr_block(&mut self, idx: u32, block_idx: u32, expr_idx: u32) -> ExprId {
        let block = make_id(block_idx, 1);
        let expr = make_id(expr_idx, 1);
        self.expr(idx, ExprKind::Block(block, expr))
    }

    pub fn expr_substruct(&mut self, idx: u32, expr_idx: u32, ident_idx: u32) -> ExprId {
        let expr = make_id(expr_idx, 1);
        let ident = make_id(ident_idx, 1);
        self.expr(idx, ExprKind::Substruct(expr, ident))
    }

    pub fn expr_match(&mut self, idx: u32, expr_idx: u32) -> ExprId {
        self.expr_unary(idx, expr_idx, ExprKind::Match)
    }

    pub fn expr_optional(&mut self, idx: u32, expr_idx: Option<u32>) -> ExprId {
        let expr = expr_idx.map(|idx| make_id(idx, 1));
        self.expr(idx, ExprKind::Optional(expr))
    }

    pub fn expr_named_struct(
        &mut self,
        idx: u32,
        ident_idx: u32,
        fields: Vec<(u32, u32)>,
    ) -> ExprId {
        let ident = make_id(ident_idx, 1);
        let fields = fields
            .into_iter()
            .map(|(ident_idx, expr_idx)| {
                let ident = make_id(ident_idx, 1);
                let expr = make_id(expr_idx, 1);
                (ident, expr)
            })
            .collect();
        self.expr(idx, ExprKind::NamedStruct(NamedStruct { ident, fields }))
    }

    pub fn expr_function_call(&mut self, idx: u32, ident_idx: u32, args: Vec<u32>) -> ExprId {
        let ident = make_id(ident_idx, 1);
        let args = args.into_iter().map(|idx| make_id(idx, 1)).collect();
        self.expr(idx, ExprKind::FunctionCall(FunctionCall { ident, args }))
    }

    pub fn expr_foreign_function_call(
        &mut self,
        idx: u32,
        module_idx: u32,
        ident_idx: u32,
        args: Vec<u32>,
    ) -> ExprId {
        let module = make_id(module_idx, 1);
        let ident = make_id(ident_idx, 1);
        let args = args.into_iter().map(|idx| make_id(idx, 1)).collect();
        self.expr(
            idx,
            ExprKind::ForeignFunctionCall(ForeignFunctionCall {
                module,
                ident,
                args,
            }),
        )
    }

    pub fn expr_enum_reference(&mut self, idx: u32, ident_idx: u32, value_idx: u32) -> ExprId {
        let ident = make_id(ident_idx, 1);
        let value = make_id(value_idx, 1);
        self.expr(idx, ExprKind::EnumReference(EnumReference { ident, value }))
    }

    pub fn stmt(&mut self, idx: u32, kind: StmtKind) -> StmtId {
        let id = make_id(idx, 1);
        self.hir.stmts.insert(id, Stmt { id, kind });
        id
    }

    pub fn stmt_let(&mut self, idx: u32, ident_idx: u32, expr_idx: u32) -> StmtId {
        let ident = make_id(ident_idx, 1);
        let expr = make_id(expr_idx, 1);
        self.stmt(idx, StmtKind::Let(LetStmt { ident, expr }))
    }

    pub fn stmt_check(&mut self, idx: u32, expr_idx: u32) -> StmtId {
        let expr = make_id(expr_idx, 1);
        self.stmt(idx, StmtKind::Check(CheckStmt { expr }))
    }

    pub fn stmt_return(&mut self, idx: u32, expr_idx: u32) -> StmtId {
        let expr = make_id(expr_idx, 1);
        self.stmt(idx, StmtKind::Return(ReturnStmt { expr }))
    }

    pub fn stmt_if(
        &mut self,
        idx: u32,
        branches: Vec<(u32, Vec<u32>)>,
        else_block_idx: Option<u32>,
    ) -> StmtId {
        let branches: Vec<_> = branches
            .into_iter()
            .map(|(expr_idx, stmt_indices)| {
                let expr = make_id(expr_idx, 1);
                let stmts: Vec<_> = stmt_indices
                    .into_iter()
                    .map(|idx| make_id(idx, 1))
                    .collect();
                IfBranch { expr, stmts }
            })
            .collect();

        let else_block = else_block_idx.map(|idx| make_id(idx, 1));

        self.stmt(
            idx,
            StmtKind::If(IfStmt {
                branches,
                else_block,
            }),
        )
    }

    pub fn stmt_finish(&mut self, idx: u32, block_idx: u32) -> StmtId {
        let block = make_id(block_idx, 1);
        self.stmt(idx, StmtKind::Finish(block))
    }

    pub fn stmt_action_call(&mut self, idx: u32, ident_idx: u32, args: Vec<u32>) -> StmtId {
        let ident = make_id(ident_idx, 1);
        let args = args.into_iter().map(|idx| make_id(idx, 1)).collect();
        self.stmt(idx, StmtKind::ActionCall(ActionCall { ident, args }))
    }

    pub fn stmt_publish(&mut self, idx: u32, expr_idx: u32) -> StmtId {
        let expr = make_id(expr_idx, 1);
        self.stmt(idx, StmtKind::Publish(Publish { exor: expr }))
    }

    pub fn stmt_emit(&mut self, idx: u32, expr_idx: u32) -> StmtId {
        let expr = make_id(expr_idx, 1);
        self.stmt(idx, StmtKind::Emit(Emit { expr }))
    }

    pub fn stmt_function_call(&mut self, idx: u32, ident_idx: u32, args: Vec<u32>) -> StmtId {
        let ident = make_id(ident_idx, 1);
        let args = args.into_iter().map(|idx| make_id(idx, 1)).collect();
        self.stmt(idx, StmtKind::FunctionCall(FunctionCall { ident, args }))
    }

    pub fn stmt_debug_assert(&mut self, idx: u32, expr_idx: u32) -> StmtId {
        let expr = make_id(expr_idx, 1);
        self.stmt(idx, StmtKind::DebugAssert(DebugAssert { expr }))
    }

    pub fn block(&mut self, idx: u32, stmt_indices: Vec<u32>) -> BlockId {
        let stmts: Vec<_> = stmt_indices
            .into_iter()
            .map(|idx| make_id(idx, 1))
            .collect();

        let id = make_id(idx, 1);
        self.hir.blocks.insert(id, Block { id, stmts });
        id
    }

    pub fn action_arg(&mut self, idx: u32, ident_idx: u32, type_idx: u32) -> ActionArgId {
        let ident = make_id(ident_idx, 1);
        let ty = make_id(type_idx, 1);
        let id = make_id(idx, 1);
        self.hir.action_args.insert(id, ActionArg { id, ident, ty });
        id
    }

    pub fn action(&mut self, idx: u32, arg_indices: Vec<u32>, block_idx: u32) -> ActionId {
        let args: Vec<_> = arg_indices.into_iter().map(|idx| make_id(idx, 1)).collect();
        let block = make_id(block_idx, 1);
        let id = make_id(idx, 1);
        self.hir.actions.insert(id, ActionDef { id, args, block });
        id
    }

    pub fn struct_field(&mut self, idx: u32, ident_idx: u32, type_idx: u32) -> StructFieldId {
        let ident = make_id(ident_idx, 1);
        let ty = make_id(type_idx, 1);
        let id = make_id(idx, 1);
        self.hir.struct_fields.insert(
            id,
            StructField {
                id,
                kind: StructFieldKind::Field { ident, ty },
            },
        );
        id
    }

    pub fn struct_ref(&mut self, idx: u32, ident_idx: u32) -> StructFieldId {
        let ident = make_id(ident_idx, 1);
        let id = make_id(idx, 1);
        self.hir.struct_fields.insert(
            id,
            StructField {
                id,
                kind: StructFieldKind::StructRef(ident),
            },
        );
        id
    }

    pub fn struct_def(&mut self, idx: u32, field_indices: Vec<u32>) -> StructId {
        let items: Vec<_> = field_indices
            .into_iter()
            .map(|idx| make_id(idx, 1))
            .collect();
        let id = make_id(idx, 1);
        self.hir.structs.insert(id, StructDef { id, items });
        id
    }

    pub fn func_arg(&mut self, idx: u32, ident_idx: u32, type_idx: u32) -> FuncArgId {
        let ident = make_id(ident_idx, 1);
        let ty = make_id(type_idx, 1);
        let id = make_id(idx, 1);
        self.hir.func_args.insert(id, FuncArg { id, ident, ty });
        id
    }

    pub fn func(
        &mut self,
        idx: u32,
        arg_indices: Vec<u32>,
        result_type_idx: u32,
        stmt_indices: Vec<u32>,
    ) -> FuncId {
        let args: Vec<_> = arg_indices.into_iter().map(|idx| make_id(idx, 1)).collect();
        let result = make_id(result_type_idx, 1);
        let stmts: Vec<_> = stmt_indices
            .into_iter()
            .map(|idx| make_id(idx, 1))
            .collect();

        let id = make_id(idx, 1);
        self.hir.funcs.insert(
            id,
            FuncDef {
                id,
                args,
                result,
                stmts,
            },
        );
        id
    }
}

/*
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_hir_macro() {
        let test_hir = hir! {
            idents: {
                1 => "name",
                2 => "age",
            },
            types: {
                1 => String,
                2 => Int,
            },
            exprs: {
                1 => Int,
                2 => Bool,
            },
            stmts: {
                1 => { Let { ident: 1, expr: 1 } },
                2 => { Check { expr: 2 } },
            },
            blocks: {
                1 => { stmts: [1, 2] },
                2 => { stmts: [] },
            },
            action_args: {
                1 => { ident: 1, ty: 1 },
                2 => { ident: 2, ty: 2 },
            },
            actions: {
                1 => { args: [1, 2], block: 1 },
                2 => { args: [], block: 2 },
            },
        };

        // Verify the structure was created
        assert_eq!(test_hir.actions.len(), 2);
        assert_eq!(test_hir.action_args.len(), 2);
        assert_eq!(test_hir.blocks.len(), 2);
        assert_eq!(test_hir.stmts.len(), 2);
        assert_eq!(test_hir.exprs.len(), 2);
        assert_eq!(test_hir.idents.len(), 2);
        assert_eq!(test_hir.types.len(), 2);

        // Verify some specific values using predictable IDs
        // Note: All SlotMap IDs start at 1 due to sentinel at index 0
        let action_0_id = make_id::<ActionId>(1, 1);
        let action_0 = &test_hir.actions[&action_0_id];
        assert_eq!(action_0.args.len(), 2);

        let ident_0_id = make_id::<IdentId>(1, 1);
        let ident_0 = &test_hir.idents[&ident_0_id];
        assert_eq!(ident_0.ident, ast::ident!("name"));
    }

    #[test]
    fn test_hir_builder() {
        let mut builder = HirBuilder::new();

        // Create idents
        let name_id = builder.ident(0, "name");
        let age_id = builder.ident(1, "age");

        // Create types
        let string_ty = builder.vtype_string(0);
        let int_ty = builder.vtype_int(1);

        // Build HIR
        let test_hir = builder.build();

        // Verify
        assert_eq!(test_hir.idents.len(), 2);
        assert_eq!(test_hir.types.len(), 2);
        assert_eq!(test_hir.idents[&name_id].ident, ast::ident!("name"));
        assert_eq!(test_hir.idents[&age_id].ident, ast::ident!("age"));

        match &test_hir.types[&string_ty].kind {
            VTypeKind::String => {}
            _ => panic!("Expected String type"),
        }

        match &test_hir.types[&int_ty].kind {
            VTypeKind::Int => {}
            _ => panic!("Expected Int type"),
        }
    }

    #[test]
    fn test_hir_macro_with_expressions() {
        let test_hir = hir! {
            idents: {
                0 => "x",
                1 => "y",
            },
            types: {
                0 => Int,
                1 => Bool,
            },
            exprs: {
                0 => { Identifier(0) },
                1 => { Identifier(1) },
                2 => { Add(0, 1) },
                3 => Int,
                4 => { GreaterThan(2, 3) },
                5 => { Not(4) },
            },
            stmts: {
                0 => { Return { expr: 5 } },
            },
            func_args: {
                0 => { ident: 0, ty: 0 },
                1 => { ident: 1, ty: 0 },
            },
            funcs: {
                0 => { args: [0, 1], result: 1, stmts: [0] },
            },
        };

        // Verify the structure
        assert_eq!(test_hir.exprs.len(), 6);
        assert_eq!(test_hir.funcs.len(), 1);
        assert_eq!(test_hir.func_args.len(), 2);
        assert_eq!(test_hir.stmts.len(), 1);

        // Check expression types using predictable IDs
        let expr_2_id = make_id::<ExprId>(2, 1);
        match &test_hir.exprs[&expr_2_id].kind {
            ExprKind::Add(_, _) => {}
            _ => panic!("Expected Add expression"),
        }
        let expr_4_id = make_id::<ExprId>(4, 1);
        match &test_hir.exprs[&expr_4_id].kind {
            ExprKind::GreaterThan(_, _) => {}
            _ => panic!("Expected GreaterThan expression"),
        }
        let expr_5_id = make_id::<ExprId>(5, 1);
        match &test_hir.exprs[&expr_5_id].kind {
            ExprKind::Not(_) => {}
            _ => panic!("Expected Not expression"),
        }
    }

    #[test]
    fn test_hir_macro_with_structs() {
        let test_hir = hir! {
            idents: {
                0 => "Person",
                1 => "name",
                2 => "age",
            },
            types: {
                0 => String,
                1 => Int,
            },
            struct_fields: {
                0 => { ident: 1, ty: 0 },
                1 => { ident: 2, ty: 1 },
            },
            structs: {
                0 => { items: [0, 1] },
            },
        };

        // Verify the structure
        assert_eq!(test_hir.structs.len(), 1);
        assert_eq!(test_hir.struct_fields.len(), 2);

        let struct_id = make_id::<StructId>(0, 1);
        let struct_def = &test_hir.structs[&struct_id];
        assert_eq!(struct_def.items.len(), 2);
    }

    #[test]
    fn test_hir_macro_with_struct_ref() {
        let test_hir = hir! {
            idents: {
                0 => "name",
                1 => "BaseStruct",
                2 => "ExtendedStruct",
            },
            types: {
                0 => String,
            },
            struct_fields: {
                0 => { ident: 0, ty: 0 },
                1 => { struct_ref: 1 },
            },
            structs: {
                0 => { items: [0, 1] },
            },
        };

        // Verify the structure
        assert_eq!(test_hir.structs.len(), 1);
        assert_eq!(test_hir.struct_fields.len(), 2);
        assert_eq!(test_hir.idents.len(), 3);

        // Check the struct fields using predictable IDs
        let field_0_id = make_id::<StructFieldId>(0, 1);
        let field_1_id = make_id::<StructFieldId>(1, 1);

        // First field should be a regular field
        match &test_hir.struct_fields[&field_0_id].kind {
            StructFieldKind::Field { ident, ty } => {
                assert_eq!(test_hir.idents[ident].ident, ast::ident!("name"));
                match &test_hir.types[ty].kind {
                    VTypeKind::String => {}
                    _ => panic!("Expected String type"),
                }
            }
            _ => panic!("Expected Field kind"),
        }

        // Second field should be a struct ref
        match &test_hir.struct_fields[&field_1_id].kind {
            StructFieldKind::StructRef(ident) => {
                assert_eq!(test_hir.idents[ident].ident, ast::ident!("BaseStruct"));
            }
            _ => panic!("Expected StructRef kind"),
        }
    }

    #[test]
    fn test_hir_testhir_partial_eq() {
        // Create a TestHir
        // Note: All IDs must start at 1 since SlotMap uses 0 as sentinel
        let test_hir = hir! {
            idents: {
                1 => "foo",
                2 => "bar",
            },
            types: {
                1 => Int,
                2 => String,
            },
            actions: {
                1 => { args: [], block: 1 },
            },
            blocks: {
                1 => { stmts: [] },
            },
        };

        // Create an equivalent Hir manually
        let mut hir = Hir::default();

        // Add idents - Note: SlotMap starts at index 1 due to sentinel at index 0
        let ident_0_id = make_id::<IdentId>(1, 1);
        hir.idents.insert_with_key(|id| {
            assert_eq!(id, ident_0_id);
            Ident {
                id,
                ident: ast::ident!("foo"),
            }
        });
        let ident_1_id = make_id::<IdentId>(2, 1);
        hir.idents.insert_with_key(|id| {
            assert_eq!(id, ident_1_id);
            Ident {
                id,
                ident: ast::ident!("bar"),
            }
        });

        // Add types - Note: SlotMap starts at index 1 due to sentinel at index 0
        let type_0_id = make_id::<VTypeId>(1, 1);
        hir.types.insert_with_key(|id| {
            assert_eq!(id, type_0_id);
            VType {
                id,
                kind: VTypeKind::Int,
            }
        });
        let type_1_id = make_id::<VTypeId>(2, 1);
        hir.types.insert_with_key(|id| {
            assert_eq!(id, type_1_id);
            VType {
                id,
                kind: VTypeKind::String,
            }
        });

        // Add block - Note: SlotMap starts at index 1 due to sentinel at index 0
        let block_0_id = make_id::<BlockId>(1, 1);
        hir.blocks.insert_with_key(|id| {
            assert_eq!(id, block_0_id);
            Block { id, stmts: vec![] }
        });

        // Add action - Note: SlotMap starts at index 1 due to sentinel at index 0
        let action_0_id = make_id::<ActionId>(1, 1);
        hir.actions.insert_with_key(|id| {
            assert_eq!(id, action_0_id);
            ActionDef {
                id,
                args: vec![],
                block: block_0_id,
            }
        });

        // Test PartialEq
        assert_eq!(hir, test_hir);
    }
}*/
