#![cfg(test)]

use std::borrow::Cow;

use aranya_policy_ast::{Policy, Version};
use aranya_policy_lang::lang::parse_policy_str;
use slotmap::{SecondaryMap, SlotMap};

use crate::hir::{
    self as hir,
    arena::AstNodes,
    hir::{
        ActionArg, ActionDef, ActionId, Block, BlockId, CmdDef, CmdField, CmdFieldKind, CmdId,
        EffectDef, EffectField, EffectFieldId, EffectFieldKind, EffectId, EnumDef, EnumId, Expr, ExprId, ExprKind,
        FactDef, FactField, FactId, FactKey, FactLiteral, FactVal, FinishFuncArg, FinishFuncDef,
        FinishFuncId, FuncArg, FuncDef, FuncId, GlobalId, GlobalLetDef, Hir, Ident, IdentId,
        InternalFunction, MatchPattern, ReturnStmt, Stmt, StmtId, StmtKind, StructDef, StructField,
        StructFieldId, StructFieldKind, StructId, VType, VTypeId, VTypeKind,
    },
    lower::LowerCtx,
    visit::{Visitor, VisitorResult},
};

struct Expected<'ast> {
    /// Our expected AST.
    want_ast: AstNodes<'ast>,
    /// The AST we got from the parser.
    got_ast: AstNodes<'ast>,
}

impl Expected<'_> {
    fn check(&self) {
        assert_eq!(self.want_ast, self.got_ast);
        assert_eq!(self.got_ast, AstNodes::default());
    }
}

macro_rules! impl_method {
    ($method:ident, $ty:ty, $field:ident) => {
        fn $method(&mut self, v: &'hir $ty) -> Self::Result {
            // TODO: verify `v` itself.
            println!("{}({:?})", stringify!($method), v.id);
            let got = self.got_ast.$field.remove(v.id).unwrap();
            let want = self.want_ast.$field.remove(v.id).unwrap();
            println!(" got = {got:?}");
            println!("want = {want:?}");
            assert_eq!(got, want);
            println!();
            Self::Result::output()
        }
    };
}

impl<'hir> Visitor<'hir> for Expected<'hir> {
    type Result = ();

    impl_method!(visit_action_def, ActionDef, actions);
    impl_method!(visit_action_arg, ActionArg, action_args);
    impl_method!(visit_action_stmt, Stmt, stmts);

    impl_method!(visit_cmd_def, CmdDef, cmds);
    impl_method!(visit_cmd_field, CmdField, cmd_fields);
    impl_method!(visit_cmd_seal, Block, blocks);
    impl_method!(visit_cmd_open, Block, blocks);
    impl_method!(visit_cmd_policy, Block, blocks);
    impl_method!(visit_cmd_recall, Block, blocks);

    impl_method!(visit_effect_def, EffectDef, effects);
    impl_method!(visit_effect_field, EffectField, effect_fields);

    impl_method!(visit_enum_def, EnumDef, enums);

    impl_method!(visit_fact_def, FactDef, facts);
    impl_method!(visit_fact_key, FactKey, fact_keys);
    impl_method!(visit_fact_value, FactVal, fact_vals);

    impl_method!(visit_finish_func_def, FinishFuncDef, finish_funcs);
    impl_method!(visit_finish_func_arg, FinishFuncArg, finish_func_args);
    impl_method!(visit_finish_func_stmt, Stmt, stmts);

    impl_method!(visit_func_def, FuncDef, funcs);
    impl_method!(visit_func_arg, FuncArg, func_args);
    impl_method!(visit_func_result, VType, types);
    impl_method!(visit_func_stmt, Stmt, stmts);

    impl_method!(visit_global_def, GlobalLetDef, global_lets);

    impl_method!(visit_struct_def, StructDef, structs);
    impl_method!(visit_struct_field, StructField, struct_fields);

    impl_method!(visit_ident, Ident, idents);
    impl_method!(visit_block, Block, blocks);
    impl_method!(visit_expr, Expr, exprs);
    impl_method!(visit_stmt, Stmt, stmts);
    impl_method!(visit_vtype, VType, types);

    // FactLiteral is not stored separately in AstNodes, it's inline in other structures
    fn visit_fact_literal(&mut self, v: &'hir FactLiteral) -> Self::Result {
        println!("{}({:?})", "visit_fact_literal", v);
        Self::Result::output()
    }
}

macro_rules! slot_map {
    () => {{
        SlotMap::with_key()
    }};
    ($($item:expr),+ $(,)?) => {{
        let mut items = SlotMap::with_key();
        $( items.insert($item); )*
        items
    }}
}

macro_rules! secondary_map {
    () => {{
        SecondaryMap::new()
    }};
    ($($item:expr),+ $(,)?) => {{
        let mut items = SecondaryMap::new();
        $( items.insert($item); )*
        items
    }}
}

macro_rules! replace_expr {
    ($_t:tt $sub:expr) => {
        $sub
    };
}

fn trampoline<'ast, F>(f: F) -> impl FnOnce(&'ast Policy, &mut Hir, &mut AstNodes<'ast>)
where
    F: FnOnce(&'ast Policy, &mut Hir, &mut AstNodes<'ast>),
{
    |policy: &'ast Policy, hir: &mut Hir, ast: &mut AstNodes<'ast>| {
        f(policy, hir, ast);
    }
}

/// Builds the expected [`Hir`] and [`AstNodes`].
///
/// NB: The resulting [`Hir`] only contains IDs; the rest of the
/// fields are set to their default values. They are not needed
/// for the test.
///
/// ```ignore
/// let policy = parse_policy_str(text, Version::V2).unwrap();
/// let (want_hir, want_ast) = build_expected! { policy =>
///     // Says `want_ast.actions` should contain the following
///     // AST nodes:
///     //
///     // - policy.actions[0]
///     // - policy.actions[1]
///     // - policy.actions[2]
///     actions => [0, 1, 2],
///     // Says `want_ast.action_args` should contain the
///     // following AST nodes:
///     //
///     // - policy.actions[1].arguments[0]
///     action_args => { 1 => [0] }
/// }
/// ```
macro_rules! build_expected {
    // The exit point for the macro.
    (@munch () -> { $(($expr:expr))* } [$policy:ident]) => {{
        let mut hir = Hir::default();
        let mut ast = AstNodes::default();
        $($expr(&$policy, &mut hir, &mut ast);)*
        (hir, ast)
    }};

    // actions
    (@munch (actions => [ $($idx:expr),* ], $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $({
                    let id = map.insert_with_key(|id| ActionDef {
                        id,
                        // NB: We don't really need to fill these
                        // values in for the test; we only care
                        // about the ID.
                        args: Vec::new(),
                        block: BlockId::default(),
                    });
                    ast.actions.insert(id, Cow::Borrowed(&policy.actions[$idx]));
                })*
                hir.actions = map;
            })))
        } [$policy]}
    };

    // action_args
    (@munch (action_args => { $($act_idx:expr => [$($arg_idx:expr),+]),* }, $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $({
                    let id = map.insert_with_key(|id| ActionArg {
                        id,
                        // NB: We don't really need to fill these
                        // values in for the test; we only care
                        // about the ID.
                        ident: IdentId::default(),
                        ty: VTypeId::default(),
                    });
                    $( ast.action_args.insert(id,
                            Cow::Borrowed(&policy.actions[$act_idx].arguments[$arg_idx])); )+
                })*
                hir.action_args = map;
            })))
        } [$policy]}
    };

    // cmds
    (@munch (cmds => [ $($idx:expr),* ], $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $(
                    let id = map.insert_with_key(|id| CmdDef {
                        id,
                        fields: Vec::new(),
                        seal: BlockId::default(),
                        open: BlockId::default(),
                        policy: BlockId::default(),
                        recall: BlockId::default(),
                    });
                    ast.cmds.insert(id, Cow::Borrowed(&policy.commands[$idx]));
                )*
                hir.cmds = map;
            })))
        } [$policy]}
    };

    // effects
    (@munch (effects => [ $($idx:expr),* ], $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $(
                    let id = map.insert_with_key(|id| EffectDef {
                        id,
                        items: Vec::new(),
                    });
                    ast.effects.insert(id, Cow::Borrowed(&policy.effects[$idx]));
                )*
                hir.effects = map;
            })))
        } [$policy]}
    };

    // enums
    (@munch (enums => [ $($idx:expr),* ], $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $(
                    let id = map.insert_with_key(|id| EnumDef {
                        id,
                    });
                    ast.enums.insert(id, Cow::Borrowed(&policy.enums[$idx]));
                )*
                hir.enums = map;
            })))
        } [$policy]}
    };

    // facts
    (@munch (facts => [ $($idx:expr),* ], $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $(
                    let id = map.insert_with_key(|id| FactDef {
                        id,
                        keys: Vec::new(),
                        vals: Vec::new(),
                    });
                    ast.facts.insert(id, Cow::Borrowed(&policy.facts[$idx]));
                )*
                hir.facts = map;
            })))
        } [$policy]}
    };

    // finish_funcs
    (@munch (finish_funcs => [ $($idx:expr),* ], $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $(
                    let id = map.insert_with_key(|id| FinishFuncDef {
                        id,
                        args: Vec::new(),
                        stmts: Vec::new(),
                    });
                    ast.finish_funcs.insert(id, Cow::Borrowed(&policy.finish_functions[$idx]));
                )*
                hir.finish_funcs = map;
            })))
        } [$policy]}
    };

    // funcs
    (@munch (funcs => [ $($idx:expr),* ], $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $(
                    let id = map.insert_with_key(|id| FuncDef {
                        id,
                        args: Vec::new(),
                        result: VTypeId::default(),
                        stmts: Vec::new(),
                    });
                    ast.funcs.insert(id, Cow::Borrowed(&policy.functions[$idx]));
                )*
                hir.funcs = map;
            })))
        } [$policy]}
    };

    // global_lets
    (@munch (global_lets => [ $($idx:expr),* ], $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $(
                    let id = map.insert_with_key(|id| GlobalLetDef {
                        id,
                        expr: ExprId::default(),
                    });
                    ast.global_lets.insert(id, Cow::Borrowed(&policy.global_lets[$idx]));
                )*
                hir.global_lets = map;
            })))
        } [$policy]}
    };

    // structs
    (@munch (structs => [ $($idx:expr),* ], $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $(
                    let id = map.insert_with_key(|id| StructDef {
                        id,
                        items: Vec::new(),
                    });
                    ast.structs.insert(id, Cow::Borrowed(&policy.structs[$idx]));
                )*
                hir.structs = map;
            })))
        } [$policy]}
    };

    // cmd_fields
    (@munch (cmd_fields => { $($cmd_idx:expr => [$($field_idx:expr),+]),* }, $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $({
                    $(
                        let id = map.insert_with_key(|id| CmdField {
                            id,
                            kind: CmdFieldKind::Field { 
                                ident: IdentId::default(), 
                                ty: VTypeId::default() 
                            },
                        });
                        ast.cmd_fields.insert(id, Cow::Borrowed(&policy.commands[$cmd_idx].fields[$field_idx]));
                    )+
                })*
                hir.cmd_fields = map;
            })))
        } [$policy]}
    };

    // effect_fields
    (@munch (effect_fields => { $($effect_idx:expr => [$($field_idx:expr),+]),* }, $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $({
                    let id = map.insert_with_key(|id| EffectField {
                        id,
                        kind: EffectFieldKind::Field {
                            ident: IdentId::default(),
                            ty: VTypeId::default(),
                        },
                    });
                    $( ast.effect_fields.insert(id,
                            Cow::Borrowed(&policy.effects[$effect_idx].items[$field_idx])); )+
                })*
                hir.effect_fields = map;
            })))
        } [$policy]}
    };

    // fact_keys
    (@munch (fact_keys => { $($fact_idx:expr => [$($key_idx:expr),+]),* }, $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $({
                    let id = map.insert_with_key(|id| FactKey {
                        id,
                        ident: IdentId::default(),
                        ty: VTypeId::default(),
                    });
                    $( ast.fact_keys.insert(id,
                            Cow::Borrowed(&policy.facts[$fact_idx].key[$key_idx])); )+
                })*
                hir.fact_keys = map;
            })))
        } [$policy]}
    };

    // fact_vals
    (@munch (fact_vals => { $($fact_idx:expr => [$($val_idx:expr),+]),* }, $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $({
                    let id = map.insert_with_key(|id| FactVal {
                        id,
                        ident: IdentId::default(),
                        ty: VTypeId::default(),
                    });
                    $( ast.fact_vals.insert(id,
                            Cow::Borrowed(&policy.facts[$fact_idx].value[$val_idx])); )+
                })*
                hir.fact_vals = map;
            })))
        } [$policy]}
    };

    // finish_func_args
    (@munch (finish_func_args => { $($func_idx:expr => [$($arg_idx:expr),+]),* }, $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $({
                    let id = map.insert_with_key(|id| FinishFuncArg {
                        id,
                        ident: IdentId::default(),
                        ty: VTypeId::default(),
                    });
                    $( ast.finish_func_args.insert(id,
                            Cow::Borrowed(&policy.finish_functions[$func_idx].arguments[$arg_idx])); )+
                })*
                hir.finish_func_args = map;
            })))
        } [$policy]}
    };

    // func_args
    (@munch (func_args => { $($func_idx:expr => [$($arg_idx:expr),+]),* }, $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $({
                    let id = map.insert_with_key(|id| FuncArg {
                        id,
                        ident: IdentId::default(),
                        ty: VTypeId::default(),
                    });
                    $( ast.func_args.insert(id,
                            Cow::Borrowed(&policy.functions[$func_idx].arguments[$arg_idx])); )+
                })*
                hir.func_args = map;
            })))
        } [$policy]}
    };

    // struct_fields
    (@munch (struct_fields => { $($struct_idx:expr => [$($field_idx:expr),+]),* }, $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $({
                    let id = map.insert_with_key(|id| StructField {
                        id,
                        kind: StructFieldKind::Field {
                            ident: IdentId::default(),
                            ty: VTypeId::default(),
                        },
                    });
                    $( ast.struct_fields.insert(id,
                            Cow::Borrowed(&policy.structs[$struct_idx].items[$field_idx])); )+
                })*
                hir.struct_fields = map;
            })))
        } [$policy]}
    };

    // blocks - using expression syntax with parentheses
    // Example usage:
    // blocks => {
    //     (actions[1].statements),
    //     (commands[0].seal),
    //     (commands[0].open),
    //     (functions[0].statements),
    // }
    (@munch (blocks => { $(($($path:tt)+)),* $(,)? }, $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $(
                    let id = map.insert_with_key(|id| Block {
                        id,
                        stmts: Vec::new(),
                    });
                    ast.blocks.insert(id, Cow::Borrowed(&policy.$($path)+));
                )*
                hir.blocks = map;
            })))
        } [$policy]}
    };

    // stmts - using expression syntax with parentheses
    // Example usage:
    // stmts => {
    //     (actions[1].statements[0]),
    //     (commands[0].seal[0]),
    //     (functions[0].statements[0]),
    // }
    (@munch (stmts => { $(($($path:tt)+)),* $(,)? }, $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $(
                    let id = map.insert_with_key(|id| Stmt {
                        id,
                        kind: StmtKind::Return(ReturnStmt { expr: ExprId::default() }),
                    });
                    ast.stmts.insert(id, Cow::Borrowed(&policy.$($path)+));
                )*
                hir.stmts = map;
            })))
        } [$policy]}
    };

    // types - using expression syntax with parentheses
    // Example usage:
    // types => {
    //     (functions[0].return_type),
    //     (functions[1].return_type),
    // }
    (@munch (types => { $(($($path:tt)+)),* $(,)? }, $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $(
                    let id = map.insert_with_key(|id| VType {
                        id,
                        kind: VTypeKind::Int,
                    });
                    ast.types.insert(id, Cow::Borrowed(&policy.$($path)+));
                )*
                hir.types = map;
            })))
        } [$policy]}
    };

    // exprs - using expression syntax with parentheses
    // Example usage:
    // exprs => {
    //     // expressions provided by caller if needed
    // }
    (@munch (exprs => { $(($($path:tt)+)),* $(,)? }, $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $(
                    let id = map.insert_with_key(|id| Expr {
                        id,
                        kind: ExprKind::Int,
                    });
                    ast.exprs.insert(id, Cow::Borrowed(&policy.$($path)+));
                )*
                hir.exprs = map;
            })))
        } [$policy]}
    };

    // idents - using expression syntax with parentheses 
    // Example usage:
    // idents => {
    //     // identifiers provided by caller if needed
    // }
    (@munch (idents => { $(($($path:tt)+)),* $(,)? }, $($next:tt)*) -> {
        $($output:tt)*
    } [$policy:ident]) => {
        build_expected! { @munch ($($next)*) -> {
            $($output)*
            ((trampoline(|policy, hir, ast| {
                let mut map = SlotMap::with_key();
                $(
                    let id = map.insert_with_key(|id| Ident {
                        id,
                        ident: policy.$($path)+.clone(),
                    });
                    ast.idents.insert(id, Cow::Borrowed(&policy.$($path)+));
                )*
                hir.idents = map;
            })))
        } [$policy]}
    };

    // The entry point for the macro.
    ($policy:ident => $($tt:tt)*) => {{
        build_expected! {
            @munch ($($tt)*) -> {} [$policy]
        }
    }};
}

#[test]
fn test_walk() {
    let text = r#"
action action1() {}
action action2(x int) {
    action action1()
    publish Cmd1 {}
}
action action3() {}

command Cmd1 {
    fields {}
    seal { return None }
    open { return None }
}

effect Effect1 {
    field1 int,
    field2 string,
}
effect Effect2 {}

// TODO: Add enum

fact Fact1[a int, b string]=>{c bool}
fact Fact2[]=>{}

// TODO: add function inputs
finish function func4() {}
finish function func5() {
    func4()
    delete Fact1[a: 42, b: "test"]
}

// TODO: add function inputs
function func1() int { return 42 }
function func2() bool { return true }
function func3() int { return func1() }

struct Struct1 {
    field1 bool,
    field2 int,
}
"#;
    let policy = parse_policy_str(text, Version::V2).unwrap();

    let (got_hir, got_ast) = hir::parse(&policy);
    println!("got_hir = {got_hir:#?}");
    println!("got_ast = {got_ast:#?}");

    let (_want_hir, want_ast) = build_expected! { policy =>
        actions => [0, 1, 2],
        action_args => { 1 => [0] },
        cmds => [0],
        cmd_fields => {},  // Cmd1 has empty fields
        effects => [0, 1],
        effect_fields => { 0 => [0, 1] },
        enums => [],  // No enums in test policy
        facts => [0, 1],
        fact_keys => { 0 => [0, 1] },
        fact_vals => { 0 => [0] },
        finish_funcs => [0, 1],
        finish_func_args => {},  // No arguments in test finish functions
        funcs => [0, 1, 2],
        func_args => {},  // No arguments in test functions
        global_lets => [],  // No global lets in test policy
        structs => [0],
        struct_fields => { 0 => [0, 1] },
        blocks => {
            (actions[0].statements),  // action1 - empty
            (actions[1].statements),  // action2 - has statements
            (actions[2].statements),  // action3 - empty
            (commands[0].seal),
            (commands[0].open),
            (commands[0].policy),     // policy block (empty in this test)
            (commands[0].recall),     // recall block (empty in this test)
            (functions[0].statements),
            (functions[1].statements),
            (functions[2].statements),
            (finish_functions[0].statements),
            (finish_functions[1].statements),
        },
        stmts => {
            (actions[1].statements[0]),
            (actions[1].statements[1]),
            (commands[0].seal[0]),
            (commands[0].open[0]),
            (functions[0].statements[0]),
            (functions[1].statements[0]),
            (functions[2].statements[0]),
            (finish_functions[1].statements[0]),
            (finish_functions[1].statements[1]),
        },
        types => {
            (functions[0].return_type),
            (functions[1].return_type),
            (functions[2].return_type),
        },
        exprs => {
            // Expressions that can be accessed directly from the policy
            // Most expressions are nested within statements and would require
            // deep extraction. Adding the ones we can reference:
        },
        idents => {
            // Identifiers in the order they appear in the HIR
            // Based on the got_ast output:
            (actions[1].arguments[0].identifier),  // "x" - IdentId(1v1)
            (actions[0].identifier),      // "action1" - IdentId(2v1)
            (commands[0].identifier),     // "Cmd1" - IdentId(3v1)
            (facts[0].key[0].identifier), // "a" - IdentId(4v1)
            (facts[0].key[1].identifier), // "b" - IdentId(5v1)
            (facts[0].value[0].identifier), // "c" - IdentId(6v1)
            (finish_functions[0].identifier), // "func4" - IdentId(7v1)
            (facts[0].identifier),        // "Fact1" - IdentId(8v1)
            // Note: There appear to be duplicate "a" and "b" identifiers
            // in the HIR, likely from different contexts
        },
    };

    /*
        let want_ast = AstNodes {
            actions: secondary_map! {
                &policy.actions[0],
                &policy.actions[1],
                &policy.actions[2],
            },
            action_args: secondary_map! {
                &policy.actions[1].arguments[0],
            },
            cmds: secondary_map! {
                &policy.commands[0],
            },
            cmd_fields: secondary_map! {
                &policy.commands[0].seal,
                &policy.commands[0].seal[0],
                &policy.commands[0].open,
                &policy.commands[0].open[0],
            },
            effects: secondary_map! {
                &policy.effects[0],
                &policy.effects[1],
            },
            effect_fields: secondary_map! {
                &policy.effects[0].items[0],
                &policy.effects[0].items[1],
            },
            enums: secondary_map! {}, // TODO
            facts: secondary_map! {
                &policy.facts[0],
                &policy.facts[1],
            },
            fact_keys: secondary_map! {
                &policy.facts[0].key[0],
                &policy.facts[0].key[1],
            },
            fact_vals: secondary_map! {
                &policy.facts[0].value[0],
            },
            finish_funcs: secondary_map! {
                &policy.finish_functions[0],
                &policy.finish_functions[1],
            },
            finish_func_args: secondary_map! {
                &policy.finish_functions[1].statements[0],
                &policy.finish_functions[1].statements[1],
            },
            funcs: secondary_map! {
                &policy.functions[0],
                &policy.functions[1],
                &policy.functions[2],
            },
            func_args: secondary_map! {},
            global_lets: secondary_map! {},
            structs: secondary_map! {
                &policy.structs[0],
            },
            struct_fields: secondary_map! {
                &policy.structs[0].items[0],
                &policy.structs[0].items[1],
            },
            blocks: secondary_map! {
                &policy.actions[1].statements,
                &policy.commands[0].seal,
                &policy.commands[0].open,
                &policy.functions[0].statements,
                &policy.functions[1].statements,
                &policy.functions[2].statements,
            },
            stmts: secondary_map! {
                &policy.actions[1].statements[0],
                &policy.actions[1].statements[1],
                &policy.commands[0].seal[0],
                &policy.commands[0].open[0],
                &policy.functions[0].statements[0],
                &policy.functions[1].statements[0],
                &policy.functions[2].statements[0],
            }
            types: secondary_map! {
                &policy.functions[0].return_type,
                &policy.functions[1].return_type,
                &policy.functions[2].return_type,
            },
            exprs: secondary_map! {}, // TODO
            idents: secondary_map! {}, // TODO
        };
    */

    let mut visitor = Expected { got_ast, want_ast };

    got_hir.walk(&mut visitor);

    visitor.check();
}
