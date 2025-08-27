#![cfg(test)]

use aranya_policy_ast::{ident, Identifier, Version};
use aranya_policy_lang::lang::parse_policy_str;
use pretty_assertions::assert_eq;
use serde::{Deserialize, Serialize};
use test_log::test;

use super::{
    scope::{ScopeId, ScopedId},
    symbols::SymbolKind,
    SymbolResolution,
};
use crate::{
    ast::Ast,
    ctx::{Ctx, InnerCtx, Session},
    diag::DiagCtx,
    hir::{ExprKind, LowerAst},
};

// --- Test Harness ---

type Items = Vec<Item>;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
enum Item {
    Action(Identifier, Items),
    Block(Items),
    Cmd(Identifier),
    Effect(Identifier),
    Enum(Identifier),
    Fact(Identifier),
    FinishFunc(Identifier, Items),
    Func(Identifier, Items),
    GlobalVar(Identifier, Items),
    LocalVar(Identifier, Items),
    Struct(Identifier),
}

impl Ctx<'_> {
    /// Recursively retrieves all items in the scope, building a tree of `Item`s.
    fn get_all_items(&self) -> Items {
        self.get_items(ScopeId::GLOBAL)
    }

    fn get_items(&self, id: ScopeId) -> Items {
        let mut items = Items::new();
        let view = self.symbols().unwrap();
        let scope = view.table().scopes.get(id).unwrap();
        for (xref, sym_id) in &scope.symbols {
            let ident = self.get_ident(*xref).clone();
            let sym = view.get(*sym_id);
            let item = match sym.kind {
                SymbolKind::Item(item_kind) => match item_kind {
                    super::ItemKind::Action(id) => {
                        let act = self.hir().unwrap().lookup(id);
                        Item::Action(ident, self.get_scoped_items(act.body))
                    }
                    super::ItemKind::Cmd(_) => Item::Cmd(ident),
                    super::ItemKind::Effect(_) => Item::Effect(ident),
                    super::ItemKind::Fact(_) => Item::Fact(ident),
                    super::ItemKind::FinishFunc(id) => {
                        let func = self.hir().unwrap().lookup(id);
                        Item::FinishFunc(ident, self.get_scoped_items(func.body))
                    }
                    super::ItemKind::Func(id) => {
                        let func = self.hir().unwrap().lookup(id);
                        Item::Func(ident, self.get_scoped_items(func.body))
                    }
                    super::ItemKind::GlobalVar(id) => {
                        let v = self.hir().unwrap().lookup(id);
                        let items = match &self.hir().unwrap().lookup(v.expr).kind {
                            ExprKind::Block(block, _) => self.get_scoped_items(block.clone()),
                            _ => vec![],
                        };
                        Item::GlobalVar(ident, items)
                    }
                    super::ItemKind::LocalVar(id) => {
                        let items = id.map(|id| self.get_scoped_items(id)).unwrap_or_default();
                        Item::LocalVar(ident, items)
                    }
                    _ => continue,
                },
                SymbolKind::Type(type_kind) => match type_kind {
                    super::TypeKind::Struct(_, _) => Item::Struct(ident),
                    super::TypeKind::Enum(_) => Item::Enum(ident),
                },
            };
            items.push(item);
        }
        items.sort();
        items
    }

    fn get_scoped_items(&self, id: impl Into<ScopedId>) -> Items {
        let id = id.into();
        let scope = self
            .symbols()
            .unwrap()
            .table()
            .scopemap
            .get(&id)
            .unwrap_or_else(|| panic!("unknown `ScopedId`: {{id:?}}"));
        self.get_items(*scope)
    }
}

/// A DSL for defining the expected scope structure in tests.
macro_rules! scope {
    (@global [$($item:expr,)*]) => { vec![$($item,)*] };
    (@global [$($item:expr),*]) => { vec![$($item),*] };
    (@global [$($item:expr,)*] action($ident:ident): { $($block:tt)* } $($rest:tt)*) => {
        scope!(@global [$($item,)* Item::Action(ident!(stringify!($ident)), scope!(@block [] $($block)*)),] $($rest)*)
    };
    (@global [$($item:expr,)*] cmd($ident:ident) $($rest:tt)*) => {
        scope!(@global [$($item,)* Item::Cmd(ident!(stringify!($ident))),] $($rest)*)
    };
    (@global [$($item:expr,)*] effect($ident:ident) $($rest:tt)*) => {
        scope!(@global [$($item,)* Item::Effect(ident!(stringify!($ident))),] $($rest)*)
    };
    (@global [$($item:expr,)*] enum($ident:ident) $($rest:tt)*) => {
        scope!(@global [$($item,)* Item::Enum(ident!(stringify!($ident))),] $($rest)*)
    };
    (@global [$($item:expr,)*] fact($ident:ident) $($rest:tt)*) => {
        scope!(@global [$($item,)* Item::Fact(ident!(stringify!($ident))),] $($rest)*)
    };
    (@global [$($item:expr,)*] function($ident:ident): { $($block:tt)* } $($rest:tt)*) => {
        scope!(@global [$($item,)* Item::Func(ident!(stringify!($ident)), scope!(@block [] $($block)*)),] $($rest)*)
    };
    (@global [$($item:expr,)*] finish function($ident:ident): { $($block:tt)* } $($rest:tt)*) => {
        scope!(@global [$($item,)* Item::FinishFunc(ident!(stringify!($ident)), scope!(@block [] $($block)*)),] $($rest)*)
    };
    (@global [$($item:expr,)*] global($ident:ident): { $($block:tt)* } $($rest:tt)*) => {
        scope!(@global [$($item,)* Item::GlobalVar(ident!(stringify!($ident)), scope!(@block [] $($block)*)),] $($rest)*)
    };
    (@global [$($item:expr,)*] struct($ident:ident) $($rest:tt)*) => {
        scope!(@global [$($item,)* Item::Struct(ident!(stringify!($ident))),] $($rest)*)
    };
    (@global [$($item:expr),*] , $($rest:tt)*) => {
        scope!(@global [$($item,)*] $($rest)*)
    };
    (@block [$($item:expr,)*]) => { vec![$($item,)*] };
    (@block [$($item:expr),*]) => { vec![$($item),*] };
    (@block [$($item:expr,)*] $ident:ident : { $($block:tt)* } $($rest:tt)*) => {
        scope!(@block [$($item,)* Item::LocalVar(ident!(stringify!($ident)), scope!(@block [] $($block)*)),] $($rest)*)
    };
    (@block [$($item:expr,)*] $ident:ident, $($rest:tt)*) => {
        scope!(@block [$($item,)* Item::LocalVar(ident!(stringify!($ident)), vec![]),] $($rest)*)
    };
    (@block [$($item:expr,)*] $ident:ident) => {
        scope!(@block [$($item,)* Item::LocalVar(ident!(stringify!($ident)), vec![]),] )
    };
    (@block [$($item:expr,)*] { $($block:tt)* } $($rest:tt)*) => {
        scope!(@block [$($item,)* Item::Block(scope!(@block [] $($block)*)),] $($rest)*)
    };
    (@block [$($item:expr,)*] , $($rest:tt)*) => {
        scope!(@block [$($item,)*] $($rest)*)
    };
    ($($tt:tt)+) => {{ scope!(@global [] $($tt)+) }};
}

fn with_symtab<T>(policy_text: &str, f: impl for<'cx> FnOnce(Ctx<'cx>) -> T) -> T {
    let policy = parse_policy_str(policy_text, Version::V2).expect("parse");
    let codemap = aranya_policy_module::CodeMap::new(&policy.text, policy.ranges.clone());
    let sess = Session {
        dcx: DiagCtx::new(&policy.text, "test.policy"),
    };
    let ast = crate::ast::Ast {
        ast: &policy,
        schemas: &[],
        codemap: &codemap,
    };
    let inner = InnerCtx::new(&sess, ast);
    let cx = Ctx { inner: &inner };

    cx.get::<LowerAst>().expect("lower hir failed");
    cx.get::<SymbolResolution>()
        .expect("symbol resolution failed");

    f(cx)
}

fn check_resolution_fails(text: &str) {
    let policy = parse_policy_str(text, Version::V2).unwrap();
    let codemap = aranya_policy_module::CodeMap::new(&policy.text, policy.ranges.clone());
    let sess = Session {
        dcx: DiagCtx::new(&policy.text, "test.policy"),
    };
    let ast = crate::ast::Ast {
        ast: &policy,
        schemas: &[],
        codemap: &codemap,
    };
    let inner = InnerCtx::new(&sess, ast);
    let cx = Ctx { inner: &inner };

    cx.get::<LowerAst>().unwrap();
    let result = cx.get::<SymbolResolution>();
    assert!(result.is_err(), "Expected symbol resolution to fail for policy:\n{{text}}");
}

// --- Tests ---

#[test]
fn test_basic() {
    let text = r###"#
        action act1() {}
        action act2(x int) {}
        action act3(x int, y int) {
            let z = x + y
        }

        function func1(x int, y struct S1) bool {
            let z = {
                let a = y.field;
                let b = a + 1;
                : x + b
            };
            return z < 100
        }
        function func2() bool {
            return { : { : { : true } } }
        }
        function func3(ok bool) bool {
            return { : { : { : ok } } }
        }

        finish function ff1() {
            let x = 42
        }
        finish function ff2(y int) {}
        finish function ff3() {}
        finish function ff4(x int) {
            let y = 42
        }

        let gx = 42
        let gy = {
            let tmp = gx + 1;
            : tmp
        }

        struct S1 {
            field int,
        }
        struct S2 {
            a int,
            b bool,
        }
    "###;
    with_symtab(text, |cx| {
        let mut want = scope! {
            action(act1): {}
            action(act2): { x }
            action(act3): { x, y, z }
            function(func1): { x, y, z: { a, b } }
            function(func2): { { { } } }
            function(func3): { ok, { { { } } } }
            finish function(ff1): { x }
            finish function(ff2): { y }
            finish function(ff3): {}
            finish function(ff4): { x, y }
            global(gx): {}
            global(gy): { tmp }
            struct(S1)
            struct(S2)
        };
        want.sort();

        let mut got = cx.get_all_items();
        got.sort();

        assert_eq!(got, want);
    });
}

#[test]
fn duplicate_symbols_are_rejected() {
    check_resolution_fails(r###"#
        action a() {}
        action a() {}
    "###);

    check_resolution_fails(r###"#
        function f() {}
        function f() {}
    "###);

    check_resolution_fails(r###"#
        let g = 1;
        let g = 2;
    "###);

    check_resolution_fails(r###"#
        action a() {}
        function a() {}
    "###);

    check_resolution_fails(r###"#
        function f(p: int, p: bool) {}
    "###);

    check_resolution_fails(r###"#
        function f() {
            let x = 1;
            let x = 2;
        }
    "###);
}

#[test]
fn undefined_symbols_are_rejected() {
    check_resolution_fails(r###"#
        function f() {
            g(); // g is not defined
        }
    "###);

    check_resolution_fails(r###"#
        function f() {
            let x = y; // y is not defined
        }
    "###);

    check_resolution_fails(r###"#
        function f(p: struct S) {}
    "###);
}

#[test]
fn test_command_effect_fact_symbols() {
    let text = "command DoIt { target: string, }\neffect DidIt { target: string, }\nfact AboutIt { subject: string, }";
    with_symtab(text, |cx| {
        let mut want = scope! {
            cmd(DoIt)
            struct(DoIt)
            effect(DidIt)
            struct(DidIt)
            fact(AboutIt)
            struct(AboutIt)
        };
        want.sort();

        let mut got = cx.get_all_items();
        got.sort();

        assert_eq!(got, want);
    });
}