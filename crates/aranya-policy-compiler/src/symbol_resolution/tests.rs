#![cfg(test)]

use std::{collections::BTreeMap, ops::Index};

use aranya_policy_ast::{ident, Identifier, Version};
use aranya_policy_lang::lang::parse_policy_str;
use aranya_policy_module::CodeMap;
use pretty_assertions::assert_eq;
use serde::{Deserialize, Serialize};
use test_log::test;

use super::{
    scope::{Scope, ScopeId, ScopedId, Scopes},
    symbols::SymbolKind,
};
use crate::{ast::Ast, ctx::Ctx, hir::ExprKind};

type Edges = BTreeMap<ScopeId, Vec<ScopeId>>;

impl Scopes {
    #[allow(dead_code)] // TODO
    fn build_edges(&self) -> Edges {
        let mut edges = Edges::new();
        for (id, scope) in &self.scopes {
            if let Some(parent) = &scope.parent {
                edges.entry(id).and_modify(|v| v.push(*parent)).or_default();
            } else {
                // The global scope is the only scope without
                // a parent.
                assert_eq!(id, ScopeId::GLOBAL);
            }
        }
        edges
    }

    fn get_scope(&self, id: ScopeId) -> &Scope {
        &self.scopes[id]
    }
}

impl Ctx<'_> {
    /// Recursively retrieves all items in the scope.
    fn get_items(&self, id: ScopeId) -> Items {
        let mut items = Items::new();
        let scope = self.symbols.scopes.get_scope(id);
        for (xref, sym_id) in &scope.symbols {
            let ident = self.idents.get(*xref).unwrap().clone();
            let sym = self.symbols.symbols.get(*sym_id).unwrap();
            let item = match sym.kind {
                SymbolKind::Action(id) => {
                    let act = self.hir.index(id);
                    Item::Action(ident, self.get_scoped_items(act.block))
                }
                SymbolKind::Cmd(_) => Item::Cmd(ident),
                SymbolKind::Effect(_) => Item::Effect(ident),
                SymbolKind::Enum(_) => Item::Enum(ident),
                SymbolKind::Fact(_) => Item::Fact(ident),
                SymbolKind::FfiEnum(_) => Item::FfiEnum(ident),
                SymbolKind::FfiFunc(_) => Item::FfiFunc(ident),
                SymbolKind::FfiModule { .. } => Item::FfiModule(ident),
                SymbolKind::FfiStruct(_) => Item::FfiStruct(ident),
                SymbolKind::FinishFunc(id) => {
                    let func = self.hir.index(id);
                    Item::FinishFunc(ident, self.get_scoped_items(func.block))
                }
                SymbolKind::Func(id) => {
                    let func = self.hir.index(id);
                    Item::Func(ident, self.get_scoped_items(func.block))
                }
                SymbolKind::GlobalVar(id) => {
                    let v = self.hir.index(id);
                    let items = match &self.hir.index(v.expr).kind {
                        ExprKind::Block(block, _) => self.get_scoped_items(*block),
                        _ => vec![],
                    };
                    Item::GlobalVar(ident, items)
                }
                SymbolKind::LocalVar(id) => {
                    let items = id.map(|id| self.get_scoped_items(id)).unwrap_or_default();
                    Item::LocalVar(ident, items)
                }
                SymbolKind::Struct(_) => Item::Struct(ident),
            };
            items.push(item);
        }
        items
    }

    fn get_scoped_items(&self, id: impl Into<ScopedId>) -> Items {
        let id = id.into();
        let scope = self
            .symbols
            .scopemap
            .get(&id)
            .unwrap_or_else(|| panic!("unknown `Scoped` ID: {id:?}"));
        self.get_items(*scope)
    }
}

type Items = Vec<Item>;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
enum Item {
    Action(Identifier, Items),
    Block(Items),
    Cmd(Identifier),
    Effect(Identifier),
    Enum(Identifier),
    Fact(Identifier),
    FfiEnum(Identifier),
    FfiFunc(Identifier),
    FfiModule(Identifier),
    FfiStruct(Identifier),
    FinishFunc(Identifier, Items),
    Func(Identifier, Items),
    GlobalVar(Identifier, Items),
    LocalVar(Identifier, Items),
    Struct(Identifier),
}

macro_rules! scope {
    (@global [$($item:expr,)*]) => { vec![$($item,)*] };
    (@global [$($item:expr),*]) => { vec![$($item),*] };

    // An action in the global scope.
    (@global [$($item:expr,)*] action($ident:ident): {
        $($block:tt)*
    } $($rest:tt)*) => {
        scope!(@global
            [$($item,)* Item::Action(
                ident!(stringify!($ident)),
                scope!(@block [] $($block)*),
            ),]
            $($rest)*
        )
    };

    // A command in the global scope.
    (@global [$($item:expr,)*] cmd($ident:ident) $($rest:tt)*) => {
        scope!(@global
            [$($item,)* Item::Cmd(ident!(stringify!($ident))),]
            $($rest)*
        )
    };

    // An effect in the global scope.
    (@global [$($item:expr,)*] effect($ident:ident) $($rest:tt)*) => {
        scope!(@global
            [$($item,)* Item::Effect(ident!(stringify!($ident))),]
            $($rest)*
        )
    };

    // An enum in the global scope.
    (@global [$($item:expr,)*] enum($ident:ident) $($rest:tt)*) => {
        scope!(@global
            [$($item,)* Item::Enum(ident!(stringify!($ident))),]
            $($rest)*
        )
    };

    // A fact in the global scope.
    (@global [$($item:expr,)*] fact($ident:ident) $($rest:tt)*) => {
        scope!(@global
            [$($item,)* Item::Fact(ident!(stringify!($ident))),]
            $($rest)*
        )
    };

    // A function in the global scope.
    (@global [$($item:expr,)*] function($ident:ident): {
        $($block:tt)+
    } $($rest:tt)*) => {
        scope!(@global
            [$($item,)* Item::Func(
                ident!(stringify!($ident)),
                scope!(@block [] $($block)+),
            ),]
            $($rest)*
        )
    };

    // A finish function in the global scope.
    (@global [$($item:expr,)*] finish function($ident:ident): {
        $($block:tt)*
    } $($rest:tt)*) => {
        scope!(@global
            [$($item,)* Item::Func(
                ident!(stringify!($ident)),
                scope!(@block [] $($block)*),
            ),]
            $($rest)*
        )
    };

    // A global variable in the global scope.
    (@global [$($item:expr,)*] global($ident:ident) : {
        $($block:tt)*
    } $($rest:tt)*) => {
        scope!(@global
            [$($item,)* Item::GlobalVar(
                ident!(stringify!($ident)),
                scope!(@block [] $($block)*),
            ),]
            $($rest)*
        )
    };

    // A struct in the global scope.
    (@global [$($item:expr,)*] struct($ident:ident) $($rest:tt)*) => {
        scope!(@global
            [$($item,)* Item::Struct(ident!(stringify!($ident))),]
            $($rest)*
        )
    };

    // Comma after the most recent item.
    (@global [$($item:expr),*] , $($rest:tt)*) => {
        scope!(@global [$($item,)*] $($rest)*)
    };

    // Finished the block with a trailing comma.
    (@block [$($item:expr,)*]) => { vec![$($item,)*] };

    // Finished the block without a trailing comma.
    (@block [$($item:expr),*]) => { vec![$($item),*] };

    // Next item in the block is a local var with a block.
    (@block [$($item:expr,)*] $ident:ident : { $($block:tt)* } $($rest:tt)*) => {
        scope!(@block
            [$($item,)* Item::LocalVar(
                ident!(stringify!($ident)),
                scope!(@block [] $($block)*),
            ),]
            $($rest)*
        )
    };

    // Next item in the block is a local var with a trailing
    // comma.
    (@block [$($item:expr,)*] $ident:ident, $($rest:tt)*) => {
        scope!(@block
            [$($item,)* Item::LocalVar(
                ident!(stringify!($ident)),
                vec![],
            ),]
            $($rest)*
        )
    };

    // Last item in the block is a local var without a trailing
    // comma.
    (@block [$($item:expr,)*] $ident:ident) => {
        scope!(@block
            [$($item,)* Item::LocalVar(
                ident!(stringify!($ident)),
                vec![],
            ),]
        )
    };

    // Next item in the block is a block.
    (@block [$($item:expr,)*] { $($block:tt)* } $($rest:tt)*) => {
        scope!(@block
            [$($item,)* Item::Block(scope!(@block [] $($block)*)),]
            $($rest)*
        )
    };

    // Comma after the most recent item.
    (@block [$($item:expr,)*] , $($rest:tt)*) => {
        scope!(@block [$($item,)*] $($rest)*)
    };

    // Entry point.
    ($($tt:tt)+) => {{ scope!(@global [] $($tt)+) }};
}

#[test]
fn test_basic() {
    let text = r#"
action act1() {}
action act2(x int) {}
action act3(x int, y int) {
    let z = x + y
}

function func1(x int, y struct S1) bool {
    let z = {
        let a = y.field
        let b = a + 1
        : x + b
    }
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
    let tmp = gx + 1
    : tmp
}

struct S1 {
    field int,
}
struct S2 {
    a int,
    b bool,
}
"#;
    let ast = parse_policy_str(text, Version::V2).unwrap();
    let codemap = CodeMap::new(&ast.text, ast.ranges.clone());
    let mut ctx = Ctx::new(text, "<test>");
    ctx.lower_hir(Ast {
        ast: &ast,
        schemas: &[],
        codemap: &codemap,
    });
    ctx.resolve_symbols().unwrap();

    //trace_macros!(true);
    let mut want = scope! {
        action(act1): { }
        action(act2): { x }
        action(act3): { x, y, z }
        function(func1): {
            x, y,
            z: { a, b },
        }
        function(func2): { { { } } }
        function(func3): { { { ok } } }
        finish function(ff1): { x }
        finish function(ff2): { y }
        finish function(ff3): { y }
        finish function(ff4): { x, y }
        global(gx): {}
        global(gy): { tmp: { gx } }
        struct(S1)
        struct(S2)
    };
    //trace_macros!(false);
    want.sort();

    let mut got = ctx.get_items(ScopeId::GLOBAL);
    got.sort();

    println!("{got:#?}");

    assert_eq!(got, want);
}
