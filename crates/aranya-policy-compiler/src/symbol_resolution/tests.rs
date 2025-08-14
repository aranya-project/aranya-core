#![cfg(test)]

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ops::Index,
};

use aranya_policy_ast::{ident, Identifier, Version};
use aranya_policy_lang::lang::parse_policy_str;
use aranya_policy_module::CodeMap;
use pretty_assertions::assert_eq;
use serde::{Deserialize, Serialize};
use test_log::test;

use super::{
    scope::{Scope, ScopeId, ScopedId, Scopes},
    symbols::{SymbolId, SymbolKind},
};
use crate::{
    ast::Ast,
    ctx::Ctx,
    hir::{ExprKind, IdentRef},
};

struct ScopeTree {
    global: Vec<Node>,
}

struct Node {
    scope: ScopeId,
}

/// Maps parent scopes to their child scopes.
type InEdges = BTreeMap<ScopeId, BTreeSet<ScopeId>>;

/// Maps child scopes to their parent scopes.
type OutEdges = BTreeMap<ScopeId, ScopeId>;

struct Graph {
    incoming: InEdges,
    outgoing: OutEdges,
    sorted: Vec<ScopeId>,
}

impl Graph {
    fn topo_sort(&self) -> Result<Vec<ScopeId>, HasCycles> {
        let mut sorted = Vec::new();
        let (mut q, mut incoming): (VecDeque<_>, InEdges) = self.incoming.iter().fold(
            (VecDeque::new(), InEdges::new()),
            |(mut q, mut edges), (id, incoming)| {
                if incoming.is_empty() {
                    q.push_back(*id);
                } else {
                    edges.insert(*id, incoming.clone());
                }
                (q, edges)
            },
        );
        let mut outgoing = self.outgoing.clone();
        while let Some(n) = q.pop_front() {
            sorted.push(n);
            let Some(m) = outgoing.remove(&n) else {
                continue;
            };
            let out = incoming.get_mut(&m).unwrap();
            out.remove(&n);
            if out.is_empty() {
                incoming.remove(&m);
                q.push_back(m);
            }
        }

        // TODO(eric): Reverse the edge direction instead.
        sorted.reverse();
        assert_eq!(sorted[0], ScopeId::GLOBAL);

        if incoming.is_empty() {
            Ok(sorted)
        } else {
            Err(HasCycles)
        }
    }

    fn collect_items(&self, ctx: &Ctx<'_>) -> Vec<Item> {
        self.dfs(ctx, ScopeId::GLOBAL, &|ctx, id| {
            let scope = ctx.symbols.scopes.get_scope(id);
            if let Some(children) = self.incoming.get(&id) {
                assert!(
                    children.len() <= scope.symbols.len(),
                    "{} < {}",
                    children.len(),
                    scope.symbols.len()
                );
            }
            // TODO
        });
        todo!()
    }

    fn walk<R>(&self, ctx: &Ctx<'_>, f: &impl FnMut(&Ctx<'_>, ScopeId) -> R) {
        self.dfs(ctx, ScopeId::GLOBAL, f)
    }

    fn dfs<R>(&self, ctx: &Ctx<'_>, id: ScopeId, f: &impl FnMut(&Ctx<'_>, ScopeId) -> R) {
        if let Some(children) = self.incoming.get(&id) {
            for &child in children {
                acc = self.dfs(child, edges, acc, f);
            }
        }
        f(self, parent, acc)
    }
}

#[derive(Copy, Clone, Debug)]
struct HasCycles;

impl Scopes {
    fn get_scope(&self, id: ScopeId) -> &Scope {
        &self.scopes[id]
    }
}

impl Ctx<'_> {
    fn build_scope_graph(&self) -> Result<Graph, HasCycles> {
        let mut incoming = InEdges::new();
        let mut outgoing = OutEdges::new();
        for (id, scope) in &self.symbols.scopes.scopes {
            if let Some(parent) = &scope.parent {
                outgoing.insert(id, *parent);
                incoming
                    .entry(*parent)
                    .and_modify(|v| {
                        v.insert(id);
                    })
                    .or_default();
            } else {
                // The global scope is the only scope without
                // a parent.
                assert_eq!(id, ScopeId::GLOBAL);
            }
        }
        let mut graph = Graph {
            incoming,
            outgoing,
            sorted: Vec::new(),
        };
        graph.sorted = graph.topo_sort()?;
        Ok(graph)
    }

    fn build_in_edges(&self) -> InEdges {
        self.build_scope_graph().unwrap().incoming
    }

    fn build_out_edges(&self) -> OutEdges {
        self.build_scope_graph().unwrap().outgoing
    }

    fn collect_all_items<R>(&self) -> Vec<Item> {
        let edges = self.build_out_edges();
        self.dfs(ScopeId::GLOBAL, &edges, Vec::new(), &|ctx, id, scopes| {})
    }

    fn dfs<R>(
        &self,
        parent: ScopeId,
        edges: &OutEdges,
        mut acc: R,
        f: &impl Fn(&Self, ScopeId, R) -> R,
    ) -> R {
        if let Some(children) = edges.get(&parent) {
            let scope = self.symbols.scopes.get_scope(parent);
            assert!(
                children.len() <= scope.symbols.len(),
                "{} < {}",
                children.len(),
                scope.symbols.len()
            );
            for &child in children {
                acc = self.dfs(child, edges, acc, f);
            }
        }
        f(self, parent, acc)
    }

    fn idk(&self, id: SymbolId, xref: IdentRef) {
        let ident = self.idents.get(xref).unwrap().clone();
        let sym = self.symbols.symbols.get(id).unwrap();
        let item = match sym.kind {
            SymbolKind::Action(_) => Item::Action(ident, children),
            SymbolKind::Cmd(_) => Item::Cmd(ident),
            SymbolKind::Effect(_) => Item::Effect(ident),
            SymbolKind::Enum(_) => Item::Enum(ident),
            SymbolKind::Fact(_) => Item::Fact(ident),
            SymbolKind::FfiEnum(_) => Item::FfiEnum(ident),
            SymbolKind::FfiFunc(_) => Item::FfiFunc(ident),
            SymbolKind::FfiModule { .. } => Item::FfiModule(ident),
            SymbolKind::FfiStruct(_) => Item::FfiStruct(ident),
            SymbolKind::FinishFunc(_) => Item::FinishFunc(ident, children),
            SymbolKind::Func(_) => Item::Func(ident, children),
            SymbolKind::GlobalVar(_) => Item::GlobalVar(ident, children),
            SymbolKind::LocalVar(_) => Item::LocalVar(ident, children),
            SymbolKind::Struct(_) => Item::Struct(ident),
        };
    }

    fn collect_items(&self, id: ScopeId, mut acc: Vec<Items>) -> Vec<Item> {
        let mut items = Items::new();
        let scope = self.symbols.scopes.get_scope(id);
        for (xref, sym_id) in &scope.symbols {
            let ident = self.idents.get(*xref).unwrap().clone();
            let sym = self.symbols.symbols.get(*sym_id).unwrap();
            let item = match sym.kind {
                SymbolKind::Action(_) => Item::Action(ident, children),
                SymbolKind::Cmd(_) => Item::Cmd(ident),
                SymbolKind::Effect(_) => Item::Effect(ident),
                SymbolKind::Enum(_) => Item::Enum(ident),
                SymbolKind::Fact(_) => Item::Fact(ident),
                SymbolKind::FfiEnum(_) => Item::FfiEnum(ident),
                SymbolKind::FfiFunc(_) => Item::FfiFunc(ident),
                SymbolKind::FfiModule { .. } => Item::FfiModule(ident),
                SymbolKind::FfiStruct(_) => Item::FfiStruct(ident),
                SymbolKind::FinishFunc(_) => Item::FinishFunc(ident, children),
                SymbolKind::Func(_) => Item::Func(ident, children),
                SymbolKind::GlobalVar(_) => Item::GlobalVar(ident, children),
                SymbolKind::LocalVar(_) => Item::LocalVar(ident, children),
                SymbolKind::Struct(_) => Item::Struct(ident),
            };
            items.push(item);
        }
        items
    }

    /// Recursively retrieves all items in the scope.
    fn get_all_items(&self) -> Items {
        self.get_items(ScopeId::GLOBAL)
    }

    fn get_items(&self, id: ScopeId) -> Items {
        println!("get_items({id})");
        let mut items = Items::new();
        let scope = self.symbols.scopes.get_scope(id);
        for (xref, sym_id) in &scope.symbols {
            let ident = self.idents.get(*xref).unwrap().clone();
            let sym = self.symbols.symbols.get(*sym_id).unwrap();
            let item = match sym.kind {
                SymbolKind::Action(id) => {
                    let act = self.hir.index(id);
                    Item::Action(ident, self.get_scoped_items(act.body))
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
                    Item::FinishFunc(ident, self.get_scoped_items(func.body))
                }
                SymbolKind::Func(id) => {
                    let func = self.hir.index(id);
                    Item::Func(ident, self.get_scoped_items(func.body))
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
                    println!("LocalVar: {id:?}");
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
            .unwrap_or_else(|| panic!("unknown `ScopedId`: {id:?}"));
        self.get_items(*scope)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
struct TestScope {
    kind: ScopeKind,
    symbols: Vec<SymKind>,
    children: Vec<TestScope>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
enum SymKind {
    Action,
    Cmd,
    Effect,
    Enum,
    Fact,
    FfiEnum,
    FfiFunc,
    FfiModule,
    FfiStruct,
    FinishFunc,
    Func,
    GlobalVar,
    LocalVar,
    Struct,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
enum ScopeKind {
    Action(Identifier),
    Block,
    FfiFunc(Identifier),
    FinishFunc(Identifier),
    Func(Identifier),
    GlobalVar(Identifier),
    LocalVar(Identifier),
    Param(Identifier),
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
            [$($item,)* Item::FinishFunc(
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
        finish function(ff3): { }
        finish function(ff4): { x, y }
        global(gx): {}
        global(gy): { tmp: { gx } }
        struct(S1)
        struct(S2)
    };
    //trace_macros!(false);
    want.sort();

    let mut got = ctx.walk_scopes(Items::new(), Ctx::collect_items);
    got.sort();

    println!("{got:#?}");
    println!("{want:#?}");

    assert_eq!(got, want);
}
