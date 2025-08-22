//! The symbol resolution compiler pass.
//!
//! # Symbols
//!
//! A *symbol* represents something that can be referenced with
//! an identifier. There are a number of different kinds of
//! symbols:
//!
//! - Actions
//! - Commands
//! - Effects
//! - Enumerations
//! - FFI enumerations, functions, modules, and structs
//! - Facts
//! - Finish functions
//! - Functions
//! - Global variables
//! - Local variables, including parameters for actions, FFI
//!   functions, finish functions, and functions.
//! - Structs
//!
//! Notably, the following are *not* symbols, even though they
//! can be referred to with an identifier:
//!
//! - FFI enumeration variants and struct fields
//! - Effect fields
//! - Enumeration variants
//! - Struct fields
//! - Fact keys and values
//!
//! These are "resolved" during the type checking compiler pass.
//!
//! # Scope
//!
//! Scope maps identifiers to symbols. Logically, you can think
//! of it as `HashMap<Identifier, Symbol>`. Every scope except
//! for the global scope has a parent scope. For example:
//!
//! ```policy
//! // global scope
//! function foo() int {
//!     // function-local scope for foo
//!     // parent is the global scope
//!     let x = {
//!         // block-local scope
//!         // parent is the function-local scope for foo
//!         : 42
//!     };
//!     // function-local scope for foo
//!     // parent is the global scope
//!     return x
//! }
//! ```
//!
//! # Algorithm
//!
//! The algorithm has two phases: mark and resolve.
//!
//! ## Mark
//!
//! The mark phase marks the global symbols (top-level HIR
//! items).
//!
//! ## Resolve
//!
//! Add each marked item to the global scope, then push the
//! global scope on to a stack.
//!
//! Perform a DFS on each of the items in the global scope. When
//! you enter a block, push a new empty scope on to the stack.
//! When you exit a block, pop the top scope off the stack.
//!
//! Resolve identifiers by iteratively checking each scope in the
//! stack, top to bottom, without modifying the stack. If none of
//! the scopes in the stack are able to resolve the identifier,
//! then the identifier is undefined.
//!
//! New symbols (e.g., local variable) are *only* defined in the
//! top scope on the stack.

mod error;
mod resolver;
mod scope;
mod symbols;
mod table;
//mod tests;

use aranya_policy_ast::ident;

use self::resolver::Resolver;
pub(crate) use self::{
    error::SymbolResolutionError,
    scope::Scopes,
    symbols::{Symbol, SymbolId, SymbolKind, Symbols},
    table::{ScopeMap, SymbolTable},
};
use crate::{
    arena::Iter,
    ctx::Ctx,
    diag::{ErrorGuaranteed, OptionExt},
    hir::{AstLowering, IdentId},
    pass::{DepsRefs, Pass, View},
};

pub(crate) type Result<T, E = SymbolResolutionError> = std::result::Result<T, E>;

#[derive(Copy, Clone, Debug)]
pub struct SymbolResolution;

impl Pass for SymbolResolution {
    const NAME: &'static str = "symbols";
    type Output = SymbolTable;
    type View<'cx> = SymbolsView<'cx>;
    type Deps = (AstLowering,);

    fn run(cx: Ctx<'_>, (hir,): DepsRefs<'_, Self>) -> Result<SymbolTable, ErrorGuaranteed> {
        let reserved_idents = [ident!("this"), ident!("envelope"), ident!("id")]
            .into_iter()
            .map(|ident| cx.intern_ident(ident))
            .collect::<Vec<_>>();
        let res = Resolver {
            ctx: cx,
            hir,
            table: SymbolTable::empty(),
            reserved_idents,
        };
        res.resolve()
    }
}

impl<'cx> Ctx<'cx> {
    pub fn symbols(self) -> Result<SymbolsView<'cx>, ErrorGuaranteed> {
        let table = self.get::<SymbolResolution>()?;
        Ok(SymbolsView::new(self, table))
    }
}

#[derive(Copy, Clone, Debug)]
pub struct SymbolsView<'cx> {
    cx: Ctx<'cx>,
    table: &'cx SymbolTable,
}

impl<'cx> SymbolsView<'cx> {
    /// Returns the symbol table.
    pub fn table(&self) -> &'cx SymbolTable {
        self.table
    }

    /// Resolve an identifier to a symbol ID.
    pub fn resolve(&self, id: IdentId) -> SymbolId {
        self.table
            .resolutions
            .get(&id)
            .copied()
            .unwrap_or_bug(self.cx.dcx(), "ident must be resolved")
    }

    /// Get a symbol by ID.
    pub fn get(&self, id: SymbolId) -> &'cx Symbol {
        self.table
            .symbols
            .get(id)
            .unwrap_or_bug(self.cx.dcx(), "symbol must exist")
    }

    /// Check if an identifier was skipped during resolution.
    pub fn is_skipped(&self, id: IdentId) -> bool {
        self.table.skipped.contains(&id)
    }

    pub fn iter(&self) -> Iter<'cx, SymbolId, Symbol> {
        self.table.symbols.iter()
    }
}

impl<'cx> View<'cx, SymbolTable> for SymbolsView<'cx> {
    fn new(cx: Ctx<'cx>, data: &'cx SymbolTable) -> Self {
        Self { cx, table: data }
    }
}

impl<'cx> IntoIterator for SymbolsView<'cx> {
    type Item = (SymbolId, &'cx Symbol);
    type IntoIter = Iter<'cx, SymbolId, Symbol>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
