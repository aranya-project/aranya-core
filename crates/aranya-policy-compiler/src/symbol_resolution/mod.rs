//! The symbol resolution compiler pass.
//!
//! # Symbols
//!
//! A *symbol* represents something that can be referred to with
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
//! The algorithm has two phases: collection and resolution.
//!
//! ## Collection
//!
//! The collection phase collects the top-level items (actions,
//! functions, etc.) in the HIR.
//!
//! ## Resolution
//!
//! Add each item collected in the collection phase to the global
//! scope, then push the global scope on to a stack.
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
mod tests;

use std::collections::BTreeMap;

use tracing::instrument;

#[cfg(test)]
use self::resolver::ScopeMap;
pub(crate) use self::{
    error::SymbolResolutionError,
    scope::{InvalidScopeId, ScopeId, Scopes},
    symbols::{SymbolId, Symbols},
};
use self::{
    resolver::{intern_reserved_idents, Resolver},
    scope::InsertError,
    symbols::{Symbol, SymbolKind},
};
use crate::{
    ctx::Ctx,
    diag::ErrorGuaranteed,
    hir::{Ident, IdentId, Span},
};

pub(crate) type Result<T, E = SymbolResolutionError> = std::result::Result<T, E>;

impl Ctx<'_> {
    /// Resolves symbols in the HIR.
    #[instrument(skip(self))]
    pub fn resolve_symbols(&mut self) -> Result<(), ErrorGuaranteed> {
        intern_reserved_idents(&mut self.idents);

        let res = Resolver {
            dcx: &self.dcx,
            hir: &self.hir,
            table: SymbolTable::empty(),
            reserved_idents: Vec::new(),
            idents: &self.idents,
        };
        self.symbols = res.resolve()?;
        Ok(())
    }
}

/// Symbol resolution information.
#[derive(Clone, Debug)]
pub(crate) struct SymbolTable {
    /// Maps identifiers to their symbols.
    pub resolutions: BTreeMap<IdentId, SymbolId>,
    /// The scope hierarchy.
    pub scopes: Scopes,
    /// The symbol arena.
    pub symbols: Symbols,
    /// TODO
    #[cfg(test)]
    pub scopemap: ScopeMap,
}

impl SymbolTable {
    pub fn empty() -> Self {
        Self {
            resolutions: BTreeMap::new(),
            scopes: Scopes::new(),
            symbols: Symbols::new(),
            #[cfg(test)]
            scopemap: ScopeMap::new(),
        }
    }

    /// Sugar for creating a child scope of `scope`.
    fn create_child_scope(&mut self, scope: ScopeId) -> Result<ScopeId, InvalidScopeId> {
        self.scopes.create_child_scope(scope)
    }

    /// Adds a symbol created from `ident`, `kind`, and `span` to
    /// `scope`.
    fn add_symbol(
        &mut self,
        scope: ScopeId,
        ident: &Ident,
        kind: SymbolKind,
        span: Option<Span>,
    ) -> Result<(), InsertError> {
        let sym = Symbol {
            ident: ident.id,
            kind,
            scope,
            span,
        };
        let sym_id = self.symbols.insert(sym);
        self.resolutions.insert(ident.id, sym_id);
        self.scopes.try_insert(scope, ident.xref, sym_id)
    }
}
