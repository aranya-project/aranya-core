//! TODO

use std::hash::Hash;

use aranya_policy_ast as ast;
use indexmap::IndexSet;

use crate::{
    ast::Index,
    hir::{self, Hir},
    symbol_resolution::SymbolTable,
};

#[derive(Debug)]
pub(crate) struct Ctx<'ctx> {
    pub(crate) ast: Index<'ctx>,
    pub(crate) hir: Hir<'ctx>,
    pub(crate) hir_arena: hir::Arena<'ctx>,
    pub(crate) symbols: SymbolTable,
    pub(crate) idents: Idents,
}

#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
pub(crate) struct InternedIdent(u32);

pub(crate) struct Idents {
    idents: IndexSet<ast::Identifier>,
}

impl Idents {
    pub fn intern(&mut self, ident: &ast::Identifier) -> InternedIdent {
        if let Some(idx) = self.idents.get_index_of(ident) {
            return InternedIdent(idx as u32);
        }
        let (idx, _) = self.idents.insert_full(ident.clone());
        InternedIdent(idx as u32)
    }

    pub fn get(&self, ident: InternedIdent) -> Option<&ast::Identifier> {
        self.idents.get_index(ident.0 as usize)
    }
}
