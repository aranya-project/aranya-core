//! TODO

use std::hash::Hash;

use aranya_policy_ast as ast;
use indexmap::IndexSet;
use serde::Serialize;

use crate::{
    ast::Index,
    hir::{self, Hir},
    symbol_resolution::SymbolTable,
};

#[derive(Debug)]
pub(crate) struct Ctx<'ctx> {
    pub(crate) ast: Index<'ctx>,
    pub(crate) hir: Hir,
    pub(crate) symbols: SymbolTable,
}
