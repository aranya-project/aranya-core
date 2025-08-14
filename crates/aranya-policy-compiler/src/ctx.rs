use std::marker::PhantomData;

use crate::{
    depgraph::DepGraph,
    diag::DiagCtx,
    hir::{Hir, IdentInterner, TextInterner},
    symbol_resolution::{SymbolId, SymbolTable},
};

/// Compiler context.
#[derive(Debug)]
pub(crate) struct Ctx<'ctx> {
    pub dcx: DiagCtx,
    pub hir: Hir,
    pub text: TextInterner,
    pub idents: IdentInterner,
    // TODO(eric): rename this to `symtab` or similar.
    pub symbols: SymbolTable,
    pub deps: DepGraph,
    pub _marker: PhantomData<&'ctx ()>,
}

impl Ctx<'_> {
    /// Creates a
    pub fn new(src: &str, path: &str) -> Self {
        Self {
            dcx: DiagCtx::new(src, path),
            hir: Hir::default(),
            text: TextInterner::new(),
            idents: IdentInterner::new(),
            symbols: SymbolTable::empty(),
            deps: DepGraph::new(),
            _marker: PhantomData,
        }
    }
}
