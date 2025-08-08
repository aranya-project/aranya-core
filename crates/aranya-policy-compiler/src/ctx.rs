use std::marker::PhantomData;

use crate::{
    diag::DiagCtx,
    hir::{Hir, IdentInterner, TextInterner},
    symbol_resolution::SymbolTable,
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
            _marker: PhantomData,
        }
    }
}
