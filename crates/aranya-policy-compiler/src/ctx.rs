//! TODO

use std::marker::PhantomData;

use bumpalo::Bump;

use crate::{hir::Hir, symbol_resolution::SymbolTable};

pub(crate) struct Ctx<'ctx> {
    pub(crate) alloc: Bump,
    pub(crate) hir: Hir,
    pub(crate) symbols: SymbolTable,
    pub(crate) _marker: PhantomData<&'ctx ()>,
}
