mod lower;
mod ssa;

use crate::hir::Hir;

pub(crate) fn lower(_hir: &Hir) -> Mir {
    todo!()
}

#[derive(Clone, Debug)]
pub(crate) struct Mir {}
