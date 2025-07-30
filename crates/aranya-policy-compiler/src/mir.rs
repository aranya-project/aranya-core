mod lower;
pub(crate) mod ssa;

use slotmap::SlotMap;

use crate::{
    hir::NormalizedHir,
    mir::{
        lower::LowerCtx,
        ssa::{Func, FuncId},
    },
};

pub(crate) fn lower(hir: &NormalizedHir) -> Mir {
    let LowerCtx { funcs, .. } = LowerCtx::build(hir);

    Mir { funcs }
}

#[derive(Clone, Debug)]
pub(crate) struct Mir {
    pub funcs: SlotMap<FuncId, Func>,
}
