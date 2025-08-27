mod lower;
pub(crate) mod ssa;

use slotmap::SlotMap;

use crate::mir::ssa::{Func, FuncId};

// TODO: wiring from pipeline calls lower_simplified_expr directly now.

#[derive(Clone, Debug)]
pub(crate) struct Mir {
    pub funcs: SlotMap<FuncId, Func>,
}
