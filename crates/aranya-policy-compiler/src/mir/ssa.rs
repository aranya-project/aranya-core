//! Single Static Assignment (SSA) form.

mod block;
mod inst;

pub(crate) use self::{
    block::{Block, BlockId, Branch, Func, FuncId, Terminator},
    inst::{
        BinOp, Call, Const, ConstValue, Create, Def, Delete, DeserializeValue, Emit, FactCount,
        FactCountType, FieldAccess, FieldId, Inst, InstKind, Load, MapNext, MapStart, Phi, Publish,
        Query, SerializeValue, UnaryOp, Update, ValueId,
    },
};
