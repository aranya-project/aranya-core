use std::hash::Hash;

use serde::{Deserialize, Serialize};
use slotmap::SlotMap;

use super::inst::{Inst, ValueId};
use crate::hir::IdentId;

/// An SSA "function".
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Func {
    pub ident: IdentId,
    pub params: Vec<ValueId>,
    pub return_type: Option<()>, // TODO: TypeId
    pub entry: BlockId,
    pub blocks: SlotMap<BlockId, Block>,
    pub instr: Vec<Inst>,
}

slotmap::new_key_type! {
    pub(crate) struct FuncId;
}

/// A basic block.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct Block {
    pub id: BlockId,
    pub phi: Vec<ValueId>,
    pub instr: Vec<ValueId>,
    pub term: Option<Terminator>,

    /// Outgoing CFG edges.
    pub succ: Vec<BlockId>,
    /// Incoming CFG edges.
    pub preds: Vec<BlockId>,
}

slotmap::new_key_type! {
    pub(crate) struct BlockId;
}

/// A terminator instruction that ends a [`Block`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Terminator {
    Return(ValueId),
    Jump(BlockId),
    Branch(Branch),
    // TODO(eric): add more panic info.
    Panic,
}

/// A conditional jump.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct Branch {
    pub cond: ValueId,
    pub true_block: BlockId,
    pub false_block: BlockId,
}
