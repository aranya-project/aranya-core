use std::hash::Hash;

use aranya_policy_ast::Text;
use serde::{Deserialize, Serialize};

use crate::symbol_resolution::SymbolId;

/// A basic block.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct Block {
    pub id: BlockId,
    pub instr: Vec<Inst>,
    pub term: Option<Terminator>,
}

slotmap::new_key_type! {
    pub(crate) struct BlockId;
}

/// A terminator instruction that ends a [`Block`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Terminator {
    Return(ValueId),
    Jump(BlockId),
    CondJump(CondJump),
    Panic,
}

/// A conditional jump.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct CondJump {
    pub cond: ValueId,
    pub true_block: BlockId,
    pub false_block: BlockId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct Value {
    pub id: ValueId,
    pub kind: ValueKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum ValueKind {
    Const(ConstValue),
    Value(ValueId),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum ConstValue {
    /// A constant integer.
    Int(i64),
    /// A constant boolean.
    Bool(bool),
    /// A constant string.
    Text(Text),
    /// Optional none.
    None,
    /// A constant enum.
    Enum,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct ValueId(pub(crate) usize);

impl ValueId {
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

macro_rules! inst {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $(pub $field:ident: $ty:ty),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
        $vis struct $name {
            $(pub $field: $ty),*
        }
    };
}

/// A basic block instruction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum Inst {
    Phi(Phi),
    Const(Const),
    BinOp(BinOp),
    UnaryOp(UnaryOp),
    FieldAccess,
    /// Query for a fact.
    Query,
    /// Create a fact.
    Create,
    /// Update a fact.
    Update,
    /// Delete a fact.
    Delete,
    /// Emit an effect.
    Emit,
    /// Publish a command.
    Publish,
    Serialize,
    Deserialize,
}

inst! {
    pub(crate) struct Const {
        pub dst: ValueId,
        pub val: Value,
    }
}

inst! {
    /// A binary operation.
    pub(crate) struct BinOp {
        pub dst: ValueId,
        pub kind: BinOpKind,
        pub lhs: ValueId,
        pub rhs: ValueId,
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) enum BinOpKind {
    Add,
    Sub,
    And,
    Or,
    Gt,
    Lt,
    Eq,
    GtEq,
    LtEq,
}

inst! {
    /// A unary operation.
    pub(crate) struct UnaryOp {
        pub dst: ValueId,
        pub kind: BinOpKind,
        pub src: ValueId,
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) enum UnaryOpKind {
    Not,
    Neg,
}

inst! {
    pub(crate) struct Phi {
        pub dst: ValueId,
        pub args: Vec<(BlockId, ValueId)>,
    }
}

inst! {
    pub(crate) struct Call {
        pub dst: ValueId,
        pub func: ValueId,
        pub args: Vec<ValueId>,
    }
}

inst! {
    pub(crate) struct Load {
        pub dst: ValueId,
        pub name: SymbolId,
    }
}

inst! {
    pub(crate) struct FieldAccess {
        // TODO
    }
}

inst! {
    pub(crate) struct Create {
        // TODO
    }
}

inst! {
    pub(crate) struct Update {
        // TODO
    }
}

inst! {
    pub(crate) struct Delete {
        // TODO
    }
}

inst! {
    pub(crate) struct Emit {
        // TODO
    }
}

inst! {
    pub(crate) struct Publish {
        // TODO
    }
}

inst! {
    pub(crate) struct SerializeValue {
        // TODO
    }
}

inst! {
    pub(crate) struct DeserializeValue {
        // TODO
    }
}
