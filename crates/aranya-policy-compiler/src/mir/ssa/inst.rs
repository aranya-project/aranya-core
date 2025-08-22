use std::{fmt, hash::Hash};

use aranya_policy_ast::Text;
use serde::{Deserialize, Serialize};
use slotmap::SlotMap;

use super::block::BlockId;
use crate::{
    hir::{CmdFieldId, CmdId, EffectFieldId, EffectId, FactId, IdentId, StructFieldId},
    symtab::SymbolId,
};

/// Declares an SSA instruction.
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

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub(crate) struct ValueId(pub usize);

impl ValueId {
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl fmt::Display for ValueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// A basic block instruction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct Inst {
    pub dst: ValueId,
    pub kind: InstKind,
}

macro_rules! enum_decl {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident($inner:ty)
            ),+ $(,)?
        }
    )=>{
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant($inner)
            ),+
        }
        $(impl From<$inner> for $name {
            fn from(inner: $inner) -> Self {
                $name::$variant(inner)
            }
        })+
    };
}

enum_decl! {
    pub(crate) enum InstKind {
        /// TODO
        Phi(Phi),
        Def(Def),
        /// Loads a constant value.
        Const(Const),
        /// A binary operation.
        BinOp(BinOp),
        /// A unary operation.
        UnaryOp(UnaryOp),
        FieldAccess(FieldAccess),
        Load(Load),
        Call(Call),
        /// Query for a fact.
        Query(Query),
        /// Create a fact.
        Create(Create),
        /// Update a fact.
        Update(Update),
        /// Delete a fact.
        Delete(Delete),
        /// Emit an effect.
        Emit(Emit),
        /// Publish a command.
        Publish(Publish),
        /// Count facts.
        FactCount(FactCount),
        /// Start a map iteration.
        MapStart(MapStart),
        /// Get next item in map iteration.
        MapNext(MapNext),
        /// Serialize a value.
        Serialize(SerializeValue),
        /// Deserialize a value.
        Deserialize(DeserializeValue),
    }
}

inst! {
    pub(crate) struct Def {
        pub arg: ValueId,
    }
}

inst! {
    /// Loads a constant value.
    pub(crate) struct Const {
        pub val: ConstValue,
    }
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
    /// This is not part of the policy language. It exists so
    /// that statements like
    ///
    /// ```policy
    /// if x {
    ///     foo()
    /// } else {
    ///     bar()
    /// }
    /// ```
    ///
    /// generate a [`ValueId`].
    Unit,
}

/// A binary operation.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) enum BinOp {
    Add(ValueId, ValueId),
    Sub(ValueId, ValueId),
    And(ValueId, ValueId),
    Or(ValueId, ValueId),
    Gt(ValueId, ValueId),
    Lt(ValueId, ValueId),
    Eq(ValueId, ValueId),
    GtEq(ValueId, ValueId),
    LtEq(ValueId, ValueId),
}

/// A unary operation.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) enum UnaryOp {
    Not(ValueId),
    Neg(ValueId),
}

inst! {
    pub(crate) struct Phi {
        pub incoming: Vec<(BlockId, ValueId)>,
    }
}

inst! {
    pub(crate) struct Call {
        pub func: ValueId,
        pub args: Vec<ValueId>,
    }
}

inst! {
    pub(crate) struct Load {
        pub name: SymbolId,
    }
}

inst! {
    pub(crate) struct FieldAccess {
        pub base: ValueId,
        pub field: FieldId,
    }
}

/// Unified field ID for different field types
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum FieldId {
    Effect(EffectFieldId),
    Struct(StructFieldId),
    Command(CmdFieldId),
}

inst! {
    pub(crate) struct Query {
        pub fact_id: FactId,
        pub key_filters: Vec<(IdentId, ValueId)>,
        pub val_filters: Vec<(IdentId, ValueId)>,
    }
}

inst! {
    pub(crate) struct Create {
        pub fact_id: FactId,
        pub keys: Vec<(IdentId, ValueId)>,
        pub values: Vec<(IdentId, ValueId)>,
    }
}

inst! {
    pub(crate) struct Update {
        pub fact_id: FactId,
        pub keys: Vec<(IdentId, ValueId)>,
        pub old_values: Vec<(IdentId, ValueId)>,
        pub new_values: Vec<(IdentId, ValueId)>,
    }
}

inst! {
    pub(crate) struct Delete {
        pub fact_id: FactId,
        pub key_filters: Vec<(IdentId, ValueId)>,
        pub val_filters: Vec<(IdentId, ValueId)>,
    }
}

inst! {
    pub(crate) struct Emit {
        pub effect_id: EffectId,
        pub fields: Vec<(FieldId, ValueId)>,
    }
}

inst! {
    pub(crate) struct Publish {
        pub cmd_id: CmdId,
        pub fields: Vec<(FieldId, ValueId)>,
    }
}

inst! {
    pub(crate) struct FactCount {
        pub fact_id: FactId,
        pub key_filters: Vec<(IdentId, ValueId)>,
        pub count_type: FactCountType,
        pub limit: i64,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum FactCountType {
    UpTo,
    AtLeast,
    AtMost,
    Exactly,
}

inst! {
    pub(crate) struct MapStart {
        pub fact_id: FactId,
        pub key_filters: Vec<(IdentId, ValueId)>,
        pub val_filters: Vec<(IdentId, ValueId)>,
    }
}

inst! {
    pub(crate) struct MapNext {
        pub map_id: ValueId,
    }
}

inst! {
    pub(crate) struct SerializeValue {
        pub src: ValueId,
    }
}

inst! {
    pub(crate) struct DeserializeValue {
        pub src: ValueId,
    }
}
