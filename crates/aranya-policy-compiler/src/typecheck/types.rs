use std::hash::Hash;

use serde::{Deserialize, Serialize};

use crate::{arena::new_key_type, symbol_resolution::SymbolId};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct Type {
    pub id: TypeId,
    pub kind: TypeKind,
}

new_key_type! {
    pub(crate) struct TypeId;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) enum TypeKind {
    String,
    Bytes,
    Int,
    Bool,
    Id,
    Struct(SymbolId),
    Enum(SymbolId),
    Optional(TypeId),
}
