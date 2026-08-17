//! Data for the version 1 policy module format
extern crate alloc;

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

use aranya_policy_ast::Identifier;
use serde::{Deserialize, Serialize};

use crate::{
    ActionDef, CHECKSUM_HASH_LEN, CodeMap, CommandDef, ConstValue, EnumDef, FactDef, FfiContract,
    Instruction, Label, StructDef,
};

/// Program data - instructions and other information needed for runtime execution.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct Program {
    /// Program memory
    pub progmem: Box<[Instruction]>,
    /// Labels
    pub labels: BTreeMap<Label, usize>,
    /// Global static data
    pub globals: BTreeMap<Identifier, ConstValue>,
    /// Code map
    pub codemap: Option<CodeMap>,
}

/// Contract data - code signature and definitions for code structures.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct Contract {
    /// A SHA-256 hash over the normalized AST
    pub signature: [u8; CHECKSUM_HASH_LEN],
    /// Action definitions
    pub actions: Vec<ActionDef>,
    /// Command definitions
    pub commands: Vec<CommandDef>,
    /// Fact definitions
    pub facts: Vec<FactDef>,
    /// Struct definitions
    pub structs: Vec<StructDef>,
    /// Enum definitions
    pub enums: Vec<EnumDef>,
    /// Module contract metadata
    pub ffis: Vec<FfiContract>,
}
