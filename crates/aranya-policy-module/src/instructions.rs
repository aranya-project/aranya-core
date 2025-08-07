use core::{
    fmt::{self, Display},
    num::NonZeroUsize,
};

use aranya_policy_ast::Identifier;
use serde::{Deserialize, Serialize};

mod meta;

pub use meta::*;

use crate::{Label, data::Value};

/// Reason for ending execution.
#[must_use]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ExitReason {
    /// Execution completed without errors.
    Normal,
    /// Execution is paused to return a result, which is at the top of the stack. Call `RunState::run()` again to resume.
    Yield,
    /// Execution was aborted gracefully, due an error.
    Check,
    /// Execution was aborted due to an unhandled error.
    Panic,
}

impl ExitReason {
    /// Asserts that the reason is `ExitReason::Normal`.
    #[cfg(feature = "testing")]
    pub fn success(self) {
        assert_eq!(self, Self::Normal);
    }
}

impl Display for ExitReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal => f.write_str("normal"),
            Self::Yield => f.write_str("yield"),
            Self::Check => f.write_str("check"),
            Self::Panic => f.write_str("panic"),
        }
    }
}

/// The target of a branch
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum Target {
    /// An unresolved target with a symbolic name
    Unresolved(Label),
    /// A resolved target referring to an address
    Resolved(usize),
}

impl Target {
    /// Get the resolved address or None if it has not been resolved.
    pub fn resolved(&self) -> Option<usize> {
        match self {
            Target::Resolved(i) => Some(*i),
            _ => None,
        }
    }
}

impl Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unresolved(label) => write!(f, "<{label}>"),
            Self::Resolved(addr) => write!(f, "{addr}"),
        }
    }
}

/// The machine instruction types
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum Instruction {
    // data
    /// Push a value onto the stack
    Const(Value),
    /// Define a local value by name
    Def(Identifier),
    /// Get a local value by name
    Get(Identifier),
    /// Duplicate the value at the top of the stack
    Dup,
    /// Remove a value from the top of the stack
    Pop,
    // control flow
    /// Define the beginning of a block
    Block,
    /// Define the end of a block
    End,
    /// Jump forward to the target in the current block
    Jump(Target),
    /// Jump if top of stack is true
    Branch(Target),
    /// Jump to the beginning of the block
    Next,
    /// Jump to the end of the block
    Last,
    /// Call regular function at target
    Call(Target),
    /// Call external function (FFI), specified by module, procedure indices. The FFI modules should be added to the MachineIO.
    ExtCall(usize, usize),
    /// Return to the last address on the control flow stack
    Return,
    /// End execution non-fatally
    Exit(ExitReason),
    // arithmetic/logic
    /// Add two numbers
    Add,
    /// Subtract two numbers
    Sub,
    /// Logical negation
    Not,
    /// Greater than
    Gt,
    /// Less than
    Lt,
    /// Equality
    Eq,
    // facts
    /// Create a fact object by name
    FactNew(Identifier),
    /// Set a key member
    FactKeySet(Identifier),
    /// Set a value member
    FactValueSet(Identifier),
    // structs
    /// Create a struct object by name
    StructNew(Identifier),
    /// Add a member to the struct
    StructSet(Identifier),
    /// Get a member from the struct
    StructGet(Identifier),
    /// Add multiple members to the struct
    MStructSet(NonZeroUsize),
    /// Get multiple members from the struct
    MStructGet(NonZeroUsize),
    // context-specific
    /// Publish a struct as a command
    Publish,
    /// Create a fact
    Create,
    /// Delete a fact
    Delete,
    /// Update a fact
    Update,
    /// Emit an effect
    Emit,
    /// Query for a fact
    Query,
    /// Count facts, up to a given limit
    FactCount(i64),
    /// Execute a fact query, and retain results so they can be consumed with `QueryNext`.
    QueryStart,
    /// Fetches the next result, and pushes it onto the stack
    QueryNext(Identifier),
    /// Serialize a command struct
    Serialize,
    /// Deserialize a command struct
    Deserialize,
    /// Metadata for tracing
    Meta(Meta),
}

impl Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Instruction::Const(v) => write!(f, "const {v}"),
            Instruction::Def(ident) => write!(f, "def {ident}"),
            Instruction::Get(ident) => write!(f, "get {ident}"),
            Instruction::Dup => write!(f, "dup"),
            Instruction::Pop => write!(f, "pop"),
            Instruction::Block => write!(f, "block"),
            Instruction::End => write!(f, "end"),
            Instruction::Jump(t) => write!(f, "jump {t}"),
            Instruction::Branch(t) => write!(f, "branch {t}"),
            Instruction::Next => write!(f, "next"),
            Instruction::Last => write!(f, "last"),
            Instruction::Call(t) => write!(f, "call {t}"),
            Instruction::ExtCall(module, proc) => write!(f, "extcall {module} {proc}"),
            Instruction::Return => write!(f, "return"),
            Instruction::Exit(reason) => write!(f, "exit {reason}"),
            Instruction::Add => write!(f, "add"),
            Instruction::Sub => write!(f, "sub"),
            Instruction::Not => write!(f, "not"),
            Instruction::Gt => write!(f, "gt"),
            Instruction::Lt => write!(f, "lt"),
            Instruction::Eq => write!(f, "eq"),
            Instruction::FactNew(ident) => write!(f, "fact.new {ident}"),
            Instruction::FactKeySet(ident) => write!(f, "fact.kset {ident}"),
            Instruction::FactValueSet(ident) => write!(f, "fact.vset {ident}"),
            Instruction::StructNew(ident) => write!(f, "struct.new {ident}"),
            Instruction::StructSet(ident) => write!(f, "struct.set {ident}"),
            Instruction::StructGet(ident) => write!(f, "struct.get {ident}"),
            Instruction::MStructGet(n) => write!(f, "mstruct.get {n}"),
            Instruction::MStructSet(n) => write!(f, "mstruct.set {n}"),
            Instruction::Publish => write!(f, "publish"),
            Instruction::Create => write!(f, "create"),
            Instruction::Delete => write!(f, "delete"),
            Instruction::Update => write!(f, "update"),
            Instruction::Emit => write!(f, "emit"),
            Instruction::Query => write!(f, "query"),
            Instruction::FactCount(limit) => write!(f, "fact.count {limit}"),
            Instruction::QueryStart => write!(f, "query.start"),
            Instruction::QueryNext(ident) => write!(f, "query.next {ident}"),
            Instruction::Serialize => write!(f, "serialize"),
            Instruction::Deserialize => write!(f, "deserialize"),
            Instruction::Meta(m) => write!(f, "meta: {m}"),
        }
    }
}
