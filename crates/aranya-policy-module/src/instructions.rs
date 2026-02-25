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
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
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
            Self::Resolved(i) => Some(*i),
            Self::Unresolved(_) => None,
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

/// Type of `Value` wrapping
#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub enum WrapType {
    /// Wrap in Result::Ok
    Ok,
    /// Wrap in Result::Err
    Err,
    /// Wrap in Option::Some
    Some,
}

impl Display for WrapType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => f.write_str("ok"),
            Self::Err => f.write_str("err"),
            Self::Some => f.write_str("some"),
        }
    }
}

/// The machine instruction types
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
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
    /// Add two numbers with saturation
    SaturatingAdd,
    /// Subtract two numbers with saturation
    SaturatingSub,
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
    /// Cast previous stack value to given type
    Cast(Identifier),
    /// Wrap the value on top of the stack in Some, Ok, or Err, depending on wrap type.
    Wrap(WrapType),
    /// Check if the value on top of the stack is the given wrap type (pushes bool).
    Is(WrapType),
    /// Unwrap the inner value from a Result (Ok or Err). Will eventually support Optional (Some) as well.
    Unwrap(WrapType),
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
    /// Save the stack depth for later restoration.
    SaveSP,
    /// Restore the stack depth.
    RestoreSP,
    /// Metadata for tracing
    Meta(Meta),
}

impl Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const(v) => write!(f, "const {v}"),
            Self::Def(ident) => write!(f, "def {ident}"),
            Self::Get(ident) => write!(f, "get {ident}"),
            Self::Dup => write!(f, "dup"),
            Self::Pop => write!(f, "pop"),
            Self::Block => write!(f, "block"),
            Self::End => write!(f, "end"),
            Self::Jump(t) => write!(f, "jump {t}"),
            Self::Branch(t) => write!(f, "branch {t}"),
            Self::Next => write!(f, "next"),
            Self::Last => write!(f, "last"),
            Self::Call(t) => write!(f, "call {t}"),
            Self::ExtCall(module, proc) => write!(f, "extcall {module} {proc}"),
            Self::Return => write!(f, "return"),
            Self::Exit(reason) => write!(f, "exit {reason}"),
            Self::Add => write!(f, "add"),
            Self::Sub => write!(f, "sub"),
            Self::SaturatingAdd => write!(f, "saturating_add"),
            Self::SaturatingSub => write!(f, "saturating_sub"),
            Self::Not => write!(f, "not"),
            Self::Gt => write!(f, "gt"),
            Self::Lt => write!(f, "lt"),
            Self::Eq => write!(f, "eq"),
            Self::FactNew(ident) => write!(f, "fact.new {ident}"),
            Self::FactKeySet(ident) => write!(f, "fact.kset {ident}"),
            Self::FactValueSet(ident) => write!(f, "fact.vset {ident}"),
            Self::StructNew(ident) => write!(f, "struct.new {ident}"),
            Self::StructSet(ident) => write!(f, "struct.set {ident}"),
            Self::StructGet(ident) => write!(f, "struct.get {ident}"),
            Self::MStructGet(n) => write!(f, "mstruct.get {n}"),
            Self::MStructSet(n) => write!(f, "mstruct.set {n}"),
            Self::Cast(ident) => write!(f, "cast {ident}"),
            Self::Wrap(wrap_type) => write!(f, "wrap {wrap_type}"),
            Self::Is(wrap_type) => write!(f, "is {wrap_type}"),
            Self::Unwrap(wrap_type) => write!(f, "unwrap {wrap_type}"),
            Self::Publish => write!(f, "publish"),
            Self::Create => write!(f, "create"),
            Self::Delete => write!(f, "delete"),
            Self::Update => write!(f, "update"),
            Self::Emit => write!(f, "emit"),
            Self::Query => write!(f, "query"),
            Self::FactCount(limit) => write!(f, "fact.count {limit}"),
            Self::QueryStart => write!(f, "query.start"),
            Self::QueryNext(ident) => write!(f, "query.next {ident}"),
            Self::Serialize => write!(f, "serialize"),
            Self::Deserialize => write!(f, "deserialize"),
            Self::SaveSP => write!(f, "save SP"),
            Self::RestoreSP => write!(f, "restore SP"),
            Self::Meta(m) => write!(f, "meta: {m}"),
        }
    }
}
