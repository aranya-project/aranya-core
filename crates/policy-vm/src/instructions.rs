extern crate alloc;

use alloc::string::String;
use core::fmt::Display;

use crate::data::Value;

/// The target of a branch
#[derive(Debug, Clone)]
pub enum Target {
    /// An unresolved target with a symbolic name
    Unresolved(String),
    /// A resolved target referring to an address
    Resolved(usize),
}

/// The machine instruction types
#[derive(Debug, Clone)]
pub enum Instruction {
    // data
    /// Push a value onto the stack
    Const(Value),
    /// Define a local value by name
    Def,
    /// Get a local value by name
    Get,
    /// Swap value at depth d with the top of the stack
    Swap(usize), // TODO(chip): remove this or limit the argument to small values
    /// Duplicate the value at depth d onto the top of the stack
    Dup(usize),
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
    Exit,
    /// End execution fatally
    Panic,
    // arithmetic/logic
    /// Add two numbers
    Add,
    /// Subtract two numbers
    Sub,
    /// Logical negation
    Not,
    /// Logical and
    And,
    /// Logical or
    Or,
    /// Greater than
    Gt,
    /// Less than
    Lt,
    /// Equality
    Eq,
    // facts
    /// Create a fact object by name
    FactNew,
    /// Set a key member
    FactKeySet,
    /// Set a value member
    FactValueSet,
    // structs
    /// Create a struct object by name
    StructNew,
    /// Add a member to the struct
    StructSet,
    /// Get a member from the struct
    StructGet,
    // context-specific
    /// Emit a struct
    Emit,
    /// Create a fact
    Create,
    /// Delete a fact
    Delete,
    /// Update a fact
    Update,
    /// Produce an effect
    Effect,
    /// Query for a fact
    Query,
    /// Simple query that's true if the fact exists
    Exists,
    /// Get the id of a command
    Id,
    /// Get the id of the author of a command
    AuthorId,
}

impl Display for Instruction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Instruction::Const(v) => write!(f, "const {}", v),
            Instruction::Def => write!(f, "def"),
            Instruction::Get => write!(f, "get"),
            Instruction::Swap(d) => write!(f, "swap({})", d),
            Instruction::Dup(d) => write!(f, "dup({})", d),
            Instruction::Pop => write!(f, "pop"),
            Instruction::Block => write!(f, "block"),
            Instruction::End => write!(f, "end"),
            Instruction::Jump(Target::Resolved(t)) => write!(f, "jump {}", t),
            Instruction::Jump(Target::Unresolved(s)) => write!(f, "jump <{}>", s),
            Instruction::Branch(Target::Resolved(t)) => write!(f, "branch {}", t),
            Instruction::Branch(Target::Unresolved(s)) => write!(f, "branch <{}>", s),
            Instruction::Next => write!(f, "next"),
            Instruction::Last => write!(f, "last"),
            Instruction::Call(Target::Resolved(t)) => write!(f, "call {}", t),
            Instruction::Call(Target::Unresolved(s)) => write!(f, "call <{}>", s),
            Instruction::ExtCall(module, proc) => write!(f, "extcall {} {}", module, proc),
            Instruction::Return => write!(f, "return"),
            Instruction::Exit => write!(f, "exit"),
            Instruction::Panic => write!(f, "panic"),
            Instruction::Add => write!(f, "add"),
            Instruction::Sub => write!(f, "sub"),
            Instruction::Not => write!(f, "not"),
            Instruction::And => write!(f, "and"),
            Instruction::Or => write!(f, "or"),
            Instruction::Gt => write!(f, "gt"),
            Instruction::Lt => write!(f, "lt"),
            Instruction::Eq => write!(f, "eq"),
            Instruction::FactNew => write!(f, "fact.new"),
            Instruction::FactKeySet => write!(f, "fact.kset"),
            Instruction::FactValueSet => write!(f, "fact.vset"),
            Instruction::StructNew => write!(f, "struct.new"),
            Instruction::StructSet => write!(f, "struct.set"),
            Instruction::StructGet => write!(f, "struct.get"),
            Instruction::Emit => write!(f, "emit"),
            Instruction::Create => write!(f, "create"),
            Instruction::Delete => write!(f, "delete"),
            Instruction::Update => write!(f, "update"),
            Instruction::Effect => write!(f, "effect"),
            Instruction::Query => write!(f, "query"),
            Instruction::Exists => write!(f, "exists"),
            Instruction::Id => write!(f, "id"),
            Instruction::AuthorId => write!(f, "author.id"),
        }
    }
}