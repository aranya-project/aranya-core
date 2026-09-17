#![allow(missing_docs)]

use core::fmt::{self, Display};

pub struct ByteCode(Box<[EncodedInstruction]>);

const _: () = assert!(size_of::<EncodedInstruction>() == 4);

#[derive(
    Copy,
    Clone,
    Debug,
    zerocopy::IntoBytes,
    zerocopy::TryFromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
)]
#[repr(u8)]
pub enum EncodedInstruction {
    // data
    /// Push a value onto the stack
    Const(PoolIdx),
    /// Push an identifier onto the stack
    Identifier(IdentIdx),
    /// Define a local value by name
    Def(IdentIdx),
    /// Get a local value by name
    Get(IdentIdx),
    /// Duplicate the value at the top of the stack
    Dup(Ignore),
    /// Remove a value from the top of the stack
    Pop(Ignore),
    // control flow
    /// Define the beginning of a block
    Block(Ignore),
    /// Define the end of a block
    End(Ignore),
    /// Jump forward to the target in the current block
    Jump(Offset),
    /// Jump if top of stack is true
    Branch(Offset),
    /// Call regular function at target
    Call(Addr),
    /// Invoke the named recall block
    Recall(Addr),
    /// Call external function (FFI), specified by module, procedure indices. The FFI modules should be added to the MachineIO.
    ExtCall(FfiCall),
    /// Return to the last address on the control flow stack
    Return(Ignore),
    /// End execution non-fatally
    Exit(Pad2<ExitReason>),
    // arithmetic/logic
    /// Add two numbers
    Add(Ignore),
    /// Subtract two numbers
    Sub(Ignore),
    /// Add two numbers with saturation
    SaturatingAdd(Ignore),
    /// Subtract two numbers with saturation
    SaturatingSub(Ignore),
    /// Logical negation
    Not(Ignore),
    /// Greater than
    Gt(Ignore),
    /// Less than
    Lt(Ignore),
    /// Equality
    Eq(Ignore),
    // facts
    /// Create a fact object by name
    FactNew(IdentIdx),
    /// Set a key member
    FactKeySet(IdentIdx),
    /// Set a value member
    FactValueSet(IdentIdx),
    // structs
    /// Create a struct object by name
    StructNew(IdentIdx),
    /// Add a member to the struct
    StructSet(IdentIdx),
    /// Get a member from the struct
    StructGet(IdentIdx),
    /// Add multiple members to the struct
    MStructSet(U24),
    /// Get multiple members from the struct
    MStructGet(U24),
    /// Cast previous stack value to given type
    Cast(IdentIdx),
    /// Wrap the value on top of the stack in Some, Ok, or Err, depending on wrap type.
    Wrap(Pad2<WrapType>),
    /// Check if the value on top of the stack is the given wrap type (pushes bool).
    Is(Pad2<WrapType>),
    /// Unwrap the inner value from a Result (Ok or Err). Will eventually support Optional (Some) as well.
    Unwrap(Pad2<WrapType>),
    // context-specific
    /// Publish a struct as a command
    Publish(Ignore),
    /// Create a fact
    Create(Ignore),
    /// Delete a fact
    Delete(Ignore),
    /// Update a fact
    Update(Ignore),
    /// Emit an effect
    Emit(Ignore),
    /// Query for a fact
    Query(Ignore),
    /// Count facts, up to a given limit
    FactCount(U24),
    /// Execute a fact query, and retain results so they can be consumed with `QueryNext`.
    QueryStart(Ignore),
    /// Fetches the next result, and pushes it onto the stack
    QueryNext(IdentIdx),
    /// Save the stack depth for later restoration.
    SaveSP(Ignore),
    /// Restore the stack depth.
    RestoreSP(Ignore),
    /// Set finish state (for analysis).
    Finish(Pad2<bool>),
}

#[derive(
    Copy,
    Clone,
    Debug,
    zerocopy::IntoBytes,
    zerocopy::FromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct Pad2<T> {
    _pad: [u8; 2],
    value: T,
}

#[derive(
    Copy,
    Clone,
    Debug,
    zerocopy::IntoBytes,
    zerocopy::TryFromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct Ignore([Zero; 3]);

#[derive(
    Copy,
    Clone,
    Debug,
    zerocopy::IntoBytes,
    zerocopy::TryFromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
)]
#[repr(u8)]
pub enum Zero {
    Value = 0,
}

#[derive(
    Copy,
    Clone,
    zerocopy::IntoBytes,
    zerocopy::FromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct U16([u8; 2]);

impl U16 {
    fn get(self) -> u16 {
        u16::from_le_bytes(self.0)
    }
}

impl fmt::Debug for U16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.get(), f)
    }
}

#[derive(
    Copy,
    Clone,
    zerocopy::IntoBytes,
    zerocopy::FromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct U24([u8; 3]);

impl U24 {
    fn get(self) -> u32 {
        let [a, b, c] = self.0;
        u32::from_le_bytes([0, a, b, c]) >> 8
    }
}

impl fmt::Debug for U24 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.get(), f)
    }
}

#[derive(
    Copy,
    Clone,
    zerocopy::IntoBytes,
    zerocopy::FromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct I24([u8; 3]);

impl I24 {
    fn get(self) -> i32 {
        let [a, b, c] = self.0;
        i32::from_le_bytes([0, a, b, c]) >> 8
    }
}

impl fmt::Debug for I24 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.get(), f)
    }
}

#[derive(
    Copy,
    Clone,
    Debug,
    zerocopy::IntoBytes,
    zerocopy::FromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct IdentIdx(U24);

#[derive(
    Copy,
    Clone,
    Debug,
    zerocopy::IntoBytes,
    zerocopy::FromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct PoolIdx(U24);

#[derive(
    Copy,
    Clone,
    Debug,
    zerocopy::IntoBytes,
    zerocopy::FromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct Offset(I24);

#[derive(
    Copy,
    Clone,
    Debug,
    zerocopy::IntoBytes,
    zerocopy::FromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct Addr(U24);

#[derive(
    Copy,
    Clone,
    Debug,
    zerocopy::IntoBytes,
    zerocopy::FromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct FfiCall {
    module: u8,
    method: U16,
}

/// Reason for ending execution.
#[must_use]
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    zerocopy::IntoBytes,
    zerocopy::TryFromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
)]
#[repr(u8)]
pub enum ExitReason {
    /// Execution completed without errors.
    Normal,
    /// Execution is paused to return a result, which is at the top of the stack. Call `RunState::run()` again to resume.
    Yield,
    /// Execution was aborted gracefully, due to an error. If the command had a recall block, it was already executed inline before this exit.
    Check,
    /// Execution was aborted due to an unhandled error.
    Panic,
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

/// Type of `Value` wrapping
#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    zerocopy::IntoBytes,
    zerocopy::TryFromBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
)]
#[repr(u8)]
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

pub fn ins_from_bytes(
    bytes: &[u8],
) -> Result<&[EncodedInstruction], zerocopy::ValidityError<&[u8], [EncodedInstruction]>> {
    zerocopy::try_transmute_ref!(bytes)
}
