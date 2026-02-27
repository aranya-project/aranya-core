//! The VM's foreign function interface.

use alloc::vec::Vec;

use aranya_crypto::Engine;
use aranya_id::{Id, IdTag};
use aranya_policy_ast::Text;
pub use aranya_policy_module::ffi::*;

#[cfg(feature = "derive")]
pub use crate::derive::*;
use crate::{CommandContext, MachineError, Stack};

/// Foreign Function Interface to allow the policy VM to call external functions.
pub trait FfiModule {
    /// The error result from [`FfiModule::call`].
    type Error: Into<MachineError>;

    /// A list of function definitions. Used by the
    /// compiler to emit the stack instructions needed for
    /// a call.
    const SCHEMA: ModuleSchema<'static>;

    /// Invokes a function in the module.
    /// `procedure` is the index in [`functions`][Self::SCHEMA].
    fn call<E: Engine>(
        &self,
        procedure: usize,
        stack: &mut impl Stack,
        ctx: &CommandContext,
        eng: &E,
    ) -> Result<(), Self::Error>;
}

/// Allows a type to be used by FFI derive.
pub trait Typed {
    /// Indicates the type of the type.
    const TYPE: Type<'static>;
}

macro_rules! impl_typed {
    ($name:ty => $type:ident) => {
        impl Typed for $name {
            const TYPE: Type<'static> = Type::$type;
        }
    };
}

impl_typed!(Text => String);

impl_typed!(Vec<u8> => Bytes);
impl_typed!(&[u8] => Bytes);

impl_typed!(isize => Int);
impl_typed!(i64 => Int);
impl_typed!(i32 => Int);
impl_typed!(i16 => Int);
impl_typed!(i8 => Int);

impl_typed!(usize => Int);
impl_typed!(u64 => Int);
impl_typed!(u32 => Int);
impl_typed!(u16 => Int);
impl_typed!(u8 => Int);

impl_typed!(bool => Bool);

impl<Tag: IdTag> Typed for Id<Tag> {
    const TYPE: Type<'static> = Type::Id;
}

impl<T: Typed> Typed for Option<T> {
    const TYPE: Type<'static> = Type::Optional(const { &T::TYPE });
}
