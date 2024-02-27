use alloc::vec::Vec;

use crypto::UserId;
use policy_vm::{
    ffi::{Arg, Color, FfiModule, Func, ModuleSchema, Type},
    CommandContext, MachineIOError, OpenContext, SealContext, Stack, Struct, Value,
};

use crate::{Envelope, Id};

pub struct TestFfiEnvelope {}

impl TestFfiEnvelope {
    fn seal(&self, stack: &mut impl Stack, ctx: &SealContext<'_>) -> Result<(), MachineIOError> {
        let author_id = UserId::default(); // should be a parameter, but stubbing it for now
        let s: Struct = stack.pop().map_err(|_| MachineIOError::Internal)?;
        if s.name != ctx.name {
            return Err(MachineIOError::Internal);
        }
        let serialized_fields = postcard::to_allocvec(&s).map_err(|_| MachineIOError::Internal)?;

        // FIXME(chip): bad implementation for example only
        let command_id = Id::hash_for_testing_only(&serialized_fields);
        let envelope = Envelope {
            parent_id: ctx.parent_id.into(),
            author_id,
            command_id,
            payload: serialized_fields,
            // TODO(chip): use an actual signature
            signature: b"LOL".to_vec(),
        };
        stack
            .push(Value::Struct(envelope.into()))
            .map_err(|_| MachineIOError::Internal)
    }

    fn open(&self, stack: &mut impl Stack, ctx: &OpenContext<'_>) -> Result<(), MachineIOError> {
        let mut envelope: Struct = stack.pop().map_err(|_| MachineIOError::Internal)?;
        let bytes: Vec<u8> = envelope
            .fields
            .remove("payload")
            .ok_or(MachineIOError::Internal)?
            .try_into()
            .map_err(|_| MachineIOError::Internal)?;
        let s: Struct = postcard::from_bytes(&bytes).map_err(|_| MachineIOError::Internal)?;
        if s.name == ctx.name {
            stack.push(s).map_err(|_| MachineIOError::Internal)?;
            Ok(())
        } else {
            Err(MachineIOError::Internal)
        }
    }
}

impl FfiModule for TestFfiEnvelope {
    type Error = MachineIOError;

    const SCHEMA: ModuleSchema<'static> = ModuleSchema {
        name: "envelope",
        functions: &[
            Func {
                name: "seal",
                args: &[Arg {
                    name: "s",
                    vtype: Type::Struct(""),
                }],
                color: Color::Pure(Type::Bytes),
            },
            Func {
                name: "open",
                args: &[Arg {
                    name: "s",
                    vtype: Type::Bytes,
                }],
                color: Color::Pure(Type::Struct("")),
            },
        ],
    };

    fn call<E: crypto::Engine + ?Sized>(
        &mut self,
        procedure: usize,
        stack: &mut impl Stack,
        ctx: &CommandContext<'_>,
        _eng: &mut E,
    ) -> Result<(), Self::Error> {
        match procedure {
            0 => {
                if let CommandContext::Seal(ctx) = ctx {
                    self.seal(stack, ctx)
                } else {
                    Err(MachineIOError::Internal)
                }
            }
            1 => {
                if let CommandContext::Open(ctx) = ctx {
                    self.open(stack, ctx)
                } else {
                    Err(MachineIOError::Internal)
                }
            }
            _ => Err(MachineIOError::Internal),
        }
    }
}
