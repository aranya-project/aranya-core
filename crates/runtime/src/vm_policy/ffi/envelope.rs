use alloc::vec::Vec;

use policy_vm::{
    ffi::{Arg, Color, FfiModule, Func, ModuleSchema, Type},
    CommandContext, KVPair, MachineIOError, OpenContext, SealContext, Stack, Struct, Value,
};

use crate::{Id, VmProtocolData};

pub struct FfiEnvelope {}

impl FfiEnvelope {
    fn seal(&self, stack: &mut impl Stack, ctx: &SealContext<'_>) -> Result<(), MachineIOError> {
        let author_id = Id::default(); // should be a parameter, but stubbing it for now
        let s: Struct = stack.pop().map_err(|_| MachineIOError::Internal)?;
        if s.name != ctx.name {
            return Err(MachineIOError::Internal);
        }
        let serialized_fields = postcard::to_allocvec(&s).map_err(|_| MachineIOError::Internal)?;

        let c = VmProtocolData::Basic {
            parent: ctx.parent_id.into(),
            author_id,
            kind: s.name,
            serialized_fields,
        };

        let payload = postcard::to_allocvec(&c).map_err(|_| MachineIOError::Internal)?;
        // FIXME(chip): bad implementation for example only
        let command_id = Id::hash_for_testing_only(&payload);
        let envelope = Struct::new(
            "Envelope",
            [
                KVPair::new("parent_id", Value::Id(ctx.parent_id)),
                KVPair::new("author_id", Value::Id(author_id.into())),
                KVPair::new("command_id", Value::Id(command_id.into())),
                KVPair::new("payload", Value::Bytes(payload)),
                // TODO(chip): use an actual signature
                KVPair::new("signature", Value::Bytes(b"LOL".to_vec())),
            ],
        );
        stack.push(envelope).map_err(|_| MachineIOError::Internal)
    }

    fn open(&self, stack: &mut impl Stack, ctx: &OpenContext<'_>) -> Result<(), MachineIOError> {
        let mut envelope: Struct = stack.pop().map_err(|_| MachineIOError::Internal)?;
        let bytes: Vec<u8> = envelope
            .fields
            .remove("payload")
            .ok_or(MachineIOError::Internal)?
            .try_into()
            .map_err(|_| MachineIOError::Internal)?;
        let unpacked: VmProtocolData =
            postcard::from_bytes(&bytes).map_err(|_| MachineIOError::Internal)?;
        if let VmProtocolData::Basic {
            kind,
            serialized_fields,
            ..
        } = unpacked
        {
            if kind == ctx.name {
                let s: Struct = postcard::from_bytes(&serialized_fields)
                    .map_err(|_| MachineIOError::Internal)?;
                stack.push(s).map_err(|_| MachineIOError::Internal)?;
                Ok(())
            } else {
                Err(MachineIOError::Internal)
            }
        } else {
            Err(MachineIOError::Internal)
        }
    }
}

impl FfiModule for FfiEnvelope {
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
