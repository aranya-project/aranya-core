extern crate alloc;

use alloc::{borrow::Cow, string::String, vec::Vec};

use crypto::UserId;
use policy_vm::{
    ActionContext, CommandContext, KVPair, Machine, MachineStatus, OpenContext, PolicyContext,
    SealContext, Struct, Value,
};

use crate::{
    command::{Command, Id},
    engine::{EngineError, NullSink, Policy, Sink},
    FactPerspective, MergeIds, Perspective,
};

mod error;
mod facts;
pub mod ffi;
mod io;
mod protocol;
pub use error::*;
pub use facts::*;
pub use io::*;
pub use protocol::*;

/// A [Policy](crate::engine::Policy) implementation that uses the Policy VM.
pub struct VmPolicy {
    machine: Machine,
}

impl VmPolicy {
    /// Create a new `VmPolicy` from a [Machine]
    pub fn new(machine: Machine) -> Result<VmPolicy, VmPolicyError> {
        Ok(VmPolicy { machine })
    }

    fn evaluate_rule<'a, P>(
        &self,
        kind: &str,
        fields: &[KVPair],
        facts: &'a mut P,
        sink: &'a mut impl Sink<(String, Vec<KVPair>)>,
        ctx: &CommandContext<'_>,
    ) -> Result<bool, EngineError>
    where
        P: FactPerspective,
    {
        let mut io = VmPolicyIO::new(facts, sink);
        let mut rs = self.machine.create_run_state(&mut io, ctx);
        let self_data = Struct::new(kind, fields);
        match rs.call_command_policy(&self_data.name, &self_data) {
            Ok(status) => match status {
                MachineStatus::Exited => Ok(true),
                MachineStatus::Panicked => Ok(false),
                // call_command_policy should never return Executing
                MachineStatus::Executing => Err(EngineError::InternalError),
            },
            Err(_) => {
                // TODO(chip): Report the VM error somehow
                Err(EngineError::InternalError)
            }
        }
    }

    fn open_command<P>(
        &self,
        author_id: Id,
        name: &str,
        parent: Id,
        payload: &[u8],
        facts: &mut P,
    ) -> Result<Struct, EngineError>
    where
        P: FactPerspective,
    {
        let mut sink = NullSink;
        let mut io = VmPolicyIO::new(facts, &mut sink);
        let ctx = CommandContext::Open(OpenContext {
            name,
            parent_id: parent.into(),
        });
        let mut rs = self.machine.create_run_state(&mut io, &ctx);
        let envelope = Struct::new(
            "Envelope",
            [
                KVPair::new("parent_id", Value::Id(parent.into())),
                KVPair::new("author_id", Value::Id(author_id.into())),
                KVPair::new("payload", Value::Bytes(payload.to_vec())),
                // TODO(chip): use an actual signature
                KVPair::new("signature", Value::Bytes(b"LOL".to_vec())),
            ],
        );
        let status = rs.call_open(name, &envelope);
        match status {
            Ok(MachineStatus::Panicked) => Err(EngineError::Check),
            Ok(MachineStatus::Executing) => Err(EngineError::InternalError),
            Ok(MachineStatus::Exited) => {
                let v = rs
                    .consume_return()
                    .map_err(|_| EngineError::InternalError)?;
                Ok(v.try_into().map_err(|_| EngineError::InternalError)?)
            }
            Err(_) => Err(EngineError::InternalError),
        }
    }

    fn seal_command(
        &self,
        name: &str,
        fields: impl IntoIterator<Item = impl Into<(String, Value)>>,
        parent: &Id,
    ) -> Result<Struct, EngineError> {
        let mut facts = NullFacts;
        let mut sink = NullSink;
        let mut io = VmPolicyIO::new(&mut facts, &mut sink);
        let ctx = CommandContext::Seal(SealContext {
            name,
            parent_id: (*parent).into(),
        });
        let mut rs = self.machine.create_run_state(&mut io, &ctx);
        let command_struct = Struct::new(name, fields);
        let status = rs.call_seal(name, &command_struct);
        match status {
            Ok(MachineStatus::Panicked) => Err(EngineError::Check),
            Ok(MachineStatus::Executing) => Err(EngineError::InternalError),
            Ok(MachineStatus::Exited) => {
                let v = rs
                    .consume_return()
                    .map_err(|_| EngineError::InternalError)?;
                Ok(v.try_into().map_err(|_| EngineError::InternalError)?)
            }
            Err(_) => Err(EngineError::InternalError),
        }
    }
}

impl Policy for VmPolicy {
    type Payload<'a> = (String, Vec<u8>);

    type Actions<'a> = (&'a str, Cow<'a, [Value]>);

    type Effects = (String, Vec<KVPair>);

    type Command<'a> = VmProtocol<'a>;

    fn serial(&self) -> u32 {
        // TODO(chip): Implement an actual serial number
        0u32
    }

    fn call_rule<'a>(
        &self,
        command: &impl Command<'a>,
        facts: &mut impl FactPerspective,
        sink: &mut impl Sink<Self::Effects>,
    ) -> Result<bool, EngineError> {
        let unpacked: VmProtocolData =
            postcard::from_bytes(command.bytes()).map_err(|_| EngineError::Read)?;
        let passed = match unpacked {
            // Init always passes, since it is the root
            VmProtocolData::Init { .. } => true,
            // Merges always pass because they're an artifact of the graph
            VmProtocolData::Merge { .. } => true,
            VmProtocolData::Basic {
                parent,
                kind,
                author_id,
                ..
            } => {
                let command_struct =
                    self.open_command(author_id, &kind, parent, command.bytes(), facts)?;
                let fields: Vec<KVPair> = command_struct
                    .fields
                    .into_iter()
                    .map(|(k, v)| KVPair::new(&k, v))
                    .collect();
                let ctx = CommandContext::Policy(PolicyContext {
                    name: &kind,
                    id: command.id().into(),
                    author: UserId::default(),
                    version: Id::default().into(),
                    parent_id: parent.into(),
                });
                self.evaluate_rule(&kind, fields.as_slice(), facts, sink, &ctx)?
            }
        };

        Ok(passed)
    }

    fn call_action(
        &self,
        parent: &Id,
        (name, args): Self::Actions<'_>,
        facts: &mut impl Perspective,
        sink: &mut impl Sink<Self::Effects>,
    ) -> Result<bool, EngineError> {
        let emit_stack = {
            let mut io = VmPolicyIO::new(facts, sink);
            let ctx = CommandContext::Action(ActionContext {
                name,
                head_id: (*parent).into(),
            });
            let mut rs = self.machine.create_run_state(&mut io, &ctx);
            let status = match args {
                Cow::Borrowed(args) => rs.call_action(name, args.iter().cloned()),
                Cow::Owned(args) => rs.call_action(name, args),
            }
            .map_err(|_| EngineError::InternalError)?;
            match status {
                MachineStatus::Exited => (),
                MachineStatus::Panicked => return Ok(false),
                MachineStatus::Executing => return Err(EngineError::InternalError),
            };
            io.into_emit_stack()
        };
        for (ref name, ref fields) in emit_stack {
            let mut envelope = self.seal_command(name, fields, parent)?;

            let payload: Vec<u8> = envelope
                .fields
                .remove("payload")
                .ok_or(EngineError::InternalError)?
                .try_into()
                .map_err(|_| EngineError::InternalError)?;
            let command_id: crypto::Id = envelope
                .fields
                .remove("command_id")
                .ok_or(EngineError::InternalError)?
                .try_into()
                .map_err(|_| EngineError::InternalError)?;
            let new_command = self.read_command(command_id.into(), &payload)?;

            let passed = self.call_rule(&new_command, facts, sink)?;
            if passed {
                facts
                    .add_command(&new_command)
                    .map_err(|_| EngineError::Write)?;
            } else {
                // Should this early return on failure or continue the
                // rest of the queued commands?
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn read_command<'a>(&self, id: Id, data: &'a [u8]) -> Result<Self::Command<'a>, EngineError> {
        let unpacked: VmProtocolData = postcard::from_bytes(data).map_err(|_| EngineError::Read)?;
        Ok(VmProtocol::new(data, id, unpacked))
    }

    fn init<'a>(
        &self,
        target: &'a mut [u8],
        _policy_data: &[u8],
        _payload: Self::Payload<'_>,
    ) -> Result<Self::Command<'a>, EngineError> {
        let c = VmProtocolData::Init {
            // TODO(chip): this is a placeholder and needs to be updated to a real
            // policy... whatever this is for.
            policy: 0u64.to_le_bytes(),
        };
        postcard::to_slice(&c, target).map_err(|_| EngineError::Write)?;
        // TODO(chip): calculate the proper ID including the signature
        let id = Id::hash_for_testing_only(target);
        Ok(VmProtocol::new(target, id, c))
    }

    fn merge<'a>(
        &self,
        target: &'a mut [u8],
        ids: MergeIds,
    ) -> Result<Self::Command<'a>, EngineError> {
        let (left, right) = ids.into();
        let c = VmProtocolData::Merge { left, right };
        postcard::to_slice(&c, target).map_err(|_| EngineError::Write)?;
        let id = Id::hash_for_testing_only(target);
        Ok(VmProtocol::new(target, id, c))
    }

    fn basic<'a>(
        &self,
        target: &'a mut [u8],
        parent: Id,
        (kind, serialized_fields): Self::Payload<'_>,
    ) -> Result<Self::Command<'a>, EngineError> {
        let c = VmProtocolData::Basic {
            parent,
            // FIXME(chip): Where does the author ID come from?
            author_id: Id::default(),
            kind,
            serialized_fields,
        };
        let data = postcard::to_slice(&c, target).map_err(|_| EngineError::Write)?;
        let id = Id::hash_for_testing_only(data);
        Ok(VmProtocol::new(data, id, c))
    }
}

#[cfg(test)]
mod tests;
