extern crate alloc;

use alloc::{borrow::Cow, boxed::Box, string::String, vec::Vec};

use crypto::UserId;
use policy_vm::{
    ActionContext, CommandContext, ExitReason, KVPair, Machine, MachineIO, MachineStack,
    OpenContext, PolicyContext, RunState, SealContext, Struct, Value,
};
use spin::Mutex;
use tracing::{error, info, instrument};

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

/// A [Policy] implementation that uses the Policy VM.
pub struct VmPolicy<E> {
    machine: Machine,
    engine: Mutex<E>,
    ffis: Mutex<Vec<Box<dyn FfiCallable<E> + Send + 'static>>>,
}

impl<E> VmPolicy<E> {
    /// Create a new `VmPolicy` from a [Machine]
    pub fn new(
        machine: Machine,
        engine: E,
        ffis: Vec<Box<dyn FfiCallable<E> + Send + 'static>>,
    ) -> Result<Self, VmPolicyError> {
        Ok(Self {
            machine,
            engine: Mutex::from(engine),
            ffis: Mutex::from(ffis),
        })
    }

    fn source_location<M>(&self, rs: &RunState<'_, M>) -> String
    where
        M: MachineIO<MachineStack>,
    {
        rs.source_location()
            .unwrap_or(String::from("(unknown location)"))
    }
}

impl<E> VmPolicy<E>
where
    E: crypto::Engine + ?Sized,
{
    #[instrument(skip_all, fields(name = name))]
    fn evaluate_rule<'a, P>(
        &self,
        name: &str,
        fields: &[KVPair],
        facts: &'a mut P,
        sink: &'a mut impl Sink<(String, Vec<KVPair>)>,
        ctx: &CommandContext<'_>,
    ) -> Result<bool, EngineError>
    where
        P: FactPerspective,
    {
        let mut ffis = self.ffis.lock();
        let mut eng = self.engine.lock();
        let mut io = VmPolicyIO::new(facts, sink, &mut *eng, &mut ffis);
        let mut rs = self.machine.create_run_state(&mut io, ctx);
        let self_data = Struct::new(name, fields);
        match rs.call_command_policy(&self_data.name, &self_data) {
            Ok(reason) => match reason {
                ExitReason::Normal => Ok(true),
                ExitReason::Check => {
                    info!("Check {}", self.source_location(&rs));
                    Ok(false)
                }
                ExitReason::Panic => {
                    info!("Panicked {}", self.source_location(&rs));
                    Ok(false)
                }
            },
            Err(e) => {
                error!("\n{e}");
                Err(EngineError::InternalError)
            }
        }
    }

    #[instrument(skip_all, fields(name = name))]
    fn open_command<P>(
        &self,
        command_id: Id,
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
        let mut ffis = self.ffis.lock();
        let mut eng = self.engine.lock();
        let mut io = VmPolicyIO::new(facts, &mut sink, &mut *eng, &mut ffis);
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
                KVPair::new("command_id", Value::Id(command_id.into())),
                KVPair::new("payload", Value::Bytes(payload.to_vec())),
                // TODO(chip): use an actual signature
                KVPair::new("signature", Value::Bytes(b"LOL".to_vec())),
            ],
        );
        let status = rs.call_open(name, &envelope);
        match status {
            Ok(reason) => match reason {
                ExitReason::Normal => {
                    let v = rs.consume_return().map_err(|e| {
                        error!("Could not pull envelope from stack: {e}");
                        EngineError::InternalError
                    })?;
                    Ok(v.try_into().map_err(|e| {
                        error!("Envelope is not a struct: {e}");
                        EngineError::InternalError
                    })?)
                }
                ExitReason::Check => {
                    info!("Check {}", self.source_location(&rs));
                    Err(EngineError::Check)
                }
                ExitReason::Panic => {
                    info!("Panicked {}", self.source_location(&rs));
                    Err(EngineError::Check)
                }
            },
            Err(e) => {
                error!("\n{e}");
                Err(EngineError::InternalError)
            }
        }
    }

    #[instrument(skip_all, fields(name = name))]
    fn seal_command(
        &self,
        name: &str,
        fields: impl IntoIterator<Item = impl Into<(String, Value)>>,
        parent: &Id,
        facts: &mut impl FactPerspective,
    ) -> Result<Struct, EngineError> {
        let mut sink = NullSink;
        let mut ffis = self.ffis.lock();
        let mut eng = self.engine.lock();
        let mut io = VmPolicyIO::new(facts, &mut sink, &mut *eng, &mut ffis);
        let ctx = CommandContext::Seal(SealContext {
            name,
            parent_id: (*parent).into(),
        });
        let mut rs = self.machine.create_run_state(&mut io, &ctx);
        let command_struct = Struct::new(name, fields);
        let status = rs.call_seal(name, &command_struct);
        match status {
            Ok(reason) => match reason {
                ExitReason::Normal => {
                    let v = rs.consume_return().map_err(|e| {
                        error!("Could not pull envelope from stack: {e}");
                        EngineError::InternalError
                    })?;
                    Ok(v.try_into().map_err(|e| {
                        error!("Envelope is not a struct: {e}");
                        EngineError::InternalError
                    })?)
                }
                ExitReason::Check => {
                    info!("Check {}", self.source_location(&rs));
                    Err(EngineError::Check)
                }
                ExitReason::Panic => {
                    info!("Panicked {}", self.source_location(&rs));
                    Err(EngineError::Check)
                }
            },
            Err(e) => {
                error!("\n{e}");
                Err(EngineError::InternalError)
            }
        }
    }
}

/// [`VmPolicy`]'s actions.
pub type VmActions<'a> = (&'a str, Cow<'a, [Value]>);

/// [`VmPolicy`]'s effects.
pub type VmEffects = (String, Vec<KVPair>);

impl<E> Policy for VmPolicy<E>
where
    E: crypto::Engine + ?Sized,
{
    type Payload<'a> = (String, Vec<u8>);

    type Actions<'a> = VmActions<'a>;

    type Effects = VmEffects;

    type Command<'a> = VmProtocol<'a>;

    fn serial(&self) -> u32 {
        // TODO(chip): Implement an actual serial number
        0u32
    }

    #[instrument(skip_all)]
    fn call_rule<'a>(
        &self,
        command: &impl Command<'a>,
        facts: &mut impl FactPerspective,
        sink: &mut impl Sink<Self::Effects>,
    ) -> Result<bool, EngineError> {
        let unpacked: VmProtocolData = postcard::from_bytes(command.bytes()).map_err(|e| {
            error!("Could not deserialize: {e}");
            EngineError::Read
        })?;
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
                let command_struct = self.open_command(
                    command.id(),
                    author_id,
                    &kind,
                    parent,
                    command.bytes(),
                    facts,
                )?;
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

    #[instrument(skip_all, fields(name = name))]
    fn call_action(
        &self,
        parent: &Id,
        (name, args): Self::Actions<'_>,
        facts: &mut impl Perspective,
        sink: &mut impl Sink<Self::Effects>,
    ) -> Result<bool, EngineError> {
        let emit_stack = {
            let mut ffis = self.ffis.lock();
            let mut eng = self.engine.lock();
            let mut io = VmPolicyIO::new(facts, sink, &mut *eng, &mut ffis);
            let ctx = CommandContext::Action(ActionContext {
                name,
                head_id: (*parent).into(),
            });
            let mut rs = self.machine.create_run_state(&mut io, &ctx);
            let exit_reason = match args {
                Cow::Borrowed(args) => rs.call_action(name, args.iter().cloned()),
                Cow::Owned(args) => rs.call_action(name, args),
            }
            .map_err(|e| {
                error!("\n{e}");
                EngineError::InternalError
            })?;
            match exit_reason {
                ExitReason::Normal => {}
                ExitReason::Check => {
                    info!("Check {}", self.source_location(&rs));
                    return Ok(false);
                }
                ExitReason::Panic => {
                    info!("Panicked {}", self.source_location(&rs));
                    return Ok(false);
                }
            };
            io.into_emit_stack()
        };
        for (ref name, ref fields) in emit_stack {
            let mut envelope = self.seal_command(name, fields, parent, facts)?;

            let payload: Vec<u8> = envelope
                .fields
                .remove("payload")
                .ok_or_else(|| {
                    error!("Could not extract `payload` field from Envelope");
                    EngineError::InternalError
                })?
                .try_into()
                .map_err(|e| {
                    error!("Envelope `payload` is not `bytes`: {e}");
                    EngineError::InternalError
                })?;
            let command_id: crypto::Id = envelope
                .fields
                .remove("command_id")
                .ok_or_else(|| {
                    error!("Could not extract `command_id` from Envelope");
                    EngineError::InternalError
                })?
                .try_into()
                .map_err(|e| {
                    error!("Envelope `command_id` is not `id`: {e}");
                    EngineError::InternalError
                })?;
            let new_command = self.read_command(command_id.into(), &payload)?;

            let passed = self.call_rule(&new_command, facts, sink)?;
            if passed {
                facts.add_command(&new_command).map_err(|e| {
                    error!("{e}");
                    EngineError::Write
                })?;
            } else {
                // Should this early return on failure or continue the
                // rest of the queued commands?
                return Ok(false);
            }
        }
        Ok(true)
    }

    #[instrument(skip_all)]
    fn read_command<'a>(&self, id: Id, data: &'a [u8]) -> Result<Self::Command<'a>, EngineError> {
        let unpacked: VmProtocolData = postcard::from_bytes(data).map_err(|e| {
            error!("Could not deserialize: {e}");
            EngineError::Read
        })?;
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
        postcard::to_slice(&c, target).map_err(|e| {
            error!("{e}");
            EngineError::Write
        })?;
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
        postcard::to_slice(&c, target).map_err(|e| {
            error!("{e}");
            EngineError::Write
        })?;
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
        let data = postcard::to_slice(&c, target).map_err(|e| {
            error!("{e}");
            EngineError::Write
        })?;
        let id = Id::hash_for_testing_only(data);
        Ok(VmProtocol::new(data, id, c))
    }
}

#[cfg(test)]
mod tests;
