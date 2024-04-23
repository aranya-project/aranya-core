extern crate alloc;

use alloc::{borrow::Cow, boxed::Box, string::String, vec::Vec};

use buggy::bug;
use policy_vm::{
    ActionContext, CommandContext, ExitReason, KVPair, Machine, MachineIO, MachineStack,
    OpenContext, PolicyContext, RunState, SealContext, Struct, Value,
};
use spin::Mutex;
use tracing::{error, info, instrument};

use crate::{
    command::{Command, CommandId},
    engine::{EngineError, NullSink, Policy, Sink},
    FactPerspective, MergeIds, Perspective, Prior,
};

mod error;
mod facts;
mod io;
mod protocol;
pub mod testing;

pub use error::*;
pub use facts::*;
pub use io::*;
pub use protocol::*;

/// Creates a [`VmActions`].
///
/// This must be used directly to avoid lifetime issues, not assigned to a variable.
///
/// # Example
///
/// ```ignore
/// let x = 42;
/// let y = String::from("asdf");
/// client.action(storage_id, sink, vm_action!(foobar(x, y)))
/// ```
#[macro_export]
macro_rules! vm_action {
    ($name:ident($($arg:expr),* $(,)?)) => {
        (
            stringify!($name),
            [$(::policy_vm::Value::from($arg)),*].as_slice().into()
        )
    };
}

/// Creates a [`VmEffect`].
///
/// This is mostly useful for testing expected effects.
///
/// # Example
///
/// ```ignore
/// let val = 3;
/// sink.add_expectation(vm_effect!(StuffHappened { x: 1, y: val }));
///
/// client.action(storage_id, sink, vm_action!(create(val)))
/// ```
#[macro_export]
macro_rules! vm_effect {
    ($name:ident { $($field:ident : $val:expr),* $(,)? }) => {
        (
            stringify!($name).into(),
            vec![$(
                ::policy_vm::KVPair::new(stringify!($field), $val.into())
            ),*]
        )
    };
}

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

impl<E: crypto::Engine> VmPolicy<E> {
    #[instrument(skip_all, fields(name = name))]
    fn evaluate_rule<'a, P>(
        &self,
        name: &str,
        fields: &[KVPair],
        envelope: Envelope,
        facts: &'a mut P,
        sink: &'a mut impl Sink<(String, Vec<KVPair>)>,
        ctx: &CommandContext<'_>,
    ) -> Result<(), EngineError>
    where
        P: FactPerspective,
    {
        let mut ffis = self.ffis.lock();
        let mut eng = self.engine.lock();
        let mut io = VmPolicyIO::new(facts, sink, &mut *eng, &mut ffis);
        let mut rs = self.machine.create_run_state(&mut io, ctx);
        let self_data = Struct::new(name, fields);
        match rs.call_command_policy(&self_data.name, &self_data, envelope.into()) {
            Ok(reason) => match reason {
                ExitReason::Normal => Ok(()),
                ExitReason::Check => {
                    info!("Check {}", self.source_location(&rs));
                    Err(EngineError::Check)
                }
                ExitReason::Panic => {
                    info!("Panicked {}", self.source_location(&rs));
                    Err(EngineError::Panic)
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
        name: &str,
        envelope: Envelope,
        facts: &mut P,
    ) -> Result<Struct, EngineError>
    where
        P: FactPerspective,
    {
        let mut sink = NullSink;
        let mut ffis = self.ffis.lock();
        let mut eng = self.engine.lock();
        let mut io = VmPolicyIO::new(facts, &mut sink, &mut *eng, &mut ffis);
        let ctx = CommandContext::Open(OpenContext { name });
        let mut rs = self.machine.create_run_state(&mut io, &ctx);
        let status = rs.call_open(name, envelope.into());
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
        ctx_parent: CommandId,
        facts: &mut impl FactPerspective,
    ) -> Result<Envelope, EngineError> {
        let mut sink = NullSink;
        let mut ffis = self.ffis.lock();
        let mut eng = self.engine.lock();
        let mut io = VmPolicyIO::new(facts, &mut sink, &mut *eng, &mut ffis);
        let ctx = CommandContext::Seal(SealContext {
            name,
            head_id: ctx_parent.into(),
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
                    let strukt = Struct::try_from(v).map_err(|e| {
                        error!("Envelope is not a struct: {e}");
                        EngineError::InternalError
                    })?;
                    let envelope = Envelope::try_from(strukt).map_err(|e| {
                        error!("Malformed Envelope: {e}");
                        EngineError::InternalError
                    })?;
                    Ok(envelope)
                }
                ExitReason::Check => {
                    info!("Check {}", self.source_location(&rs));
                    Err(EngineError::Check)
                }
                ExitReason::Panic => {
                    info!("Panicked {}", self.source_location(&rs));
                    Err(EngineError::Panic)
                }
            },
            Err(e) => {
                error!("\n{e}");
                Err(EngineError::InternalError)
            }
        }
    }

    #[instrument(skip_all)]
    fn read_command<'a>(
        &self,
        id: CommandId,
        data: &'a [u8],
    ) -> Result<VmProtocol<'a>, EngineError> {
        let unpacked: VmProtocolData = postcard::from_bytes(data).map_err(|e| {
            error!("Could not deserialize: {e:?}");
            EngineError::Read
        })?;
        Ok(VmProtocol::new(data, id, unpacked))
    }
}

/// [`VmPolicy`]'s actions.
pub type VmActions<'a> = (&'a str, Cow<'a, [Value]>);

/// [`VmPolicy`]'s effects.
pub type VmEffect = (String, Vec<KVPair>);

impl<E: crypto::Engine> Policy for VmPolicy<E> {
    type Payload<'a> = (String, Vec<u8>);

    type Action<'a> = VmActions<'a>;

    type Effect = VmEffect;

    type Command<'a> = VmProtocol<'a>;

    fn serial(&self) -> u32 {
        // TODO(chip): Implement an actual serial number
        0u32
    }

    #[instrument(skip_all)]
    fn call_rule(
        &self,
        command: &impl Command,
        facts: &mut impl FactPerspective,
        sink: &mut impl Sink<Self::Effect>,
    ) -> Result<(), EngineError> {
        let unpacked: VmProtocolData = postcard::from_bytes(command.bytes()).map_err(|e| {
            error!("Could not deserialize: {e:?}");
            EngineError::Read
        })?;
        match unpacked {
            VmProtocolData::Init {
                author_id,
                kind,
                serialized_fields,
                signature,
                ..
            } => {
                let envelope = Envelope {
                    parent_id: CommandId::default(),
                    author_id,
                    command_id: command.id(),
                    payload: serialized_fields,
                    signature,
                };
                let command_struct = self.open_command(&kind, envelope.clone(), facts)?;
                let fields: Vec<KVPair> = command_struct
                    .fields
                    .into_iter()
                    .map(|(k, v)| KVPair::new(&k, v))
                    .collect();
                let ctx = CommandContext::Policy(PolicyContext {
                    name: &kind,
                    id: command.id().into(),
                    author: author_id,
                    version: CommandId::default().into(),
                });
                self.evaluate_rule(&kind, fields.as_slice(), envelope, facts, sink, &ctx)?
            }
            VmProtocolData::Basic {
                parent,
                kind,
                author_id,
                serialized_fields,
                signature,
            } => {
                let envelope = Envelope {
                    parent_id: parent,
                    author_id,
                    command_id: command.id(),
                    payload: serialized_fields,
                    signature,
                };
                let command_struct = self.open_command(&kind, envelope.clone(), facts)?;
                let fields: Vec<KVPair> = command_struct
                    .fields
                    .into_iter()
                    .map(|(k, v)| KVPair::new(&k, v))
                    .collect();
                let ctx = CommandContext::Policy(PolicyContext {
                    name: &kind,
                    id: command.id().into(),
                    author: author_id,
                    version: CommandId::default().into(),
                });
                self.evaluate_rule(&kind, fields.as_slice(), envelope, facts, sink, &ctx)?
            }
            // Merges always pass because they're an artifact of the graph
            _ => (),
        }

        Ok(())
    }

    #[instrument(skip_all, fields(name = name))]
    fn call_action(
        &self,
        (name, args): Self::Action<'_>,
        facts: &mut impl Perspective,
        sink: &mut impl Sink<Self::Effect>,
    ) -> Result<(), EngineError> {
        let parent = match facts.head_id() {
            Prior::None => None,
            Prior::Single(id) => Some(id),
            Prior::Merge(_, _) => bug!("cannot have a merge parent in call_action"),
        };
        // FIXME(chip): This is kind of wrong, but it avoids having to
        // plumb Option<Id> into the VM and FFI
        let ctx_parent = parent.unwrap_or_default();

        let emit_stack = {
            let mut ffis = self.ffis.lock();
            let mut eng = self.engine.lock();
            let mut io = VmPolicyIO::new(facts, sink, &mut *eng, &mut ffis);
            let ctx = CommandContext::Action(ActionContext {
                name,
                head_id: ctx_parent.into(),
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
                    return Err(EngineError::Check);
                }
                ExitReason::Panic => {
                    info!("Panicked {}", self.source_location(&rs));
                    return Err(EngineError::Panic);
                }
            };
            io.into_emit_stack()
        };

        for (name, fields) in emit_stack {
            let envelope = self.seal_command(&name, fields, ctx_parent, facts)?;
            let data = match parent {
                None => VmProtocolData::Init {
                    // TODO(chip): where does the policy value come from?
                    policy: 0u64.to_le_bytes(),
                    author_id: envelope.author_id,
                    kind: name,
                    serialized_fields: envelope.payload,
                    signature: envelope.signature,
                },
                Some(parent) => VmProtocolData::Basic {
                    author_id: envelope.author_id,
                    parent,
                    kind: name,
                    serialized_fields: envelope.payload,
                    signature: envelope.signature,
                },
            };
            let wrapped = postcard::to_allocvec(&data)?;
            let new_command = self.read_command(envelope.command_id, &wrapped)?;

            self.call_rule(&new_command, facts, sink)?;
            facts.add_command(&new_command).map_err(|e| {
                error!("{e}");
                EngineError::Write
            })?;
        }

        Ok(())
    }

    fn merge<'a>(
        &self,
        target: &'a mut [u8],
        ids: MergeIds,
    ) -> Result<Self::Command<'a>, EngineError> {
        let (left, right) = ids.into();
        let c = VmProtocolData::Merge { left, right };
        let data = postcard::to_slice(&c, target).map_err(|e| {
            error!("{e}");
            EngineError::Write
        })?;
        let id = CommandId::hash_for_testing_only(data);
        Ok(VmProtocol::new(data, id, c))
    }
}

#[cfg(test)]
mod tests;
