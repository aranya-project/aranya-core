//! VmPolicy implements a [Policy] that evaluates actions and commands via the [Policy
//! VM](../../policy_vm/index.html).
//!
//! ## Creating a `VmPolicy` instance
//!
//! To use `VmPolicy` in your [`Engine`](super::Engine), you need to provide a Policy VM
//! [`Machine`], a [`crypto::Engine`], and a Vec of Boxed FFI implementations. The Machine
//! will be created by either compiling a policy document (see
//! [`parse_policy_document()`](../../policy_lang/lang/fn.parse_policy_document.html) and
//! [`Compiler`](../../policy_compiler/struct.Compiler.html)), or loading a compiled policy
//! module (see [`Machine::from_module()`]). The crypto engine comes from your favorite
//! implementation
//! ([`DefaultEngine::from_entropy()`](crypto::default::DefaultEngine::from_entropy) is a
//! good choice for testing). The list of FFIs is a list of things that implement
//! [`FfiModule`](policy_vm::ffi::FfiModule), most likely via the [ffi attribute
//! macro](../../policy_vm/ffi/attr.ffi.html). The list of FFI modules _must_ be in the same
//! order as the FFI schemas given during VM construction.
//!
//! ```ignore
//! // Create a `Machine` by compiling policy from source.
//! let ast = parse_policy_document(policy_doc).unwrap();
//! let machine = Compiler::new(&ast)
//!     .ffi_modules(&[TestFfiEnvelope::SCHEMA])
//!     .compile()
//!     .unwrap();
//! // Create a `crypto::Engine` implementation
//! let (eng, _) = DefaultEngine::from_entropy(Rng);
//! // Create a list of FFI module implementations
//! let ffi_modules = vec![Box::from(TestFfiEnvelope {
//!     user: UserId::random(&mut Rng),
//! })];
//! // And finally, create the VmPolicy
//! let policy = VmPolicy::new(machine, eng, ffi_modules).unwrap();
//! ```
//!
//! ## Actions and Effects
//!
//! The VM represents actions as a kind of function, which has a name and a list of
//! parameters. [`VmPolicy`] represents those actions as [`VmAction`]. Calling an action
//! via [`call_action()`](VmPolicy::call_action) requires you to give it an action of
//! that type. You can use the [`vm_action!()`](crate::vm_action) macro to create this
//! more comfortably.
//!
//! The VM represents effects as a named struct containing a set of fields. `VmPolicy`
//! represents this as [`VmEffect`]. Effects captured via [`Sink`]s will have this type.
//! You can use the [`vm_effect!()`](crate::vm_effect) macro to create effects.
//!
//! ## The "init" command and action
//!
//! To create a graph, there must be a command that is the ancestor of all commands in that
//! graph - the "init" command. In `VmPolicy`, that command is created via a special action
//! given as the second argument to
//! [`ClientState::new_graph()`](crate::ClientState::new_graph). The first command produced
//! by that action becomes the "init" command. It has basically all the same properties as
//! any other command, except it has no parent.
//!
//! So for this example policy:
//!
//! ```policy
//! command Init {
//!     fields {
//!         nonce int,
//!     }
//!     seal { ... }
//!     open { ... }
//!     policy {
//!         finish {}
//!     }
//! }
//!
//! action init(nonce int) {
//!     publish Init {
//!         nonce: nonce,
//!     }
//! }
//! ```
//!
//! This is an example of initializing a graph with `new_graph()`:
//!
//! ```ignore
//! let engine = MyEngine::new();
//! let provider = MyStorageProvider::new();
//! let mut cs = ClientState::new(engine, provider);
//! let mut sink = MySink::new();
//!
//! let storage_id = cs
//!     .new_graph(&[0u8], vm_action!(init(0)), &mut sink)
//!     .expect("could not create graph");
//! ```
//!
//! Because the ID of this initial command is also the storage ID of the resulting graph,
//! some data within the command must be present to ensure that multiple initial commands
//! create distinct IDs for each graph. If no other suitable data exists, it is good
//! practice to add a nonce field that is distinct for each graph.
//!
//! ## Policy Interface Generator
//!
//! A more comfortable way to use `VmPolicy` is via the [Policy Interface
//! Generator](../../policy_ifgen/index.html). It creates a Rust interface for actions and
//! effects from a policy document.

extern crate alloc;

use alloc::{borrow::Cow, boxed::Box, string::String, vec::Vec};
use core::fmt;

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
    CommandRecall, FactPerspective, MergeIds, Perspective, Prior,
};

mod error;
mod io;
mod protocol;
pub mod testing;

pub use error::*;
pub use io::*;
pub use protocol::*;

/// Creates a [`VmAction`].
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
        $crate::VmAction {
            name: stringify!($name),
            args: [$(::policy_vm::Value::from($arg)),*].as_slice().into(),
        }
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
        $crate::VmEffect {
            name: stringify!($name).into(),
            fields: vec![$(
                ::policy_vm::KVPair::new(stringify!($field), $val.into())
            ),*],
        }
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
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip_all, fields(name = name))]
    fn evaluate_rule<'a, P>(
        &self,
        name: &str,
        fields: &[KVPair],
        envelope: Envelope,
        facts: &'a mut P,
        sink: &'a mut impl Sink<VmEffect>,
        ctx: &CommandContext<'_>,
        recall: CommandRecall,
    ) -> Result<(), EngineError>
    where
        P: FactPerspective,
    {
        let mut ffis = self.ffis.lock();
        let mut eng = self.engine.lock();
        let mut io = VmPolicyIO::new(facts, sink, &mut *eng, &mut ffis);
        let mut rs = self.machine.create_run_state(&mut io, ctx);
        let self_data = Struct::new(name, fields);
        match rs.call_command_policy(&self_data.name, &self_data, envelope.clone().into()) {
            Ok(reason) => match reason {
                ExitReason::Normal => Ok(()),
                ExitReason::Check => {
                    info!("Check {}", self.source_location(&rs));
                    self.recall_internal(recall, &mut rs, name, &self_data, envelope)
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

    fn recall_internal<M>(
        &self,
        recall: CommandRecall,
        rs: &mut RunState<'_, M>,
        name: &str,
        self_data: &Struct,
        envelope: Envelope,
    ) -> Result<(), EngineError>
    where
        M: MachineIO<MachineStack>,
    {
        match recall {
            CommandRecall::None => Err(EngineError::Check),
            CommandRecall::OnCheck => {
                match rs.call_command_recall(name, self_data, envelope.into()) {
                    Ok(ExitReason::Normal) => Err(EngineError::Check),
                    Ok(ExitReason::Check) => {
                        info!("Recall failed: {}", self.source_location(rs));
                        Err(EngineError::Check)
                    }
                    Ok(ExitReason::Panic) | Err(_) => {
                        info!("Recall panicked: {}", self.source_location(rs));
                        Err(EngineError::Panic)
                    }
                }
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
}

/// [`VmPolicy`]'s actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmAction<'a> {
    /// The name of the action.
    pub name: &'a str,
    /// The arguments of the action.
    pub args: Cow<'a, [Value]>,
}

/// [`VmPolicy`]'s effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmEffect {
    /// The name of the effect.
    pub name: String,
    /// The fields of the effect.
    pub fields: Vec<KVPair>,
}

impl<E: crypto::Engine> Policy for VmPolicy<E> {
    type Action<'a> = VmAction<'a>;
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
        recall: CommandRecall,
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
                self.evaluate_rule(
                    &kind,
                    fields.as_slice(),
                    envelope,
                    facts,
                    sink,
                    &ctx,
                    recall,
                )?
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
                self.evaluate_rule(
                    &kind,
                    fields.as_slice(),
                    envelope,
                    facts,
                    sink,
                    &ctx,
                    recall,
                )?
            }
            // Merges always pass because they're an artifact of the graph
            _ => (),
        }

        Ok(())
    }

    #[instrument(skip_all, fields(name = action.name))]
    fn call_action(
        &self,
        action: Self::Action<'_>,
        facts: &mut impl Perspective,
        sink: &mut impl Sink<Self::Effect>,
    ) -> Result<(), EngineError> {
        let VmAction { name, args } = action;

        let parent = match facts.head_id() {
            Prior::None => None,
            Prior::Single(id) => Some(id),
            Prior::Merge(_, _) => bug!("cannot have a merge parent in call_action"),
        };
        // FIXME(chip): This is kind of wrong, but it avoids having to
        // plumb Option<Id> into the VM and FFI
        let ctx_parent = parent.unwrap_or_default();

        let publish_stack = {
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
            io.into_publish_stack()
        };

        for (name, fields) in publish_stack {
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
            let new_command = VmProtocol::new(&wrapped, envelope.command_id, data);

            self.call_rule(&new_command, facts, sink, CommandRecall::None)?;
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

impl fmt::Display for VmAction<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_tuple(self.name);
        for arg in self.args.as_ref() {
            d.field(&DebugViaDisplay(arg));
        }
        d.finish()
    }
}

impl fmt::Display for VmEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct(&self.name);
        for field in &self.fields {
            d.field(field.key(), &DebugViaDisplay(field.value()));
        }
        d.finish()
    }
}

/// Implements `Debug` via `T`'s `Display` impl.
struct DebugViaDisplay<T>(T);

impl<T: fmt::Display> fmt::Debug for DebugViaDisplay<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
