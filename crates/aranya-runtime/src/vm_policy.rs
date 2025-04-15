//! VmPolicy implements a [Policy] that evaluates actions and commands via the [Policy
//! VM](../../policy_vm/index.html).
//!
//! ## Creating a `VmPolicy` instance
//!
//! To use `VmPolicy` in your [`Engine`](super::Engine), you need to provide a Policy VM
//! [`Machine`], a [`aranya_crypto::Engine`], and a Vec of Boxed FFI implementations. The Machine
//! will be created by either compiling a policy document (see
//! [`parse_policy_document()`](../../policy_lang/lang/fn.parse_policy_document.html) and
//! [`Compiler`](../../policy_compiler/struct.Compiler.html)), or loading a compiled policy
//! module (see [`Machine::from_module()`]). The crypto engine comes from your favorite
//! implementation
//! ([`DefaultEngine::from_entropy()`](aranya_crypto::default::DefaultEngine::from_entropy) is a
//! good choice for testing). The list of FFIs is a list of things that implement
//! [`FfiModule`](aranya_policy_vm::ffi::FfiModule), most likely via the [ffi attribute
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
//! // Create a `aranya_crypto::Engine` implementation
//! let (eng, _) = DefaultEngine::from_entropy(Rng);
//! // Create a list of FFI module implementations
//! let ffi_modules = vec![Box::from(TestFfiEnvelope {
//!     device: DeviceId::random(&mut Rng),
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
//! ## Priorities
//!
//! `VmPolicy` uses the policy language's attributes system to report command priorities to
//! the runtime. You can specify the priority of a command by adding the `priority`
//! attribute. It should be an `int` literal.
//!
//! ```policy
//! command Foo {
//!     attributes {
//!         priority: 3
//!     }
//!     // ... fields, policy, etc.
//! }
//! ```
//!
//! ## Policy Interface Generator
//!
//! A more comfortable way to use `VmPolicy` is via the [Policy Interface
//! Generator](../../policy_ifgen/index.html). It creates a Rust interface for actions and
//! effects from a policy document.

extern crate alloc;

use alloc::{
    borrow::Cow, boxed::Box, collections::BTreeMap, format, rc::Rc, string::String, vec::Vec,
};
use core::{borrow::Borrow, cell::RefCell, fmt};

use aranya_policy_vm::{
    ActionContext, CommandContext, ExitReason, KVPair, Machine, MachineIO, MachineStack,
    OpenContext, PolicyContext, RunState, Stack, Struct, Value,
};
use buggy::{bug, BugExt};
use spin::Mutex;
use tracing::{error, info, instrument};

use crate::{
    command::{Command, CommandId},
    engine::{EngineError, NullSink, Policy, Sink},
    CommandRecall, FactPerspective, MergeIds, Perspective, Prior, Priority,
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
            args: [$(::aranya_policy_vm::Value::from($arg)),*].as_slice().into(),
        }
    };
}

/// Creates a [`VmEffectData`].
///
/// This is mostly useful for testing expected effects, and is expected to be compared
/// against a [`VmEffect`].
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
        $crate::VmEffectData {
            name: stringify!($name).into(),
            fields: vec![$(
                ::aranya_policy_vm::KVPair::new(stringify!($field), $val.into())
            ),*],
        }
    };
}

/// A [Policy] implementation that uses the Policy VM.
pub struct VmPolicy<E> {
    machine: Machine,
    engine: Mutex<E>,
    ffis: Vec<Box<dyn FfiCallable<E> + Send + 'static>>,
    priority_map: BTreeMap<String, VmPriority>,
}

impl<E> VmPolicy<E> {
    /// Create a new `VmPolicy` from a [Machine]
    pub fn new(
        machine: Machine,
        engine: E,
        ffis: Vec<Box<dyn FfiCallable<E> + Send + 'static>>,
    ) -> Result<Self, VmPolicyError> {
        let priority_map = get_command_priorities(&machine)?;
        Ok(Self {
            machine,
            engine: Mutex::new(engine),
            ffis,
            priority_map,
        })
    }

    fn source_location<M>(&self, rs: &RunState<'_, M>) -> String
    where
        M: MachineIO<MachineStack>,
    {
        rs.source_location()
            .unwrap_or_else(|| String::from("(unknown location)"))
    }
}

/// Scans command attributes for priorities and creates the priority map from them.
fn get_command_priorities(
    machine: &Machine,
) -> Result<BTreeMap<String, VmPriority>, VmPolicyError> {
    let mut priority_map = BTreeMap::new();
    for (name, attrs) in &machine.command_attributes {
        let finalize = attrs
            .get("finalize")
            .map(|attr| match *attr {
                Value::Bool(b) => Ok(b),
                _ => Err(VmPolicyError::InvalidAttribute(format!(
                    "{name}::finalize should be Bool, was {}",
                    attr.type_name()
                ))),
            })
            .transpose()?
            == Some(true);
        let priority: Option<u32> = attrs
            .get("priority")
            .map(|attr| match *attr {
                Value::Int(b) => b.try_into().map_err(|_| {
                    VmPolicyError::InvalidAttribute(format!(
                        "{name}::priority value must be within [0, 2^32-1]"
                    ))
                }),
                _ => Err(VmPolicyError::InvalidAttribute(format!(
                    "{name}::priority should be Int, was {}",
                    attr.type_name()
                ))),
            })
            .transpose()?;
        match (finalize, priority) {
            (false, None) => {}
            (false, Some(p)) => {
                priority_map.insert(name.clone(), VmPriority::Basic(p));
            }
            (true, None) => {
                priority_map.insert(name.clone(), VmPriority::Finalize);
            }
            (true, Some(_)) => {
                return Err(VmPolicyError::InvalidAttribute(format!(
                    "{name} has both finalize and priority set"
                )));
            }
        }
    }
    Ok(priority_map)
}

impl<E: aranya_crypto::Engine> VmPolicy<E> {
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip_all, fields(name = name))]
    fn evaluate_rule<'a, P>(
        &self,
        name: &str,
        fields: &[KVPair],
        envelope: Envelope<'_>,
        facts: &'a mut P,
        sink: &'a mut impl Sink<VmEffect>,
        ctx: CommandContext<'_>,
        recall: CommandRecall,
    ) -> Result<(), EngineError>
    where
        P: FactPerspective,
    {
        let facts = RefCell::new(facts);
        let sink = RefCell::new(sink);
        let io = RefCell::new(VmPolicyIO::new(&facts, &sink, &self.engine, &self.ffis));
        let mut rs = self.machine.create_run_state(&io, ctx);
        let self_data = Struct::new(name, fields);
        match rs.call_command_policy(&self_data.name, &self_data, envelope.clone().into()) {
            Ok(reason) => match reason {
                ExitReason::Normal => Ok(()),
                ExitReason::Yield => bug!("unexpected yield"),
                ExitReason::Check => {
                    info!("Check {}", self.source_location(&rs));
                    // Construct a new recall context from the policy context
                    let CommandContext::Policy(policy_ctx) = rs.get_context() else {
                        error!(
                            "Non-policy context while evaluating rule: {:?}",
                            rs.get_context()
                        );
                        return Err(EngineError::InternalError);
                    };
                    let recall_ctx = CommandContext::Recall(policy_ctx.clone());
                    rs.set_context(recall_ctx);
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
        envelope: Envelope<'_>,
    ) -> Result<(), EngineError>
    where
        M: MachineIO<MachineStack>,
    {
        match recall {
            CommandRecall::None => Err(EngineError::Check),
            CommandRecall::OnCheck => {
                match rs.call_command_recall(name, self_data, envelope.into()) {
                    Ok(ExitReason::Normal) => Err(EngineError::Check),
                    Ok(ExitReason::Yield) => bug!("unexpected yield"),
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
        envelope: Envelope<'_>,
        facts: &mut P,
    ) -> Result<Struct, EngineError>
    where
        P: FactPerspective,
    {
        let facts = RefCell::new(facts);
        let mut sink = NullSink;
        let sink2 = RefCell::new(&mut sink);
        let io = RefCell::new(VmPolicyIO::new(&facts, &sink2, &self.engine, &self.ffis));
        let ctx = CommandContext::Open(OpenContext { name });
        let mut rs = self.machine.create_run_state(&io, ctx);
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
                ExitReason::Yield => bug!("unexpected yield"),
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmAction<'a> {
    /// The name of the action.
    pub name: &'a str,
    /// The arguments of the action.
    pub args: Cow<'a, [Value]>,
}

/// A partial version of [`VmEffect`] containing only the data. Created by
/// [`vm_effect!`] and used to compare only the name and fields against the full
/// `VmEffect`.
#[derive(Debug)]
pub struct VmEffectData {
    /// The name of the effect.
    pub name: String,
    /// The fields of the effect.
    pub fields: Vec<KVPair>,
}

impl PartialEq<VmEffect> for VmEffectData {
    fn eq(&self, other: &VmEffect) -> bool {
        self.name == other.name && self.fields == other.fields
    }
}

impl PartialEq<VmEffectData> for VmEffect {
    fn eq(&self, other: &VmEffectData) -> bool {
        self.name == other.name && self.fields == other.fields
    }
}

/// [`VmPolicy`]'s effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmEffect {
    /// The name of the effect.
    pub name: String,
    /// The fields of the effect.
    pub fields: Vec<KVPair>,
    /// The command ID that produced this effect
    pub command: CommandId,
    /// Was this produced from a recall block?
    pub recalled: bool,
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum VmPriority {
    Basic(u32),
    Finalize,
}

impl Default for VmPriority {
    fn default() -> Self {
        Self::Basic(0)
    }
}

impl From<VmPriority> for Priority {
    fn from(value: VmPriority) -> Self {
        match value {
            VmPriority::Basic(p) => Self::Basic(p),
            VmPriority::Finalize => Self::Finalize,
        }
    }
}

impl<E> VmPolicy<E> {
    fn get_command_priority(&self, name: &str) -> VmPriority {
        debug_assert!(self.machine.command_defs.contains_key(name));
        self.priority_map.get(name).copied().unwrap_or_default()
    }
}

impl<E: aranya_crypto::Engine> Policy for VmPolicy<E> {
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
        let unpacked: VmProtocolData<'_> = postcard::from_bytes(command.bytes()).map_err(|e| {
            error!("Could not deserialize: {e:?}");
            EngineError::Read
        })?;
        let (command_info, expected_priority) = {
            match unpacked {
                VmProtocolData::Init {
                    author_id,
                    kind,
                    serialized_fields,
                    signature,
                    ..
                } => (
                    Some((
                        Envelope {
                            parent_id: CommandId::default(),
                            author_id,
                            command_id: command.id(),
                            payload: Cow::Borrowed(serialized_fields),
                            signature: Cow::Borrowed(signature),
                        },
                        kind,
                        author_id,
                    )),
                    Priority::Init,
                ),
                VmProtocolData::Basic {
                    parent,
                    kind,
                    author_id,
                    serialized_fields,
                    signature,
                } => (
                    Some((
                        Envelope {
                            parent_id: parent.id,
                            author_id,
                            command_id: command.id(),
                            payload: Cow::Borrowed(serialized_fields),
                            signature: Cow::Borrowed(signature),
                        },
                        kind,
                        author_id,
                    )),
                    self.get_command_priority(kind).into(),
                ),
                // Merges always pass because they're an artifact of the graph
                _ => (None, Priority::Merge),
            }
        };

        if command.priority() != expected_priority {
            error!(
                "Expected priority {:?}, got {:?}",
                expected_priority,
                command.priority()
            );
            bug!("Command has invalid priority");
        }

        if let Some((envelope, kind, author_id)) = command_info {
            let command_struct = self.open_command(kind, envelope.clone(), facts)?;
            let fields: Vec<KVPair> = command_struct
                .fields
                .into_iter()
                .map(|(k, v)| KVPair::new(&k, v))
                .collect();
            let ctx = CommandContext::Policy(PolicyContext {
                name: kind,
                id: command.id().into(),
                author: author_id,
                version: CommandId::default().into(),
            });
            self.evaluate_rule(kind, fields.as_slice(), envelope, facts, sink, ctx, recall)?
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

        let parent = match facts.head_address()? {
            Prior::None => None,
            Prior::Single(id) => Some(id),
            Prior::Merge(_, _) => bug!("cannot have a merge parent in call_action"),
        };
        // FIXME(chip): This is kind of wrong, but it avoids having to
        // plumb Option<Id> into the VM and FFI
        let ctx_parent = parent.unwrap_or_default();
        let facts = Rc::new(RefCell::new(facts));
        let sink = Rc::new(RefCell::new(sink));
        let io = RefCell::new(VmPolicyIO::new(&facts, &sink, &self.engine, &self.ffis));
        let ctx = CommandContext::Action(ActionContext {
            name,
            head_id: ctx_parent.id.into(),
        });
        {
            let mut rs = self.machine.create_run_state(&io, ctx);
            let mut exit_reason = match args {
                Cow::Borrowed(args) => rs.call_action(name, args.iter().cloned()),
                Cow::Owned(args) => rs.call_action(name, args),
            }
            .map_err(|e| {
                error!("\n{e}");
                EngineError::InternalError
            })?;
            loop {
                match exit_reason {
                    ExitReason::Normal => {
                        // Action completed
                        break;
                    }
                    ExitReason::Yield => {
                        // Command was published.
                        let command_struct: Struct = rs.stack.pop().map_err(|e| {
                            error!("should have command struct: {e}");
                            EngineError::InternalError
                        })?;

                        let fields = command_struct
                            .fields
                            .iter()
                            .map(|(k, v)| KVPair::new(k, v.clone()));
                        io.try_borrow_mut()
                            .assume("should be able to borrow io")?
                            .publish(command_struct.name.clone(), fields);

                        let seal_ctx = rs.get_context().seal_from_action(&command_struct.name)?;
                        let mut rs_seal = self.machine.create_run_state(&io, seal_ctx);
                        match rs_seal
                            .call_seal(&command_struct.name, &command_struct)
                            .map_err(|e| {
                                error!("Cannot seal command: {}", e);
                                EngineError::Panic
                            })? {
                            ExitReason::Normal => (),
                            r @ ExitReason::Yield
                            | r @ ExitReason::Check
                            | r @ ExitReason::Panic => {
                                error!("Could not seal command: {}", r);
                                return Err(EngineError::Panic);
                            }
                        }

                        // Grab sealed envelope from stack
                        let envelope_struct: Struct = rs_seal.stack.pop().map_err(|e| {
                            error!("Expected a sealed envelope {e}");
                            EngineError::InternalError
                        })?;
                        let envelope = Envelope::try_from(envelope_struct).map_err(|e| {
                            error!("Malformed envelope: {e}");
                            EngineError::InternalError
                        })?;

                        // The parent of a basic command should be the command that was added to the perspective on the previous
                        // iteration of the loop
                        let parent = match RefCell::borrow_mut(Rc::borrow(&facts)).head_address()? {
                            Prior::None => None,
                            Prior::Single(id) => Some(id),
                            Prior::Merge(_, _) => bug!("cannot have a merge parent in call_action"),
                        };

                        let priority = if parent.is_some() {
                            self.get_command_priority(command_struct.name.as_str())
                                .into()
                        } else {
                            Priority::Init
                        };

                        let data = match parent {
                            None => VmProtocolData::Init {
                                // TODO(chip): where does the policy value come from?
                                policy: 0u64.to_le_bytes(),
                                author_id: envelope.author_id,
                                kind: &command_struct.name,
                                serialized_fields: &envelope.payload,
                                signature: &envelope.signature,
                            },
                            Some(parent) => VmProtocolData::Basic {
                                author_id: envelope.author_id,
                                parent,
                                kind: &command_struct.name,
                                serialized_fields: &envelope.payload,
                                signature: &envelope.signature,
                            },
                        };
                        let wrapped = postcard::to_allocvec(&data)?;
                        let new_command =
                            VmProtocol::new(&wrapped, envelope.command_id, data, priority);

                        self.call_rule(
                            &new_command,
                            *RefCell::borrow_mut(Rc::borrow(&facts)),
                            *RefCell::borrow_mut(Rc::borrow(&sink)),
                            CommandRecall::None,
                        )?;
                        RefCell::borrow_mut(Rc::borrow(&facts))
                            .add_command(&new_command)
                            .map_err(|e| {
                                error!("{e}");
                                EngineError::Write
                            })?;

                        // After publishing a new command, the RunState's context must be updated to reflect the new head
                        rs.update_context_with_new_head(new_command.id().into())?;

                        // Resume action after last Publish
                        exit_reason = rs.run().map_err(|e| {
                            error!("{e}");
                            EngineError::InternalError
                        })?;
                    }
                    ExitReason::Check => {
                        info!("Check {}", self.source_location(&rs));
                        return Err(EngineError::Check);
                    }
                    ExitReason::Panic => {
                        info!("Panicked {}", self.source_location(&rs));
                        return Err(EngineError::Panic);
                    }
                };
            }
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
        Ok(VmProtocol::new(data, id, c, Priority::Merge))
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

#[cfg(test)]
mod test {
    use alloc::{format, string::String};

    use aranya_policy_compiler::Compiler;
    use aranya_policy_lang::lang::parse_policy_str;
    use aranya_policy_vm::ast::Version;

    use super::*;

    #[test]
    fn test_get_command_priorities() {
        fn process(attrs: &str) -> Result<Option<VmPriority>, String> {
            let policy = format!(
                r#"
                command Test {{
                    attributes {{
                        {attrs}
                    }}
                    fields {{ }}
                    seal {{ return None }}
                    open {{ return None }}
                    policy {{ }}
                }}
                "#
            );
            let ast = parse_policy_str(&policy, Version::V2).unwrap_or_else(|e| panic!("{e}"));
            let module = Compiler::new(&ast)
                .compile()
                .unwrap_or_else(|e| panic!("{e}"));
            let machine = Machine::from_module(module).expect("can create machine");
            let priorities = get_command_priorities(&machine).map_err(|e| match e {
                VmPolicyError::InvalidAttribute(msg) => msg,
                _ => panic!("unexpected error: {e}"),
            })?;
            Ok(priorities.get("Test").copied())
        }

        assert_eq!(process(""), Ok(None));
        assert_eq!(process("finalize: false"), Ok(None));

        assert_eq!(process("priority: 42"), Ok(Some(VmPriority::Basic(42))));
        assert_eq!(
            process("finalize: false, priority: 42"),
            Ok(Some(VmPriority::Basic(42)))
        );
        assert_eq!(
            process("priority: 42, finalize: false"),
            Ok(Some(VmPriority::Basic(42)))
        );

        assert_eq!(process("finalize: true"), Ok(Some(VmPriority::Finalize)));

        assert_eq!(
            process("finalize: 42"),
            Err("Test::finalize should be Bool, was Int".into())
        );
        assert_eq!(
            process("priority: false"),
            Err("Test::priority should be Int, was Bool".into())
        );
        assert_eq!(
            process("priority: -1"),
            Err("Test::priority value must be within [0, 2^32-1]".into())
        );
        assert_eq!(
            process(&format!("priority: {}", i64::MAX)),
            Err("Test::priority value must be within [0, 2^32-1]".into())
        );
        assert_eq!(
            process("finalize: true, priority: 42"),
            Err("Test has both finalize and priority set".into())
        )
    }
}
