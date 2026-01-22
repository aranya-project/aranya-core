//! VmPolicy implements a [Policy] that evaluates actions and commands via the [Policy
//! VM](../../policy_vm/index.html).
//!
//! ## Creating a `VmPolicy` instance
//!
//! To use `VmPolicy` in your [`PolicyStore`](super::PolicyStore), you need to provide a Policy VM
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
//! let policy_store = MyPolicyStore::new();
//! let provider = MyStorageProvider::new();
//! let mut cs = ClientState::new(policy_store, provider);
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

use alloc::{borrow::Cow, boxed::Box, collections::BTreeMap, rc::Rc, string::String, vec::Vec};
use core::{borrow::Borrow as _, cell::RefCell, fmt};

use aranya_crypto::BaseId;
use aranya_policy_vm::{
    ActionContext, CommandContext, CommandDef, ExitReason, KVPair, Machine, MachineIO,
    MachineStack, OpenContext, PolicyContext, RunState, Stack as _, Struct, Value,
    ast::{Identifier, Persistence},
};
use buggy::{BugExt as _, bug};
use spin::Mutex;
use tracing::{error, info, instrument};

use crate::{
    ActionPlacement, Address, CommandPlacement, FactPerspective, MergeIds, Perspective, Prior,
    Priority,
    command::{CmdId, Command},
    policy::{NullSink, Policy, PolicyError, Sink},
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
/// let y = text!("asdf");
/// client.action(storage_id, sink, vm_action!(foobar(x, y)))
/// ```
#[macro_export]
macro_rules! vm_action {
    ($name:ident($($arg:expr),* $(,)?)) => {
        $crate::VmAction {
            name: ::aranya_policy_vm::ident!(stringify!($name)),
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
            name: ::aranya_policy_vm::ident!(stringify!($name)),
            fields: vec![$(
                ::aranya_policy_vm::KVPair::new(::aranya_policy_vm::ident!(stringify!($field)), $val.into())
            ),*],
        }
    };
}

/// A [Policy] implementation that uses the Policy VM.
pub struct VmPolicy<CE> {
    machine: Machine,
    engine: Mutex<CE>,
    ffis: Vec<Box<dyn FfiCallable<CE> + Send + 'static>>,
    priority_map: BTreeMap<Identifier, VmPriority>,
}

impl<CE> VmPolicy<CE> {
    /// Create a new `VmPolicy` from a [Machine]
    pub fn new(
        machine: Machine,
        engine: CE,
        ffis: Vec<Box<dyn FfiCallable<CE> + Send + 'static>>,
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
) -> Result<BTreeMap<Identifier, VmPriority>, AttributeError> {
    let mut priority_map = BTreeMap::new();
    for def in machine.command_defs.iter() {
        let name = &def.name.name;
        let attrs = PriorityAttrs::load(name.as_str(), def)?;
        match def.persistence {
            Persistence::Persistent => {
                priority_map.insert(name.clone(), get_command_priority(name, &attrs)?);
            }
            Persistence::Ephemeral { .. } => {
                if attrs != PriorityAttrs::default() {
                    return Err(AttributeError(
                        "ephemeral command must not have priority".into(),
                    ));
                }
            }
        }
    }
    Ok(priority_map)
}

#[derive(Default, PartialEq)]
struct PriorityAttrs {
    init: bool,
    finalize: bool,
    priority: Option<u32>,
}

impl PriorityAttrs {
    fn load(name: &str, def: &CommandDef) -> Result<Self, AttributeError> {
        let attrs = &def.attributes;
        let init = attrs
            .get("init")
            .map(|attr| match attr.value {
                Value::Bool(b) => Ok(b),
                _ => Err(AttributeError::type_mismatch(
                    name,
                    "finalize",
                    "Bool",
                    &attr.value.type_name(),
                )),
            })
            .transpose()?
            == Some(true);
        let finalize = attrs
            .get("finalize")
            .map(|attr| match attr.value {
                Value::Bool(b) => Ok(b),
                _ => Err(AttributeError::type_mismatch(
                    name,
                    "finalize",
                    "Bool",
                    &attr.value.type_name(),
                )),
            })
            .transpose()?
            == Some(true);
        let priority: Option<u32> = attrs
            .get("priority")
            .map(|attr| match attr.value {
                Value::Int(b) => b.try_into().map_err(|_| {
                    AttributeError::int_range(name, "priority", u32::MIN.into(), u32::MAX.into())
                }),
                _ => Err(AttributeError::type_mismatch(
                    name,
                    "priority",
                    "Int",
                    &attr.value.type_name(),
                )),
            })
            .transpose()?;
        Ok(Self {
            init,
            finalize,
            priority,
        })
    }
}

fn get_command_priority(
    name: &Identifier,
    attrs: &PriorityAttrs,
) -> Result<VmPriority, AttributeError> {
    match (attrs.init, attrs.finalize, attrs.priority) {
        (true, true, _) => Err(AttributeError::exclusive(name.as_str(), "init", "finalize")),
        (true, false, Some(_)) => Err(AttributeError::exclusive(name.as_str(), "init", "priority")),
        (true, false, None) => Ok(VmPriority::Init),

        (false, true, Some(_)) => Err(AttributeError::exclusive(
            name.as_str(),
            "finalize",
            "priority",
        )),
        (false, true, None) => Ok(VmPriority::Finalize),

        (false, false, Some(n)) => Ok(VmPriority::Basic(n)),

        (false, false, None) => Err(AttributeError::missing(
            name.as_str(),
            "init | finalize | priority",
        )),
    }
}

impl<CE: aranya_crypto::Engine> VmPolicy<CE> {
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip_all, fields(name = name.as_str()))]
    fn evaluate_rule<'a, P>(
        &self,
        name: Identifier,
        fields: &[KVPair],
        envelope: Envelope<'_>,
        facts: &'a mut P,
        sink: &'a mut impl Sink<VmEffect>,
        ctx: CommandContext,
        placement: CommandPlacement,
    ) -> Result<(), PolicyError>
    where
        P: FactPerspective,
    {
        let facts = RefCell::new(facts);
        let sink = RefCell::new(sink);
        let io = RefCell::new(VmPolicyIO::new(&facts, &sink, &self.engine, &self.ffis));
        let mut rs = self.machine.create_run_state(&io, ctx);
        let this_data = Struct::new(name, fields);
        match rs.call_command_policy(this_data.clone(), envelope.clone().into()) {
            Ok(reason) => match reason {
                ExitReason::Normal => Ok(()),
                ExitReason::Yield => bug!("unexpected yield"),
                ExitReason::Check => {
                    info!("Check {}", self.source_location(&rs));

                    match placement {
                        CommandPlacement::OnGraphAtOrigin | CommandPlacement::OffGraph => {
                            // Immediate check failure.
                            return Err(PolicyError::Check);
                        }
                        CommandPlacement::OnGraphInBraid => {
                            // Perform recall.
                        }
                    }

                    // Construct a new recall context from the policy context
                    let CommandContext::Policy(policy_ctx) = rs.get_context() else {
                        error!(
                            "Non-policy context while evaluating rule: {:?}",
                            rs.get_context()
                        );
                        return Err(PolicyError::InternalError);
                    };
                    let recall_ctx = CommandContext::Recall(policy_ctx.clone());
                    rs.set_context(recall_ctx);
                    self.recall_internal(&mut rs, this_data, envelope)
                }
                ExitReason::Panic => {
                    info!("Panicked {}", self.source_location(&rs));
                    Err(PolicyError::Panic)
                }
            },
            Err(e) => {
                error!("\n{e}");
                Err(PolicyError::InternalError)
            }
        }
    }

    fn recall_internal<M>(
        &self,
        rs: &mut RunState<'_, M>,
        this_data: Struct,
        envelope: Envelope<'_>,
    ) -> Result<(), PolicyError>
    where
        M: MachineIO<MachineStack>,
    {
        match rs.call_command_recall(this_data, envelope.into()) {
            Ok(ExitReason::Normal) => Err(PolicyError::Check),
            Ok(ExitReason::Yield) => bug!("unexpected yield"),
            Ok(ExitReason::Check) => {
                info!("Recall failed: {}", self.source_location(rs));
                Err(PolicyError::Check)
            }
            Ok(ExitReason::Panic) | Err(_) => {
                info!("Recall panicked: {}", self.source_location(rs));
                Err(PolicyError::Panic)
            }
        }
    }

    #[instrument(skip_all, fields(name = name.as_str()))]
    fn open_command<P>(
        &self,
        name: Identifier,
        envelope: Envelope<'_>,
        facts: &mut P,
    ) -> Result<Struct, PolicyError>
    where
        P: FactPerspective,
    {
        let facts = RefCell::new(facts);
        let mut sink = NullSink;
        let sink2 = RefCell::new(&mut sink);
        let io = RefCell::new(VmPolicyIO::new(&facts, &sink2, &self.engine, &self.ffis));
        let ctx = CommandContext::Open(OpenContext { name: name.clone() });
        let mut rs = self.machine.create_run_state(&io, ctx);
        let status = rs.call_open(name, envelope.into());
        match status {
            Ok(reason) => match reason {
                ExitReason::Normal => {
                    let v = rs.consume_return().map_err(|e| {
                        error!("Could not pull envelope from stack: {e}");
                        PolicyError::InternalError
                    })?;
                    Ok(v.try_into().map_err(|e| {
                        error!("Envelope is not a struct: {e}");
                        PolicyError::InternalError
                    })?)
                }
                ExitReason::Yield => bug!("unexpected yield"),
                ExitReason::Check => {
                    info!("Check {}", self.source_location(&rs));
                    Err(PolicyError::Check)
                }
                ExitReason::Panic => {
                    info!("Panicked {}", self.source_location(&rs));
                    Err(PolicyError::Check)
                }
            },
            Err(e) => {
                error!("\n{e}");
                Err(PolicyError::InternalError)
            }
        }
    }
}

/// [`VmPolicy`]'s actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmAction<'a> {
    /// The name of the action.
    pub name: Identifier,
    /// The arguments of the action.
    pub args: Cow<'a, [Value]>,
}

/// A partial version of [`VmEffect`] containing only the data. Created by
/// [`vm_effect!`] and used to compare only the name and fields against the full
/// `VmEffect`.
#[derive(Debug)]
pub struct VmEffectData {
    /// The name of the effect.
    pub name: Identifier,
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
    pub name: Identifier,
    /// The fields of the effect.
    pub fields: Vec<KVPair>,
    /// The command ID that produced this effect
    pub command: CmdId,
    /// Was this produced from a recall block?
    pub recalled: bool,
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum VmPriority {
    Init,
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
            VmPriority::Init => Self::Init,
            VmPriority::Basic(p) => Self::Basic(p),
            VmPriority::Finalize => Self::Finalize,
        }
    }
}

impl<CE> VmPolicy<CE> {
    fn get_command_priority(&self, name: &Identifier) -> VmPriority {
        debug_assert!(self.machine.command_defs.contains(name));
        self.priority_map.get(name).copied().unwrap_or_default()
    }
}

impl<CE: aranya_crypto::Engine> Policy for VmPolicy<CE> {
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
        placement: CommandPlacement,
    ) -> Result<(), PolicyError> {
        let parent_id = match command.parent() {
            Prior::None => CmdId::default(),
            Prior::Single(parent) => parent.id,
            Prior::Merge(_, _) => bug!("merge commands are not evaluated"),
        };

        let VmProtocolData {
            author_id,
            kind,
            serialized_fields,
            signature,
        } = postcard::from_bytes(command.bytes()).map_err(|e| {
            error!("Could not deserialize: {e:?}");
            PolicyError::Read
        })?;

        let expected_priority = self.get_command_priority(&kind).into();
        if command.priority() != expected_priority {
            error!(
                "Expected priority {:?}, got {:?}",
                expected_priority,
                command.priority()
            );
            bug!("Command has invalid priority");
        }

        let def = self.machine.command_defs.get(&kind).ok_or_else(|| {
            error!("unknown command {kind}");
            PolicyError::InternalError
        })?;

        let envelope = Envelope {
            parent_id,
            author_id,
            command_id: command.id(),
            payload: Cow::Borrowed(serialized_fields),
            signature: Cow::Borrowed(signature),
        };

        match (placement, &def.persistence) {
            (CommandPlacement::OnGraphAtOrigin, Persistence::Persistent) => {}
            (CommandPlacement::OnGraphInBraid, Persistence::Persistent) => {}
            (CommandPlacement::OffGraph, Persistence::Ephemeral(_)) => {}
            (CommandPlacement::OnGraphAtOrigin, Persistence::Ephemeral(_)) => {
                error!("cannot evaluate ephemeral command on-graph");
                return Err(PolicyError::InternalError);
            }
            (CommandPlacement::OnGraphInBraid, Persistence::Ephemeral(_)) => {
                error!("cannot evaluate ephemeral command in braid");
                return Err(PolicyError::InternalError);
            }
            (CommandPlacement::OffGraph, Persistence::Persistent) => {
                error!("cannot evaluate persistent command off-graph");
                return Err(PolicyError::InternalError);
            }
        }

        let command_struct = self.open_command(kind.clone(), envelope.clone(), facts)?;
        let fields: Vec<KVPair> = command_struct
            .fields
            .into_iter()
            .map(|(k, v)| KVPair::new(k, v))
            .collect();
        let ctx = CommandContext::Policy(PolicyContext {
            name: kind.clone(),
            id: command.id(),
            author: author_id,
            version: BaseId::default(),
        });
        self.evaluate_rule(
            kind,
            fields.as_slice(),
            envelope,
            facts,
            sink,
            ctx,
            placement,
        )?;

        Ok(())
    }

    #[instrument(skip_all, fields(name = action.name.as_str()))]
    fn call_action(
        &self,
        action: Self::Action<'_>,
        facts: &mut impl Perspective,
        sink: &mut impl Sink<Self::Effect>,
        action_placement: ActionPlacement,
    ) -> Result<(), PolicyError> {
        let VmAction { name, args } = action;

        let def = self.machine.action_defs.get(&name).ok_or_else(|| {
            error!("action not found");
            PolicyError::InternalError
        })?;

        match (action_placement, &def.persistence) {
            (ActionPlacement::OnGraph, Persistence::Persistent) => {}
            (ActionPlacement::OffGraph, Persistence::Ephemeral(_)) => {}
            (ActionPlacement::OnGraph, Persistence::Ephemeral(_)) => {
                error!("cannot call ephemeral action on-graph");
                return Err(PolicyError::InternalError);
            }
            (ActionPlacement::OffGraph, Persistence::Persistent) => {
                error!("cannot call persistent action off-graph");
                return Err(PolicyError::InternalError);
            }
        }

        let parent = match facts.head_address()? {
            Prior::None => None,
            Prior::Single(id) => Some(id),
            Prior::Merge(_, _) => bug!("cannot have a merge parent in call_action"),
        };
        // FIXME(chip): This is kind of wrong, but it avoids having to
        // plumb `Option<CmdId>` into the VM and FFI
        let ctx_parent = parent.unwrap_or_default();
        let facts = Rc::new(RefCell::new(facts));
        let sink = Rc::new(RefCell::new(sink));
        let io = RefCell::new(VmPolicyIO::new(&facts, &sink, &self.engine, &self.ffis));
        let ctx = CommandContext::Action(ActionContext {
            name: name.clone(),
            head_id: ctx_parent.id,
        });
        let command_placement = match action_placement {
            ActionPlacement::OnGraph => CommandPlacement::OnGraphAtOrigin,
            ActionPlacement::OffGraph => CommandPlacement::OffGraph,
        };
        {
            let mut rs = self.machine.create_run_state(&io, ctx);
            let mut exit_reason = match args {
                Cow::Borrowed(args) => rs.call_action(name, args.iter().cloned()),
                Cow::Owned(args) => rs.call_action(name, args),
            }
            .map_err(|e| {
                error!("\n{e}");
                PolicyError::InternalError
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
                            PolicyError::InternalError
                        })?;
                        let command_name = command_struct.name.clone();

                        let seal_ctx = rs.get_context().seal_from_action(command_name.clone())?;
                        let mut rs_seal = self.machine.create_run_state(&io, seal_ctx);
                        match rs_seal.call_seal(command_struct).map_err(|e| {
                            error!("Cannot seal command: {}", e);
                            PolicyError::Panic
                        })? {
                            ExitReason::Normal => (),
                            r @ (ExitReason::Yield | ExitReason::Check | ExitReason::Panic) => {
                                error!("Could not seal command: {}", r);
                                return Err(PolicyError::Panic);
                            }
                        }

                        // Grab sealed envelope from stack
                        let envelope_struct: Struct = rs_seal.stack.pop().map_err(|e| {
                            error!("Expected a sealed envelope {e}");
                            PolicyError::InternalError
                        })?;
                        let envelope = Envelope::try_from(envelope_struct).map_err(|e| {
                            error!("Malformed envelope: {e}");
                            PolicyError::InternalError
                        })?;

                        // The parent of a basic command should be the command that was added to the perspective on the previous
                        // iteration of the loop
                        let parent = RefCell::borrow_mut(Rc::borrow(&facts)).head_address()?;
                        let priority = self.get_command_priority(&command_name).into();

                        let policy;
                        match parent {
                            Prior::None => {
                                // TODO(chip): where does the policy value come from?
                                policy = Some(0u64.to_le_bytes());
                                if !matches!(priority, Priority::Init) {
                                    error!(
                                        "Command {command_name} has invalid priority {priority:?}"
                                    );
                                    return Err(PolicyError::InternalError);
                                }
                            }
                            Prior::Single(_) => {
                                policy = None;
                                if !matches!(priority, Priority::Basic(_) | Priority::Finalize) {
                                    error!(
                                        "Command {command_name} has invalid priority {priority:?}"
                                    );
                                    return Err(PolicyError::InternalError);
                                }
                            }
                            Prior::Merge(_, _) => bug!("cannot have a merge parent in call_action"),
                        }

                        let data = VmProtocolData {
                            author_id: envelope.author_id,
                            kind: command_name.clone(),
                            serialized_fields: &envelope.payload,
                            signature: &envelope.signature,
                        };

                        let wrapped = postcard::to_allocvec(&data)
                            .assume("can serialize vm protocol data")?;

                        let new_command = VmProtocol {
                            id: envelope.command_id,
                            priority,
                            parent,
                            policy,
                            data: &wrapped,
                        };

                        self.call_rule(
                            &new_command,
                            *RefCell::borrow_mut(Rc::borrow(&facts)),
                            *RefCell::borrow_mut(Rc::borrow(&sink)),
                            command_placement,
                        )?;
                        RefCell::borrow_mut(Rc::borrow(&facts))
                            .add_command(&new_command)
                            .map_err(|e| {
                                error!("{e}");
                                PolicyError::Write
                            })?;

                        // After publishing a new command, the RunState's context must be updated to reflect the new head
                        rs.update_context_with_new_head(new_command.id())?;

                        // Resume action after last Publish
                        exit_reason = rs.run().map_err(|e| {
                            error!("{e}");
                            PolicyError::InternalError
                        })?;
                    }
                    ExitReason::Check => {
                        info!("Check {}", self.source_location(&rs));
                        return Err(PolicyError::Check);
                    }
                    ExitReason::Panic => {
                        info!("Panicked {}", self.source_location(&rs));
                        return Err(PolicyError::Panic);
                    }
                }
            }
        }

        Ok(())
    }

    fn merge<'a>(
        &self,
        _target: &'a mut [u8],
        ids: MergeIds,
    ) -> Result<Self::Command<'a>, PolicyError> {
        let (left, right): (Address, Address) = ids.into();
        let id = aranya_crypto::merge_cmd_id::<CE::CS>(left.id, right.id);
        Ok(VmProtocol {
            id,
            priority: Priority::Merge,
            parent: Prior::Merge(left, right),
            policy: None,
            data: &[],
        })
    }
}

impl fmt::Display for VmAction<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_tuple(self.name.as_str());
        for arg in self.args.as_ref() {
            d.field(&DebugViaDisplay(arg));
        }
        d.finish()
    }
}

impl fmt::Display for VmEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct(self.name.as_str());
        for field in &self.fields {
            d.field(field.key().as_str(), &DebugViaDisplay(field.value()));
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
    use alloc::format;

    use aranya_policy_compiler::Compiler;
    use aranya_policy_lang::lang::parse_policy_str;
    use aranya_policy_vm::ast::Version;

    use super::*;

    #[test]
    fn test_require_command_priority() {
        let cases = [
            r#"command Test {
                fields {}
                seal { return todo() }
                open { return todo() }
                policy {}
            }"#,
            r#"command Test {
                attributes {}
                fields {}
                seal { return todo() }
                open { return todo() }
                policy {}
            }"#,
            r#"command Test {
                attributes {
                    init: false,
                    finalize: false,
                }
                fields {}
                seal { return todo() }
                open { return todo() }
                policy {}
            }"#,
        ];

        for case in cases {
            let ast = parse_policy_str(case, Version::V2).unwrap_or_else(|e| panic!("{e}"));
            let module = Compiler::new(&ast)
                .compile()
                .unwrap_or_else(|e| panic!("{e}"));
            let machine = Machine::from_module(module).expect("can create machine");
            let err = get_command_priorities(&machine).expect_err("should fail");
            assert_eq!(
                err,
                AttributeError::missing("Test", "init | finalize | priority")
            );
        }
    }

    #[test]
    fn test_get_command_priorities() {
        fn process(attrs: &str) -> Result<VmPriority, AttributeError> {
            let policy = format!(
                r#"
                command Test {{
                    attributes {{
                        {attrs}
                    }}
                    fields {{ }}
                    seal {{ return todo() }}
                    open {{ return todo() }}
                    policy {{ }}
                }}
                "#
            );
            let ast = parse_policy_str(&policy, Version::V2).unwrap_or_else(|e| panic!("{e}"));
            let module = Compiler::new(&ast)
                .compile()
                .unwrap_or_else(|e| panic!("{e}"));
            let machine = Machine::from_module(module).expect("can create machine");
            let priorities = get_command_priorities(&machine)?;
            Ok(*priorities.get("Test").expect("priorities are mandatory"))
        }

        assert_eq!(process("priority: 42"), Ok(VmPriority::Basic(42)));
        assert_eq!(
            process("finalize: false, priority: 42"),
            Ok(VmPriority::Basic(42))
        );
        assert_eq!(
            process("init: false, priority: 42, finalize: false"),
            Ok(VmPriority::Basic(42))
        );

        assert_eq!(process("init: true"), Ok(VmPriority::Init));
        assert_eq!(process("finalize: true"), Ok(VmPriority::Finalize));

        assert_eq!(
            process("finalize: 42"),
            Err(AttributeError::type_mismatch(
                "Test", "finalize", "Bool", "Int"
            ))
        );
        assert_eq!(
            process("priority: false"),
            Err(AttributeError::type_mismatch(
                "Test", "priority", "Int", "Bool"
            ))
        );
        assert_eq!(
            process("priority: -1"),
            Err(AttributeError::int_range(
                "Test",
                "priority",
                u32::MIN.into(),
                u32::MAX.into(),
            ))
        );
        assert_eq!(
            process(&format!("priority: {}", i64::MAX)),
            Err(AttributeError::int_range(
                "Test",
                "priority",
                u32::MIN.into(),
                u32::MAX.into(),
            ))
        );

        assert_eq!(
            process("finalize: true, priority: 42"),
            Err(AttributeError::exclusive("Test", "finalize", "priority"))
        );
        assert_eq!(
            process("init: true, priority: 42"),
            Err(AttributeError::exclusive("Test", "init", "priority"))
        );
        assert_eq!(
            process("init: true, finalize: true"),
            Err(AttributeError::exclusive("Test", "init", "finalize"))
        );
    }
}
