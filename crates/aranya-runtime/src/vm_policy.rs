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
//!     device: DeviceId::random(Rng),
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
//!     policy {
//!         finish {}
//!     }
//! }
//!
//! action init(nonce int) {
//!     publish Init { nonce }
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
//! let graph_id = cs
//!     .new_graph(&[0u8], vm_action!(init(0)), &mut sink)
//!     .expect("could not create graph");
//! ```
//!
//! Because the ID of this initial command is also the ID of the resulting graph,
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

use alloc::{borrow::Cow, boxed::Box, collections::BTreeMap, string::String, vec::Vec};
use core::fmt;

use aranya_policy_vm::{
    ActionContext, CommandContext, CommandDef, ConstValue, ExitReason, KVPair, Machine, MachineIO,
    MachineStack, PolicyContext, RunState, Stack as _, Struct, Value, ast::Identifier,
    ffi_contract_validate,
};
use buggy::{BugExt as _, bug};
use tracing::{error, info, instrument};

use crate::{
    ActionPlacement, Address, CommandPlacement, FactPerspective, MergeIds, NullSink, Perspective,
    Prior, Priority,
    command::{CmdId, Command},
    policy::{Policy, PolicyError, Sink},
};

mod error;
mod io;
mod protocol;
mod seal_open;

pub use error::*;
pub use io::*;
pub use protocol::*;
pub use seal_open::SealCtx;

pub static FLAVORS: aranya_policy_module::flavor::Flavors<'static> = {
    use aranya_policy_module::{
        arg,
        flavor::{Flavor, Flavors, Struct},
    };
    use aranya_policy_vm::ident;
    Flavors {
        default: Flavor {
            envelope: Struct {
                name: ident!("DefaultEnvelope"),
                fields: &[
                    arg!("command_id", Id),
                    arg!("parent_id", Id),
                    arg!("author_id", Id),
                ],
            },
        },
        flavors: &[
            (
                ident!("init"),
                Flavor {
                    envelope: Struct {
                        name: ident!("InitEnvelope"),
                        fields: &[
                            arg!("command_id", Id),
                            // no parent_id
                            arg!("author_id", Id),
                        ],
                    },
                },
            ),
            (
                ident!("ephemeral"),
                Flavor {
                    envelope: Struct {
                        name: ident!("EphemeralEnvelope"),
                        fields: &[
                            arg!("command_id", Id),
                            arg!("graph_id", Id),
                            arg!("author_id", Id),
                        ],
                    },
                },
            ),
        ],
    }
};

/// Creates a [`VmAction`].
///
/// This must be used directly to avoid lifetime issues, not assigned to a variable.
///
/// # Example
///
/// ```ignore
/// let x = 42;
/// let y = text!("asdf");
/// client.action(graph_id, sink, vm_action!(foobar(x, y)))
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
/// client.action(graph_id, sink, vm_action!(create(val)))
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
    engine: CE,
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
        if let Some(module_ffis) = &machine.ffis {
            ffi_contract_validate(module_ffis, ffis.iter().map(|m| m.schema()))?;
        } else {
            tracing::warn!("Module does not have contract; cannot validate FFI");
        }
        let priority_map = get_command_priorities(&machine)?;
        Ok(Self {
            machine,
            engine,
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
    machine
        .command_defs
        .iter()
        .map(|def| {
            let priority = get_command_priority(def)?;
            Ok((def.name.clone(), priority))
        })
        .collect()
}

/// Get the priority for one command from flavor and attributes.
fn get_command_priority(def: &CommandDef) -> Result<VmPriority, AttributeError> {
    Ok(match &def.flavor {
        None => VmPriority::Basic(load_priority(def)?),
        Some(flavor) => {
            if def.attributes.iter().any(|a| a.name == "priority") {
                return Err(AttributeError::should_not_have(
                    flavor.as_str(),
                    def.name.as_str(),
                    "priority",
                ));
            }
            match flavor.as_str() {
                "ephemeral" => VmPriority::Ephemeral,
                "init" => VmPriority::Init,
                "finalize" => VmPriority::Finalize,
                _ => {
                    return Err(AttributeError::unknown_flavor(
                        flavor.as_str(),
                        def.name.as_str(),
                    ));
                }
            }
        }
    })
}

/// Read the priority attribute.
fn load_priority(def: &CommandDef) -> Result<u32, AttributeError> {
    let cmd_name = def.name.as_str();
    let attr_name = "priority";
    let attr = def
        .attributes
        .iter()
        .find(|a| a.name == attr_name)
        .ok_or_else(|| AttributeError::missing(cmd_name, attr_name))?;
    let ConstValue::Int(int) = attr.value else {
        return Err(AttributeError::type_mismatch(
            cmd_name,
            attr_name,
            "Int",
            &attr.value.type_name(),
        ));
    };
    u32::try_from(int).map_err(|_| {
        AttributeError::int_range(cmd_name, attr_name, u32::MIN.into(), u32::MAX.into())
    })
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
    ) -> Result<(), PolicyError>
    where
        P: FactPerspective,
    {
        let mut io = VmPolicyIO::new(facts, sink, &self.engine, &self.ffis);
        let mut rs = self.machine.create_run_state(&mut io, ctx);
        let this_data = Struct::new(name, fields);
        match rs.call_command_policy(this_data, envelope.into()) {
            Ok(reason) => match reason {
                ExitReason::Normal => Ok(()),
                ExitReason::Yield => bug!("unexpected yield"),
                ExitReason::Check => {
                    info!("Check: {}", self.source_location(&rs));
                    Err(PolicyError::Rejected)
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

    #[instrument(skip_all, fields(name = command_struct.name.as_str()))]
    fn seal_command(
        &self,
        command_struct: &Struct,
        parent_id: CmdId,
        seal_ctx: &SealCtx<CE>,
    ) -> Result<(Vec<u8>, Envelope<'_>), PolicyError> {
        let payload = self.machine.serialize_struct(command_struct).map_err(|e| {
            error!(error = %e, "cannot serialize command");
            PolicyError::Write
        })?;

        let envelope = seal_open::seal_with_key(
            &seal_ctx.key,
            command_struct,
            &payload,
            seal_ctx.author,
            parent_id,
        )
        .map_err(|e| {
            error!(error = %e, "could not seal command");
            PolicyError::Panic
        })?;

        Ok((payload, envelope))
    }

    #[instrument(skip_all, fields(name = command_struct.name.as_str()))]
    fn open_command(
        &self,
        command_struct: &Struct,
        payload: &[u8],
        envelope: &Envelope<'_>,
        facts: &mut impl FactPerspective,
    ) -> Result<(), PolicyError> {
        let mut sink = NullSink;
        let mut io = VmPolicyIO::new(facts, &mut sink, &self.engine, &self.ffis);

        let (_, value) = self
            .machine
            .call_get_key(command_struct.clone(), envelope.author_id, &mut io)
            .map_err(|_| PolicyError::Panic)?;

        let key_bytes = value.ok_or(PolicyError::Panic)?;
        let key: aranya_crypto::VerifyingKey<CE::CS> =
            postcard::from_bytes(&key_bytes).map_err(|_| {
                tracing::warn!("could not deserialize open key");
                PolicyError::Panic
            })?;

        seal_open::open_with_key(key, command_struct, payload, envelope)
            .map_err(|_| PolicyError::Panic)
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
    Ephemeral,
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
            VmPriority::Ephemeral => Self::Basic(0), // ?
        }
    }
}

impl<CE> VmPolicy<CE> {
    fn get_command_priority(&self, name: &Identifier) -> Result<VmPriority, PolicyError> {
        self.priority_map.get(name).copied().ok_or_else(|| {
            error!("unknown command {name}");
            PolicyError::InternalError
        })
    }
}

impl<CE: aranya_crypto::Engine> Policy for VmPolicy<CE> {
    type Action<'a> = VmAction<'a>;
    type SealCtx = SealCtx<CE>;
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
    ) -> Result<Priority, PolicyError> {
        let parent_id = match command.parent() {
            Prior::None => CmdId::default(),
            Prior::Single(parent) => parent.id,
            Prior::Merge(_, _) => bug!("merge commands are not evaluated"),
        };

        let VmProtocolData {
            author_id,
            kind,
            serialized_fields: payload,
            signature,
        } = postcard::from_bytes(command.bytes()).map_err(|e| {
            error!("Could not deserialize: {e:?}");
            PolicyError::Read
        })?;

        let priority = self.get_command_priority(&kind)?;

        let def = self.machine.command_defs.get(&kind).ok_or_else(|| {
            error!("unknown command {kind}");
            PolicyError::InternalError
        })?;

        let envelope = Envelope {
            parent_id,
            author_id,
            command_id: command.id(),
            signature: Cow::Borrowed(signature),
        };

        let def_is_ephemeral = def.flavor.as_ref().is_some_and(|x| x == "ephemeral");

        match (placement, def_is_ephemeral) {
            (CommandPlacement::OnGraphAtOrigin, false) => {}
            (CommandPlacement::OnGraphInBraid, false) => {}
            (CommandPlacement::OffGraph, true) => {}
            (CommandPlacement::OnGraphAtOrigin, true) => {
                error!("cannot evaluate ephemeral command on-graph");
                return Err(PolicyError::InternalError);
            }
            (CommandPlacement::OnGraphInBraid, true) => {
                error!("cannot evaluate ephemeral command in braid");
                return Err(PolicyError::InternalError);
            }
            (CommandPlacement::OffGraph, false) => {
                error!("cannot evaluate persistent command off-graph");
                return Err(PolicyError::InternalError);
            }
        }

        let command_struct = self
            .machine
            .deserialize_struct(kind.clone(), payload)
            .map_err(|e| {
                error!(
                    error = %e,
                    "could not deserialize command during braid"
                );
                PolicyError::Read
            })?;

        match placement {
            CommandPlacement::OnGraphAtOrigin | CommandPlacement::OffGraph => {
                self.open_command(&command_struct, payload, &envelope, facts)?;
            }
            CommandPlacement::OnGraphInBraid => {
                // Bypass real open and just deserialize.
            }
        }

        let fields: Vec<KVPair> = command_struct
            .fields
            .into_iter()
            .map(|(k, v)| KVPair::new(k, v))
            .collect();
        let ctx = CommandContext::Policy(PolicyContext {
            name: kind.clone(),
            id: command.id(),
            author: author_id,
            version: aranya_crypto::BaseId::default(),
        });
        self.evaluate_rule(kind, fields.as_slice(), envelope, facts, sink, ctx)?;

        Ok(priority.into())
    }

    #[instrument(skip_all, fields(name = action.name.as_str()))]
    fn call_action(
        &self,
        action: Self::Action<'_>,
        facts: &mut impl Perspective,
        sink: &mut impl Sink<Self::Effect>,
        action_placement: ActionPlacement,
        seal_ctx: &SealCtx<CE>,
    ) -> Result<(), PolicyError> {
        let VmAction { name, args } = action;

        let def = self.machine.action_defs.get(&name).ok_or_else(|| {
            error!("action not found");
            PolicyError::InternalError
        })?;

        let def_is_ephemeral = def.flavor.as_ref().is_some_and(|x| x == "ephemeral");

        match (action_placement, def_is_ephemeral) {
            (ActionPlacement::OnGraph, false) => {}
            (ActionPlacement::OffGraph, true) => {}
            (ActionPlacement::OnGraph, true) => {
                error!("cannot call ephemeral action on-graph");
                return Err(PolicyError::InternalError);
            }
            (ActionPlacement::OffGraph, false) => {
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
        let ctx_parent = parent.map(|a| a.id).unwrap_or_default();
        let mut io = VmPolicyIO::new(facts, sink, &self.engine, &self.ffis);
        let ctx = CommandContext::Action(ActionContext {
            name: name.clone(),
            head_id: ctx_parent,
        });
        let command_placement = match action_placement {
            ActionPlacement::OnGraph => CommandPlacement::OnGraphAtOrigin,
            ActionPlacement::OffGraph => CommandPlacement::OffGraph,
        };
        {
            let mut rs = self.machine.create_run_state(&mut io, ctx);
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
                        // Action completed. A fallible action leaves its return
                        // value on the stack; an infallible action leaves nothing.
                        if def.is_fallible() {
                            let value = rs.stack.pop_value().map_err(|e| {
                                error!("expected action result value: {e}");
                                PolicyError::InternalError
                            })?;
                            // `Err(payload)` => the action failed;
                            // anything else (`Ok`/placeholder success) succeeds.
                            if let Value::Result(Err(payload)) = value {
                                info!(
                                    "action returned Err {}: {}",
                                    self.source_location(&rs),
                                    payload,
                                );
                                return Err(PolicyError::Rejected);
                            }
                        }
                        break;
                    }
                    ExitReason::Yield => {
                        // Command was published.
                        let command_struct: Struct = rs.stack.pop().map_err(|e| {
                            error!("should have command struct: {e}");
                            PolicyError::InternalError
                        })?;

                        let command_name = command_struct.name.clone();

                        // The parent of a basic command should be the command that was added to the perspective on the previous
                        // iteration of the loop
                        let parent = rs.io.facts.head_address()?;

                        let priority = self.get_command_priority(&command_name)?.into();

                        let parent_id;
                        let policy;
                        match parent {
                            Prior::None => {
                                parent_id = CmdId::default();
                                // TODO(chip): where does the policy value come from?
                                policy = Some(0u64.to_le_bytes());
                                if !matches!(priority, Priority::Init) {
                                    error!(
                                        "Command {command_name} has invalid priority {priority:?}"
                                    );
                                    return Err(PolicyError::InternalError);
                                }
                            }
                            Prior::Single(p) => {
                                parent_id = p.id;
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

                        let (payload, envelope) =
                            self.seal_command(&command_struct, parent_id, seal_ctx)?;

                        let data = VmProtocolData {
                            author_id: envelope.author_id,
                            kind: command_name.clone(),
                            serialized_fields: &payload,
                            signature: &envelope.signature,
                        };

                        let wrapped = postcard::to_allocvec(&data)
                            .assume("can serialize vm protocol data")?;

                        let new_command = VmProtocol {
                            id: envelope.command_id,
                            parent,
                            policy,
                            data: &wrapped,
                        };

                        self.call_rule(&new_command, rs.io.facts, rs.io.sink, command_placement)?;
                        rs.io
                            .facts
                            .add_command(&new_command, priority)
                            .map_err(|e| {
                                error!("{e}");
                                PolicyError::Write
                            })?;

                        // After publishing a new command, the RunState's context must be updated to reflect the new head
                        let new_head = match rs.io.facts.head_address()? {
                            Prior::Single(addr) => addr.id,
                            _ => bug!("expected single head after adding command"),
                        };
                        rs.update_context_with_new_head(new_head)?;

                        // Resume action after last Publish
                        exit_reason = rs.run().map_err(|e| {
                            error!("{e}");
                            PolicyError::InternalError
                        })?;
                    }
                    ExitReason::Check => {
                        // Can't recall outside a command context
                        info!("Check {}", self.source_location(&rs));
                        return Err(PolicyError::Rejected);
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
    use aranya_policy_vm::{ast::Version, ident};

    use super::*;

    #[test]
    fn test_require_command_priority() {
        let cases = [
            r#"command Test {
                fields {}
                policy {}
            }"#,
            r#"command Test {
                attributes {}
                fields {}
                policy {}
            }"#,
            r#"command Test {
                attributes {
                    init: false,
                    finalize: false,
                }
                fields {}
                policy {}
            }"#,
        ];

        for case in cases {
            let ast = parse_policy_str(case, Version::V2).unwrap();
            let module = Compiler::new(&ast).allow_baseless(true).compile().unwrap();
            let machine = Machine::from_module(module).expect("can create machine");
            let def = machine.command_defs.get(&ident!("Test")).unwrap();
            let err = get_command_priority(def).expect_err("should fail");
            assert_eq!(err, AttributeError::missing("Test", "priority"));
        }
    }

    #[test]
    #[ignore = "TODO: pass flavors"]
    fn test_get_command_priority() {
        fn basic(attrs: &str) -> String {
            format!(
                r#"
                command Test {{
                    attributes {{
                        {attrs}
                    }}
                    fields {{ }}
                    policy {{ }}
                }}
                "#
            )
        }

        fn flavored(flavor: &str, attrs: &str) -> String {
            format!(
                r#"
                base command({flavor}) Base {{ get_key {{ return None }} }}
                command Test with Base {{
                    attributes {{
                        {attrs}
                    }}
                    fields {{ }}
                    policy {{ }}
                }}
                "#
            )
        }

        fn process(policy: String) -> Result<VmPriority, AttributeError> {
            let ast = parse_policy_str(&policy, Version::V2).unwrap();
            let module = Compiler::new(&ast).allow_baseless(true).compile().unwrap();
            let machine = Machine::from_module(module).expect("can create machine");
            let def = machine.command_defs.get(&ident!("Test")).unwrap();
            get_command_priority(def)
        }

        assert_eq!(process(basic("priority: 42")), Ok(VmPriority::Basic(42)));
        assert_eq!(
            process(basic("finalize: false, priority: 42")),
            Ok(VmPriority::Basic(42))
        );
        assert_eq!(
            process(basic("init: false, priority: 42, finalize: false")),
            Ok(VmPriority::Basic(42))
        );

        assert_eq!(process(flavored("init", "")), Ok(VmPriority::Init));
        assert_eq!(process(flavored("finalize", "")), Ok(VmPriority::Finalize));

        assert_eq!(
            process(basic("priority: false")),
            Err(AttributeError::type_mismatch(
                "Test", "priority", "Int", "Bool"
            ))
        );
        assert_eq!(
            process(basic("priority: -1")),
            Err(AttributeError::int_range(
                "Test",
                "priority",
                u32::MIN.into(),
                u32::MAX.into(),
            ))
        );
        assert_eq!(
            process(basic(&format!("priority: {}", i64::MAX))),
            Err(AttributeError::int_range(
                "Test",
                "priority",
                u32::MIN.into(),
                u32::MAX.into(),
            ))
        );

        assert_eq!(
            process(flavored("finalize", "priority: 42")),
            Err(AttributeError::should_not_have(
                "finalize", "Test", "priority"
            ))
        );
        assert_eq!(
            process(flavored("init", "priority: 42")),
            Err(AttributeError::should_not_have("init", "Test", "priority"))
        );
    }
}
