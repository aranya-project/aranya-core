use alloc::{borrow::Cow, collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::borrow::Borrow as _;

use aranya_crypto::BaseId;
use aranya_policy_vm::{
    ActionContext, CommandContext, ExitReason, KVPair, Machine, MachineIO, MachineStack,
    PolicyContext, RunState, Stack as _, Struct, Value, ast::Identifier, ffi_contract_validate,
};
use buggy::{BugExt as _, bug};
use tracing::{error, info, instrument, warn};

use super::{
    error::VmPolicyError,
    interface::{VmAction, VmEffect},
    io::{FfiCallable, VmPolicyIO},
    priority::{VmPriority, get_command_priorities},
    protocol::{Envelope, VmProtocol, VmProtocolData},
    seal_open::{SealCtx, open_with_key},
};
use crate::{
    Address, CommandPlacement, FactPerspective, FlavorCtx, GraphId, MergeIds, NullSink,
    Perspective, Prior, Priority,
    command::{CmdId, Command},
    policy::{Policy, PolicyError, Sink},
    vm_policy::protocol::{BasicEnvelope, EphemeralEnvelope, FinalizeEnvelope, InitEnvelope},
};

pub static FLAVORS: aranya_policy_module::flavor::Flavors<'static> = {
    use aranya_policy_module::{
        arg,
        flavor::{Flavor, Flavors, Struct},
    };
    use aranya_policy_vm::ident;
    Flavors {
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
                ident!("basic"),
                Flavor {
                    envelope: Struct {
                        name: ident!("DefaultEnvelope"),
                        fields: &[
                            arg!("command_id", Id),
                            arg!("parent_id", Id),
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
            (
                ident!("finalize"),
                Flavor {
                    envelope: Struct {
                        name: ident!("FinalizeEnvelope"),
                        fields: &[
                            arg!("command_id", Id),
                            arg!("parent_id", Id),
                            // TODO(jdygert): Make finalize certified.
                            // Omit `author_id` so nothing relies on it.
                        ],
                    },
                },
            ),
        ],
    }
};

/// A [Policy] implementation that uses the Policy VM.
pub struct VmPolicy<CE> {
    machine: Machine,
    engine: CE,
    ffis: Vec<Arc<dyn FfiCallable<CE> + Send + 'static>>,
    priority_map: BTreeMap<Identifier, VmPriority>,
}

impl<CE> VmPolicy<CE> {
    /// Create a new `VmPolicy` from a [Machine]
    pub fn new(
        machine: Machine,
        engine: CE,
        ffis: Vec<Arc<dyn FfiCallable<CE> + Send + 'static>>,
    ) -> Result<Self, VmPolicyError> {
        if let Some(module_ffis) = &machine.ffis {
            ffi_contract_validate(module_ffis, ffis.iter().map(|m| m.schema()))?;
        } else {
            warn!("Module does not have contract; cannot validate FFI");
        }
        let priority_map = get_command_priorities(&machine)?;
        Ok(Self {
            machine,
            engine,
            ffis,
            priority_map,
        })
    }

    fn source_location<M>(&self, rs: &RunState<M>) -> String
    where
        M: MachineIO<MachineStack>,
    {
        rs.source_location()
            .unwrap_or_else(|| String::from("(unknown location)"))
    }

    fn get_command_priority(&self, name: &Identifier) -> Result<VmPriority, PolicyError> {
        self.priority_map.get(name).copied().ok_or_else(|| {
            error!("unknown command {name}");
            PolicyError::InternalError
        })
    }
}

impl<CE: aranya_crypto::Engine> VmPolicy<CE> {
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip_all, fields(name = name.as_str()))]
    fn evaluate_rule<'a, P>(
        &self,
        name: Identifier,
        fields: &[KVPair],
        envelope: Envelope,
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
        policy: Option<&[u8]>,
    ) -> Result<super::seal_open::Sealed<CE::CS>, PolicyError> {
        let payload = self.machine.serialize_struct(command_struct).map_err(|e| {
            error!(error = %e, "cannot serialize command");
            PolicyError::Write
        })?;

        let flavor = self
            .machine
            .command_defs
            .get(&command_struct.name)
            .assume("sealing known command")?
            .flavor
            .as_str();

        let sealed = super::seal_open::seal_with_key(
            &seal_ctx.key,
            flavor,
            command_struct,
            payload,
            seal_ctx.author,
            parent_id,
            policy,
        )
        .map_err(|e| {
            error!(error = %e, "could not seal command");
            PolicyError::Panic
        })?;

        Ok(sealed)
    }

    #[instrument(skip_all, fields(name = command_struct.name.as_str()))]
    fn open_command(
        &self,
        command_struct: &Struct,
        payload: &[u8],
        signature: &[u8],
        envelope: &Envelope,
        facts: &mut impl FactPerspective,
        policy: Option<&[u8]>,
    ) -> Result<(), PolicyError> {
        let mut sink = NullSink;
        let mut io = VmPolicyIO::new(facts, &mut sink, &self.engine, &self.ffis);

        let (_, value) = self
            .machine
            .call_get_key(command_struct.clone(), envelope.author_id(), &mut io)
            .inspect_err(|e| warn!(error = %e, "failed getting key"))
            .map_err(|_| PolicyError::Panic)?;

        let key_bytes = value.ok_or_else(|| {
            warn!("no key present");
            PolicyError::Panic
        })?;
        let key: aranya_crypto::VerifyingKey<CE::CS> =
            postcard::from_bytes(&key_bytes).map_err(|_| {
                warn!("could not deserialize open key");
                PolicyError::Panic
            })?;

        open_with_key(key, command_struct, payload, signature, envelope, policy)
            .inspect_err(|e| warn!(error = %e, "open_with_key failed"))
            .map_err(|_| PolicyError::Panic)
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

        let command_id = command.id();
        let envelope = match def.flavor.as_str() {
            "basic" => Envelope::Basic(BasicEnvelope {
                command_id,
                parent_id,
                author_id,
            }),
            "init" => Envelope::Init(InitEnvelope {
                command_id,
                author_id,
            }),
            "finalize" => Envelope::Finalize(FinalizeEnvelope {
                command_id,
                parent_id,
                fact_root: BaseId::default(), // TODO(jdygert): real fact root
            }),
            "ephemeral" => Envelope::Ephemeral(EphemeralEnvelope {
                command_id,
                graph_id: GraphId::transmute(parent_id),
                author_id,
            }),
            // TODO(jdygert): validate in contract so this is truly unreachable.
            _ => bug!("unknown flavor"),
        };

        let def_is_ephemeral = def.flavor == "ephemeral";

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
                self.open_command(
                    &command_struct,
                    payload,
                    signature,
                    &envelope,
                    facts,
                    command.policy(),
                )?;
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
            version: BaseId::default(),
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
        seal_ctx: &SealCtx<CE>,
        flavor_ctx: FlavorCtx<'_>,
    ) -> Result<(), PolicyError> {
        let VmAction { name, args } = action;

        let def = self.machine.action_defs.get(&name).ok_or_else(|| {
            error!("action not found");
            PolicyError::InternalError
        })?;

        let mut parent_id: CmdId;
        let command_placement: CommandPlacement;
        let maybe_policy: Option<&[u8]>;
        match (&flavor_ctx, def.flavor.as_str(), facts.head_address()?) {
            (&FlavorCtx::Init { policy }, "init", Prior::None) => {
                parent_id = CmdId::default();
                command_placement = CommandPlacement::OnGraphAtOrigin;
                maybe_policy = Some(policy);
            }
            (&FlavorCtx::Basic, "basic", Prior::Single(p)) => {
                parent_id = p.id;
                command_placement = CommandPlacement::OnGraphAtOrigin;
                maybe_policy = None;
            }
            (&FlavorCtx::Ephemeral, "ephemeral", Prior::Single(p)) => {
                parent_id = p.id;
                command_placement = CommandPlacement::OffGraph;
                maybe_policy = None;
            }
            (flavor_ctx, flavor_def, head_address) => {
                // NB: This should only be reachable in these cases:
                // - You call this method directly with invalid context.
                // - You manipulate compiled policy.
                // - We forgot to handle a new variant.
                error!(
                    ?flavor_ctx,
                    ?flavor_def,
                    ?head_address,
                    "invalid action call"
                );
                return Err(PolicyError::InternalError);
            }
        }

        let mut io = VmPolicyIO::new(facts, sink, &self.engine, &self.ffis);
        let ctx = CommandContext::Action(ActionContext {
            name: name.clone(),
            head_id: parent_id,
        });
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

                        if matches!(flavor_ctx, FlavorCtx::Init { .. }) && parent != Prior::None {
                            error!("can't publish multiple init commands");
                            return Err(PolicyError::InternalError);
                        }

                        let sealed =
                            self.seal_command(&command_struct, parent_id, seal_ctx, maybe_policy)?;

                        let signature = sealed.signature.to_bytes();
                        let data = VmProtocolData {
                            author_id: sealed.envelope.author_id(),
                            kind: command_name,
                            serialized_fields: &sealed.payload,
                            signature: signature.borrow(),
                        };

                        let wrapped = postcard::to_allocvec(&data)
                            .assume("can serialize vm protocol data")?;

                        let new_command = VmProtocol {
                            id: sealed.envelope.command_id(),
                            parent,
                            policy: maybe_policy,
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
                        parent_id = match rs.io.facts.head_address()? {
                            Prior::Single(addr) => addr.id,
                            _ => bug!("expected single head after adding command"),
                        };
                        rs.update_context_with_new_head(parent_id)?;

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
