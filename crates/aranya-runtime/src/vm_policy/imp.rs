use alloc::{borrow::Cow, collections::BTreeMap, string::String, sync::Arc, vec::Vec};

use aranya_policy_vm::{
    ActionContext, CommandContext, ExitReason, KVPair, Machine, MachineIO, MachineStack,
    PolicyContext, RunState, Stack as _, Struct, Value, ast::Identifier, ffi_contract_validate,
};
use buggy::{BugExt as _, bug};
use tracing::{error, info, instrument};

use super::{
    error::VmPolicyError,
    interface::{VmAction, VmEffect},
    io::{FfiCallable, VmPolicyIO},
    priority::{VmPriority, get_command_priorities},
    protocol::{Envelope, VmProtocol, VmProtocolData},
    seal_open::{SealCtx, open_with_key, seal_with_key},
};
use crate::{
    ActionPlacement, Address, CommandPlacement, FactPerspective, MergeIds, NullSink, Perspective,
    Prior, Priority,
    command::{CmdId, Command},
    policy::{Policy, PolicyError, Sink},
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

        let envelope = seal_with_key(
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

        open_with_key(key, command_struct, payload, envelope).map_err(|_| PolicyError::Panic)
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
        let VmAction { name, args, policy } = action;

        let def = self.machine.action_defs.get(&name).ok_or_else(|| {
            error!("action not found");
            PolicyError::InternalError
        })?;

        let def_is_ephemeral = def.flavor == "ephemeral";

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
                        let policy = match parent {
                            Prior::None => {
                                parent_id = CmdId::default();
                                // TODO(chip): where does the policy value come from?
                                if !matches!(priority, Priority::Init) {
                                    error!(
                                        "Command {command_name} has invalid priority {priority:?}"
                                    );
                                    return Err(PolicyError::InternalError);
                                }
                                Some(policy.unwrap_or(&[0u8; 8]))
                            }
                            Prior::Single(p) => {
                                parent_id = p.id;
                                if !matches!(priority, Priority::Basic(_) | Priority::Finalize) {
                                    error!(
                                        "Command {command_name} has invalid priority {priority:?}"
                                    );
                                    return Err(PolicyError::InternalError);
                                }
                                None
                            }
                            Prior::Merge(_, _) => bug!("cannot have a merge parent in call_action"),
                        };

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
