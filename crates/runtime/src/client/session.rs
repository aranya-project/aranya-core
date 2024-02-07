//! Ephemeral sessions for off-graph commands.
//!
//! See [`ClientState::session`] and [`Session`].
//!
//! Design discussion/docs: <https://git.spideroak-inc.com/spideroak-inc/flow3-docs/pull/53>

use alloc::boxed::Box;
use core::marker::PhantomData;

use buggy::{bug, Bug, BugExt};
use serde::{Deserialize, Serialize};

use crate::{
    ClientError, ClientState, Command, Engine, FactPerspective, Id, Perspective, Policy, PolicyId,
    Prior, Priority, Revertable, Segment, Sink, Storage, StorageError, StorageProvider,
    MAX_COMMAND_LENGTH,
};

/// Ephemeral session used to handle/generate off-graph commands.
pub struct Session<SP: StorageProvider, E> {
    /// The ID of the associated storage
    storage_id: Id,
    /// Current working perspective
    perspective: <SP::Storage as Storage>::Perspective,
    /// Policy ID for session
    policy_id: PolicyId,
    /// Head of perspective
    head: Id,
    /// Tag for associated engine
    _engine: PhantomData<E>,
}

impl<SP: StorageProvider, E: Engine> Session<SP, E> {
    pub(super) fn new(provider: &mut SP, storage_id: Id) -> Result<Self, ClientError> {
        let storage = provider.get_storage(&storage_id)?;
        let head_loc = storage.get_head()?;
        let seg = storage.get_segment(&head_loc)?;
        let head = seg.head().id();
        let perspective = storage
            .get_linear_perspective(&head_loc)?
            .assume("can get perspective at head")?;

        let result = Self {
            storage_id,
            perspective,
            policy_id: seg.policy(),
            head,
            _engine: PhantomData,
        };

        Ok(result)
    }

    /// Evaluate an action on the ephemeral session and generate serialized
    /// commands, so another client can [`Session::receive`] them.
    pub fn action<ES, MS>(
        &mut self,
        client: &ClientState<E, SP>,
        effect_sink: &mut ES,
        message_sink: &mut MS,
        action: <E::Policy as Policy>::Actions<'_>,
    ) -> Result<(), ClientError>
    where
        ES: Sink<E::Effects>,
        MS: for<'b> Sink<&'b [u8]>,
    {
        let policy = client.engine.get_policy(&self.policy_id)?;

        // Use a special perspective so we can send to the message sink.
        let mut perspective = SessionPerspective {
            storage_id: self.storage_id,
            message_sink,
            perspective: &mut self.perspective,
            policy: self.policy_id,
            head: self.head,
            added: 0,
        };
        let checkpoint = perspective.perspective.checkpoint();
        effect_sink.begin();

        // Try to perform action.
        match policy.call_action(&self.head, action, &mut perspective, effect_sink) {
            Ok(true) => {
                // Success, update head and commit effects
                self.head = perspective.head;
                effect_sink.commit();
                Ok(())
            }
            Ok(false) => {
                // Rejected, revert all
                perspective.perspective.revert(checkpoint);
                perspective.message_sink.rollback();
                effect_sink.rollback();
                Err(ClientError::NotAuthorized)
            }
            Err(e) => {
                // Other error, revert all? See #513.
                perspective.perspective.revert(checkpoint);
                perspective.message_sink.rollback();
                effect_sink.rollback();
                Err(e.into())
            }
        }
    }

    /// Handle a command from another client generated by [`Session::action`].
    ///
    /// You do NOT need to reprocess the commands from actions generated in the
    /// same session.
    pub fn receive(
        &mut self,
        client: &ClientState<E, SP>,
        sink: &mut impl Sink<E::Effects>,
        command_bytes: &[u8],
    ) -> Result<(), ClientError> {
        let command: SessionCommand<'_> =
            postcard::from_bytes(command_bytes).map_err(ClientError::SessionDeserialize)?;

        if command.storage_id != self.storage_id {
            bug!("ephemeral commands must be run on the same graph");
        }

        let policy = client.engine.get_policy(&self.policy_id)?;

        // Try to evaluate command.
        sink.begin();
        let checkpoint = self.perspective.checkpoint();
        if !policy.call_rule(&command, &mut self.perspective, sink)? {
            self.perspective.revert(checkpoint);
            sink.rollback();
            return Err(ClientError::NotAuthorized);
        }
        sink.commit();

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
/// Used for serializing session commands
struct SessionCommand<'a> {
    storage_id: Id,
    priority: u32, // Priority::Basic
    id: Id,
    parent: Id, // Prior::Single
    #[serde(borrow)]
    data: &'a [u8],
}

impl<'sc, 'cmd> Command<'cmd> for SessionCommand<'sc> {
    fn priority(&self) -> Priority {
        Priority::Basic(self.priority)
    }

    fn id(&self) -> Id {
        self.id
    }

    fn parent(&self) -> Prior<Id> {
        Prior::Single(self.parent)
    }

    fn policy(&self) -> Option<&[u8]> {
        // Session commands should never have policy?
        None
    }

    fn bytes(&self) -> &[u8] {
        self.data
    }
}

impl<'sc> SessionCommand<'sc> {
    fn from_cmd<'cmd>(storage_id: Id, command: &'sc impl Command<'cmd>) -> Result<Self, Bug> {
        if command.policy().is_some() {
            bug!("session command should have no policy")
        }
        Ok(SessionCommand {
            storage_id,
            priority: match command.priority() {
                Priority::Basic(p) => p,
                _ => bug!("wrong command type"),
            },
            id: command.id(),
            parent: match command.parent() {
                Prior::Single(p) => p,
                _ => bug!("wrong command type"),
            },
            data: command.bytes(),
        })
    }
}

struct SessionPerspective<'a, MS, P> {
    storage_id: Id,
    message_sink: &'a mut MS,
    perspective: &'a mut P,
    policy: PolicyId,
    head: Id,
    added: usize,
}

impl<'a, MS, P> FactPerspective for SessionPerspective<'a, MS, P>
where
    P: FactPerspective,
{
    fn query(&self, key: &[u8]) -> Result<Option<Box<[u8]>>, StorageError> {
        self.perspective.query(key)
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) {
        self.perspective.insert(key, value)
    }

    fn delete(&mut self, key: &[u8]) {
        self.perspective.delete(key)
    }
}

impl<'s, MS, P> Perspective for SessionPerspective<'s, MS, P>
where
    MS: for<'b> Sink<&'b [u8]>,
    P: Perspective,
{
    fn policy(&self) -> PolicyId {
        self.policy
    }

    fn add_command<'cmd>(&mut self, command: &impl Command<'cmd>) -> Result<usize, StorageError> {
        // TODO(jdygert): Shouldn't need to actually store the commands.
        // Currently needed so checkpoint is correct when reverting.
        self.perspective.add_command(command)?;

        let command = SessionCommand::from_cmd(self.storage_id, command)?;
        let mut buf = [0u8; MAX_COMMAND_LENGTH];
        let bytes = postcard::to_slice(&command, &mut buf).assume("can serialize")?;
        self.message_sink.consume(bytes);
        self.added = self
            .added
            .checked_add(1)
            .assume("will not add usize::MAX commands")?;
        Ok(self.added)
    }

    fn includes(&self, id: &Id) -> bool {
        self.perspective.includes(id)
    }
}