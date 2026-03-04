use core::{fmt, iter::DoubleEndedIterator};

use buggy::Bug;
use tracing::error;

use crate::{
    Address, CmdId, Command, GraphId, PeerCache, Perspective as _, Policy, PolicyError,
    PolicyStore, Sink, Storage as _, StorageError, StorageProvider, TraversalBuffer,
    policy::ActionPlacement,
};

mod braiding;
mod session;
mod transaction;

pub use self::{session::Session, transaction::Transaction};

/// An error returned by the runtime client.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("no such parent: {0}")]
    NoSuchParent(CmdId),
    #[error("policy error: {0}")]
    PolicyError(PolicyError),
    #[error("storage error: {0}")]
    StorageError(#[from] StorageError),
    #[error("init error")]
    InitError,
    #[error("not authorized")]
    NotAuthorized,
    #[error("session deserialize error: {0}")]
    SessionDeserialize(#[from] postcard::Error),
    /// Attempted to braid two parallel finalize commands together.
    ///
    /// Policy must be designed such that two parallel finalize commands are never produced.
    ///
    /// Currently, this is practically an unrecoverable error. You must wipe all graphs containing
    /// the "bad" finalize command and resync from the "good" clients. Otherwise, your network will
    /// split into two separate graph states which can never successfully sync.
    #[error("found parallel finalize commands during braid")]
    ParallelFinalize,
    #[error("concurrent transaction usage")]
    ConcurrentTransaction,
    #[error(transparent)]
    Bug(#[from] Bug),
}

impl From<PolicyError> for ClientError {
    fn from(error: PolicyError) -> Self {
        match error {
            PolicyError::Check => Self::NotAuthorized,
            _ => Self::PolicyError(error),
        }
    }
}

/// Keeps track of client graph state.
///
/// - `PS` should be an implementation of [`PolicyStore`].
/// - `SP` should be an implementation of [`StorageProvider`].
pub struct ClientState<PS, SP> {
    policy_store: PS,
    provider: SP,
}

// Manual Debug impl to exclude `buffers` (large, not useful in debug output).
impl<PS: fmt::Debug, SP: fmt::Debug> fmt::Debug for ClientState<PS, SP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientState")
            .field("policy_store", &self.policy_store)
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

impl<PS, SP> ClientState<PS, SP> {
    /// Creates a `ClientState`.
    pub const fn new(policy_store: PS, provider: SP) -> Self {
        Self {
            policy_store,
            provider,
        }
    }

    /// Provide access to the [`StorageProvider`].
    pub fn provider(&mut self) -> &mut SP {
        &mut self.provider
    }
}

impl<PS, SP> ClientState<PS, SP>
where
    PS: PolicyStore,
    SP: StorageProvider,
{
    /// Create a new graph (AKA Team). This graph will start with the initial policy
    /// provided which must be compatible with the policy store PS. The `payload` is the initial
    /// init message that will bootstrap the graph facts. Effects produced when processing
    /// the payload are emitted to the sink.
    pub fn new_graph(
        &mut self,
        policy_data: &[u8],
        action: <PS::Policy as Policy>::Action<'_>,
        sink: &mut impl Sink<PS::Effect>,
    ) -> Result<GraphId, ClientError> {
        let policy_id = self.policy_store.add_policy(policy_data)?;
        let policy = self.policy_store.get_policy(policy_id)?;

        let mut perspective = self.provider.new_perspective(policy_id);
        sink.begin();
        policy
            .call_action(action, &mut perspective, sink, ActionPlacement::OnGraph)
            .inspect_err(|_| sink.rollback())?;
        sink.commit();

        let (graph_id, _) = self.provider.new_storage(perspective)?;

        Ok(graph_id)
    }

    /// Remove a graph (AKA Team). The graph commands will be removed from storage.
    pub fn remove_graph(&mut self, graph_id: GraphId) -> Result<(), ClientError> {
        self.provider.remove_storage(graph_id)?;

        Ok(())
    }

    /// Commit the [`Transaction`] to storage, after merging all temporary heads.
    ///
    /// Returns whether any new commands were added.
    pub fn commit(
        &mut self,
        trx: Transaction<SP, PS>,
        sink: &mut impl Sink<PS::Effect>,
        buffer: &mut TraversalBuffer,
    ) -> Result<bool, ClientError> {
        trx.commit(&mut self.provider, &mut self.policy_store, sink, buffer)
    }

    /// Add commands to the transaction, writing the results to
    /// `sink`.
    /// Returns the number of commands that were added.
    pub fn add_commands(
        &mut self,
        trx: &mut Transaction<SP, PS>,
        sink: &mut impl Sink<PS::Effect>,
        commands: &[impl Command],
        buffer: &mut TraversalBuffer,
    ) -> Result<usize, ClientError> {
        trx.add_commands(
            commands,
            &mut self.provider,
            &mut self.policy_store,
            sink,
            buffer,
        )
    }

    pub fn update_heads<I>(
        &mut self,
        graph_id: GraphId,
        addrs: I,
        request_heads: &mut PeerCache,
        buffer: &mut TraversalBuffer,
    ) -> Result<(), ClientError>
    where
        I: IntoIterator<Item = Address>,
        I::IntoIter: DoubleEndedIterator,
    {
        let storage = self.provider.get_storage(graph_id)?;

        // Commands in sync messages are always ancestor-first (lower max_cut to higher max_cut).
        // Reverse the iterator to process highest max_cut first, which allows us to skip ancestors
        // since if a command is an ancestor of one we've already added, we don't need to add it.
        for address in addrs.into_iter().rev() {
            if let Some(loc) = storage.get_location(address, buffer)? {
                request_heads.add_command(storage, address, loc, buffer)?;
            } else {
                error!(
                    "UPDATE_HEADS: Address {:?} does NOT exist in storage, skipping (should not happen if command was successfully added)",
                    address
                );
            }
        }

        Ok(())
    }

    /// Returns the address of the head of the graph.
    pub fn head_address(&mut self, graph_id: GraphId) -> Result<Address, ClientError> {
        let storage = self.provider.get_storage(graph_id)?;
        let address = storage.get_head_address()?;
        Ok(address)
    }

    /// Performs an `action`, writing the results to `sink`.
    pub fn action(
        &mut self,
        graph_id: GraphId,
        sink: &mut impl Sink<PS::Effect>,
        action: <PS::Policy as Policy>::Action<'_>,
    ) -> Result<(), ClientError> {
        let storage = self.provider.get_storage(graph_id)?;

        let head = storage.get_head()?;

        let mut perspective = storage.get_linear_perspective(head)?;

        let policy_id = perspective.policy();
        let policy = self.policy_store.get_policy(policy_id)?;

        // No need to checkpoint the perspective since it is only for this action.
        // Must checkpoint once we add action transactions.

        sink.begin();
        match policy.call_action(action, &mut perspective, sink, ActionPlacement::OnGraph) {
            Ok(()) => {
                let segment = storage.write(perspective)?;
                storage.commit(segment)?;
                sink.commit();
                Ok(())
            }
            Err(e) => {
                sink.rollback();
                Err(e.into())
            }
        }
    }
}

impl<PS, SP> ClientState<PS, SP>
where
    SP: StorageProvider,
{
    /// Create a new [`Transaction`], used to receive [`Command`]s when syncing.
    pub fn transaction(&mut self, graph_id: GraphId) -> Transaction<SP, PS> {
        Transaction::new(graph_id)
    }

    /// Create an ephemeral [`Session`] associated with this client.
    pub fn session(&mut self, graph_id: GraphId) -> Result<Session<SP, PS>, ClientError> {
        Session::new(&mut self.provider, graph_id)
    }

    /// Checks if a command with the given address exists in the specified graph.
    ///
    /// Returns `true` if the command exists, `false` if it doesn't exist or the graph doesn't exist.
    /// This method is used to determine if we need to sync when a hello message is received.
    pub fn command_exists(
        &mut self,
        graph_id: GraphId,
        address: Address,
        buffer: &mut TraversalBuffer,
    ) -> bool {
        let Ok(storage) = self.provider.get_storage(graph_id) else {
            // Graph doesn't exist
            return false;
        };
        storage
            .get_location(address, buffer)
            .unwrap_or(None)
            .is_some()
    }
}
