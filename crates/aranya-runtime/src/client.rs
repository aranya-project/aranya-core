use buggy::{Bug, BugExt};

use crate::{
    Address, CmdId, Command, Engine, EngineError, GraphId, PeerCache, Perspective, Policy, Sink,
    Storage, StorageError, StorageProvider,
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
    #[error("engine error: {0}")]
    EngineError(EngineError),
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
    #[error(transparent)]
    Bug(#[from] Bug),
}

impl From<EngineError> for ClientError {
    fn from(error: EngineError) -> Self {
        match error {
            EngineError::Check => Self::NotAuthorized,
            _ => Self::EngineError(error),
        }
    }
}

/// Keeps track of client graph state.
///
/// - `E` should be an implementation of [`Engine`].
/// - `SP` should be an implementation of [`StorageProvider`].
#[derive(Debug)]
pub struct ClientState<E, SP> {
    engine: E,
    provider: SP,
}

impl<E, SP> ClientState<E, SP> {
    /// Creates a `ClientState`.
    pub const fn new(engine: E, provider: SP) -> ClientState<E, SP> {
        ClientState { engine, provider }
    }

    /// Provide access to the [`StorageProvider`].
    pub fn provider(&mut self) -> &mut SP {
        &mut self.provider
    }
}

impl<E, SP> ClientState<E, SP>
where
    E: Engine,
    SP: StorageProvider,
{
    /// Create a new graph (AKA Team). This graph will start with the initial policy
    /// provided which must be compatible with the engine E. The `payload` is the initial
    /// init message that will bootstrap the graph facts. Effects produced when processing
    /// the payload are emitted to the sink.
    pub fn new_graph(
        &mut self,
        policy_data: &[u8],
        action: <E::Policy as Policy>::Action<'_>,
        sink: &mut impl Sink<E::Effect>,
    ) -> Result<GraphId, ClientError> {
        let policy_id = self.engine.add_policy(policy_data)?;
        let policy = self.engine.get_policy(policy_id)?;

        let mut perspective = self.provider.new_perspective(policy_id);
        sink.begin();
        policy
            .call_action(action, &mut perspective, sink)
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
    pub fn commit(
        &mut self,
        trx: &mut Transaction<SP, E>,
        sink: &mut impl Sink<E::Effect>,
    ) -> Result<(), ClientError> {
        trx.commit(&mut self.provider, &mut self.engine, sink)?;
        Ok(())
    }

    /// Add commands to the transaction, writing the results to
    /// `sink`.
    /// Returns the number of commands that were added.
    pub fn add_commands(
        &mut self,
        trx: &mut Transaction<SP, E>,
        sink: &mut impl Sink<E::Effect>,
        commands: impl IntoIterator<Item: Command>,
    ) -> Result<usize, ClientError> {
        let count = trx.add_commands(commands, &mut self.provider, &mut self.engine, sink)?;
        Ok(count)
    }

    pub fn update_heads(
        &mut self,
        storage_id: GraphId,
        addrs: impl IntoIterator<Item = Address>,
        request_heads: &mut PeerCache,
    ) -> Result<(), ClientError> {
        let storage = self.provider.get_storage(storage_id)?;
        for address in addrs {
            if let Some(loc) = storage.get_location(address)? {
                request_heads.add_command(storage, address, loc)?;
            }
        }
        Ok(())
    }

    /// Returns the ID of the head of the graph.
    pub fn head_id(&mut self, storage_id: GraphId) -> Result<CmdId, ClientError> {
        let storage = self.provider.get_storage(storage_id)?;

        let head = storage.get_head()?;
        let id = storage.get_command_id(head)?;
        Ok(id)
    }

    /// Performs an `action`, writing the results to `sink`.
    pub fn action(
        &mut self,
        storage_id: GraphId,
        sink: &mut impl Sink<E::Effect>,
        action: <E::Policy as Policy>::Action<'_>,
    ) -> Result<(), ClientError> {
        let storage = self.provider.get_storage(storage_id)?;

        let head = storage.get_head()?;

        let mut perspective = storage
            .get_linear_perspective(head)?
            .assume("can always get perspective at head")?;

        let policy_id = perspective.policy();
        let policy = self.engine.get_policy(policy_id)?;

        // No need to checkpoint the perspective since it is only for this action.
        // Must checkpoint once we add action transactions.

        sink.begin();
        match policy.call_action(action, &mut perspective, sink) {
            Ok(_) => {
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

impl<E, SP> ClientState<E, SP>
where
    SP: StorageProvider,
{
    /// Create a new [`Transaction`], used to receive [`Command`]s when syncing.
    pub fn transaction(&mut self, storage_id: GraphId) -> Transaction<SP, E> {
        Transaction::new(storage_id)
    }

    /// Create an ephemeral [`Session`] associated with this client.
    pub fn session(&mut self, storage_id: GraphId) -> Result<Session<SP, E>, ClientError> {
        Session::new(&mut self.provider, storage_id)
    }
}
