use alloc::vec::Vec;
use buggy::Bug;
use tracing::{debug, info};

use crate::{
    Address, CmdId, Command, Engine, EngineError, GraphId, PeerCache, Perspective as _, Policy,
    Sink, Storage as _, StorageError, StorageProvider, engine::ActionPlacement,
    sync::COMMAND_RESPONSE_MAX,
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
    pub const fn new(engine: E, provider: SP) -> Self {
        Self { engine, provider }
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
    /// Returns the number of commands that were added and their addresses.
    pub fn add_commands(
        &mut self,
        trx: &mut Transaction<SP, E>,
        sink: &mut impl Sink<E::Effect>,
        commands: &[impl Command],
    ) -> Result<(usize, heapless::Vec<Address, COMMAND_RESPONSE_MAX>), ClientError> {
        let count = trx.add_commands(commands, &mut self.provider, &mut self.engine, sink)?;
        let addresses: heapless::Vec<Address, COMMAND_RESPONSE_MAX> = commands
            .iter()
            .filter_map(|cmd| cmd.address().ok())
            .collect();
        Ok((count, addresses))
    }

    pub fn update_heads(
        &mut self,
        storage_id: GraphId,
        addrs: impl IntoIterator<Item = Address>,
        request_heads: &mut PeerCache,
    ) -> Result<(), ClientError> {
        let storage = self.provider.get_storage(storage_id)?;
        
        // Collect addresses into a vector so we can sort them
        let mut addresses: Vec<Address> = addrs.into_iter().collect();
        let total_addresses = addresses.len();
        
        // Sort by max_cut descending - process highest max_cut first
        // This allows us to skip ancestors since if a command is an ancestor of one we've already added,
        // we don't need to add it
        addresses.sort_by(|a, b| b.max_cut.cmp(&a.max_cut));
        
        info!(
            "update_heads: Processing {} addresses, sorted by max_cut descending (max_cut range: {} to {})",
            total_addresses,
            addresses.first().map(|a| a.max_cut).unwrap_or(0),
            addresses.last().map(|a| a.max_cut).unwrap_or(0)
        );
        
        let mut addresses_added = 0usize;
        let mut addresses_skipped = 0usize;
        let mut get_location_calls = 0usize;
        
        for (idx, address) in addresses.iter().enumerate() {
            get_location_calls += 1;
            let location_result = storage.get_location(*address)?;
            
            match location_result {
                Some(loc) => {
                    // Log first few and every 10th to see pattern
                    if idx < 5 || idx % 10 == 0 {
                        info!(
                            "update_heads: Processing address {}/{} (max_cut={}, id={:?})",
                            idx + 1,
                            total_addresses,
                            address.max_cut,
                            address.id
                        );
                    }
                    request_heads.add_command(storage, *address, loc)?;
                    addresses_added += 1;
                }
                None => {
                    debug!("UPDATE_HEADS: Address {:?} does NOT exist in storage, skipping (should not happen if command was successfully added)", address);
                    addresses_skipped += 1;
                }
            }
        }
        
        info!(
            "update_heads: Completed {} addresses: added={}, skipped={}, get_location_calls={}",
            total_addresses,
            addresses_added,
            addresses_skipped,
            get_location_calls
        );
        
        Ok(())
    }

    /// Returns the address of the head of the graph.
    pub fn head_address(&mut self, storage_id: GraphId) -> Result<Address, ClientError> {
        let storage = self.provider.get_storage(storage_id)?;
        let address = storage.get_head_address()?;
        Ok(address)
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

        let mut perspective = storage.get_linear_perspective(head)?;

        let policy_id = perspective.policy();
        let policy = self.engine.get_policy(policy_id)?;

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

    /// Checks if a command with the given address exists in the specified graph.
    ///
    /// Returns `true` if the command exists, `false` if it doesn't exist or the graph doesn't exist.
    /// This method is used to determine if we need to sync when a hello message is received.
    pub fn command_exists(&mut self, storage_id: GraphId, address: Address) -> bool {
        let Ok(storage) = self.provider.get_storage(storage_id) else {
            // Graph doesn't exist
            return false;
        };
        storage.get_location(address).unwrap_or(None).is_some()
    }
}
