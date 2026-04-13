use core::{fmt, iter::DoubleEndedIterator};

use aranya_crypto::Engine;
use aranya_runtime::{
    Address, ClientError, ClientState, Command, GraphId, PolicyError, PolicyId, PolicyStore,
    Session, Sink, Transaction, TraversalBuffer, VmAction, VmEffect, VmPolicy,
    storage::linear::{IoManager, LinearStorageProvider},
    sync::PeerCache,
};

/// A single-policy store backed by [`VmPolicy`].
///
/// This is the concrete [`PolicyStore`] implementation used by [`Client`].
pub struct VmPolicyStore<CE> {
    policy: VmPolicy<CE>,
    policy_id: PolicyId,
}

impl<CE> VmPolicyStore<CE> {
    /// Creates a new `VmPolicyStore` from a [`VmPolicy`].
    pub fn new(policy: VmPolicy<CE>) -> Self {
        Self {
            policy,
            policy_id: PolicyId::new(0),
        }
    }
}

#[doc(hidden)]
impl<CE: Engine> PolicyStore for VmPolicyStore<CE> {
    type Policy = VmPolicy<CE>;
    type Effect = VmEffect;

    fn add_policy(&mut self, _policy: &[u8]) -> Result<PolicyId, PolicyError> {
        Ok(self.policy_id)
    }

    fn get_policy(&self, _id: PolicyId) -> Result<&Self::Policy, PolicyError> {
        Ok(&self.policy)
    }
}

/// Type alias for a [`Transaction`] used with [`Client`].
pub type ClientTransaction<CE, FM> = Transaction<LinearStorageProvider<FM>, VmPolicyStore<CE>>;

/// Type alias for a [`Session`] used with [`Client`].
pub type ClientSession<CE, FM> = Session<LinearStorageProvider<FM>, VmPolicyStore<CE>>;

/// The Aranya client.
///
/// Wraps [`ClientState`] with the policy store fixed to [`VmPolicyStore`]
/// and the storage provider fixed to [`LinearStorageProvider`].
///
/// - `CE` is the cryptographic engine (e.g., [`aranya_crypto::default::DefaultEngine`]).
/// - `FM` is the IO manager for storage (e.g., [`aranya_runtime::linear::IoManager`]).
pub struct Client<CE, FM: IoManager> {
    inner: ClientState<VmPolicyStore<CE>, LinearStorageProvider<FM>>,
}

impl<CE, FM: IoManager> Client<CE, FM> {
    /// Creates a new `Client`.
    pub const fn new(policy_store: VmPolicyStore<CE>, provider: LinearStorageProvider<FM>) -> Self {
        Self {
            inner: ClientState::new(policy_store, provider),
        }
    }

    /// Provides access to the [`LinearStorageProvider`].
    pub fn provider(&mut self) -> &mut LinearStorageProvider<FM> {
        self.inner.provider()
    }
}

impl<CE, FM: IoManager> fmt::Debug for Client<CE, FM> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

impl<CE: Engine, FM: IoManager> Client<CE, FM> {
    /// Create a new graph (AKA Team).
    ///
    /// The graph starts with the provided policy data and init action.
    /// Effects produced when processing the action are emitted to the sink.
    pub fn new_graph(
        &mut self,
        policy_data: &[u8],
        action: VmAction<'_>,
        sink: &mut impl Sink<VmEffect>,
    ) -> Result<GraphId, ClientError> {
        self.inner.new_graph(policy_data, action, sink)
    }

    /// Remove a graph and all its commands from storage.
    pub fn remove_graph(&mut self, graph_id: GraphId) -> Result<(), ClientError> {
        self.inner.remove_graph(graph_id)
    }

    /// Commit a [`ClientTransaction`] to storage, after merging all temporary heads.
    ///
    /// Returns whether any new commands were added.
    pub fn commit(
        &mut self,
        trx: ClientTransaction<CE, FM>,
        sink: &mut impl Sink<VmEffect>,
        buffer: &mut TraversalBuffer,
    ) -> Result<bool, ClientError> {
        self.inner.commit(trx, sink, buffer)
    }

    /// Add commands to a transaction, writing the results to `sink`.
    ///
    /// Returns the number of commands that were added.
    pub fn add_commands(
        &mut self,
        trx: &mut ClientTransaction<CE, FM>,
        sink: &mut impl Sink<VmEffect>,
        commands: &[impl Command],
        buffer: &mut TraversalBuffer,
    ) -> Result<usize, ClientError> {
        self.inner.add_commands(trx, sink, commands, buffer)
    }

    /// Update the peer cache with new command addresses.
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
        self.inner
            .update_heads(graph_id, addrs, request_heads, buffer)
    }

    /// Returns the address of the head of the graph.
    pub fn head_address(&mut self, graph_id: GraphId) -> Result<Address, ClientError> {
        self.inner.head_address(graph_id)
    }

    /// Performs an action, writing the results to `sink`.
    pub fn action(
        &mut self,
        graph_id: GraphId,
        sink: &mut impl Sink<VmEffect>,
        action: VmAction<'_>,
    ) -> Result<(), ClientError> {
        self.inner.action(graph_id, sink, action)
    }
}

impl<CE, FM: IoManager> Client<CE, FM> {
    /// Create a new [`ClientTransaction`], used to receive commands when syncing.
    pub fn transaction(&mut self, graph_id: GraphId) -> ClientTransaction<CE, FM> {
        self.inner.transaction(graph_id)
    }

    /// Create an ephemeral [`ClientSession`] associated with this client.
    pub fn session(&mut self, graph_id: GraphId) -> Result<ClientSession<CE, FM>, ClientError> {
        self.inner.session(graph_id)
    }

    /// Checks if a command with the given address exists in the specified graph.
    ///
    /// Returns `true` if the command exists, `false` if it doesn't exist
    /// or the graph doesn't exist.
    pub fn command_exists(
        &mut self,
        graph_id: GraphId,
        address: Address,
        buffer: &mut TraversalBuffer,
    ) -> bool {
        self.inner.command_exists(graph_id, address, buffer)
    }
}
