//! Interface for simulating or testing Aranya.
//!
//! The Aranya Model is a library which provides APIs to construct one or more clients, execute actions on the clients, sync between clients, and gather performance metrics about the operations performed.

extern crate alloc;
use alloc::{collections::BTreeMap, vec::Vec};
use core::{cell::RefCell, fmt::Debug, mem};
use std::{collections::btree_map::Entry, marker::PhantomData};

use anyhow::Result;
use aranya_crypto::Rng;
use aranya_policy_compiler::CompileError;
use aranya_policy_lang::lang::ParseError;
use aranya_runtime::{
    engine::{Engine, EngineError, Policy, PolicyId, Sink},
    storage::GraphId,
    testing::dsl::dispatch,
    vm_policy::{VmEffect, VmPolicy, VmPolicyError},
    ClientError, ClientState, PeerCache, StorageProvider, SyncError, SyncRequester,
    MAX_SYNC_MESSAGE_SIZE,
};

/// Model engine effect.
///
/// An Effect is a struct used in policy `finish` and `recall` blocks to describe the shape of side effects emitted from processed commands.
pub type ModelEffect = VmEffect;

/// Model engine.
///
/// Holds the [`VmPolicy`] model engine methods.
pub struct ModelEngine<E> {
    policy: VmPolicy<E>,
}

impl<E> ModelEngine<E>
where
    E: aranya_crypto::Engine,
{
    /// Creates a new ModelEngine instance with a [`VmPolicy`].
    pub fn new(policy: VmPolicy<E>) -> Self {
        Self { policy }
    }
}

impl<E> Engine for ModelEngine<E>
where
    E: aranya_crypto::Engine,
{
    type Policy = VmPolicy<E>;
    type Effect = ModelEffect;

    fn add_policy(&mut self, policy: &[u8]) -> Result<PolicyId, EngineError> {
        // TODO: (Scott) Implement once `add_policy` method is implemented in the policy_vm
        // For now return dummy PolicyId
        Ok(PolicyId::new(policy[0] as usize))
    }

    fn get_policy(&self, _id: PolicyId) -> Result<&Self::Policy, EngineError> {
        Ok(&self.policy)
    }
}

/// An error returned by the model engine.
#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("client not found")]
    ClientNotFound,
    #[error("graph not found")]
    GraphNotFound,
    #[error("duplicate client")]
    DuplicateClient,
    #[error("duplicate graph")]
    DuplicateGraph,
    #[error(transparent)]
    Engine(#[from] EngineError),
    #[error(transparent)]
    Sync(#[from] SyncError),
    #[error(transparent)]
    VmPolicy(#[from] VmPolicyError),
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error(transparent)]
    Compile(#[from] CompileError),
}

/// Proxy ID for clients
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProxyClientId(pub u64);

/// Proxy ID for graphs
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProxyGraphId(pub u64);

/// The [`Model`] manages adding clients, graphs, actions, syncing client state,
/// creating sessions, and processing ephemeral commands.
pub trait Model {
    type Effect;
    type Action<'a>;
    type PublicKeys;
    type ClientArgs;
    type Session<'a>
    where
        Self: 'a;
    type ClientId;
    type GraphId;

    /// Used to add a client to the model.
    fn add_client(&mut self, proxy_id: Self::ClientId) -> Result<(), ModelError>
    where
        Self::ClientArgs: Default,
    {
        self.add_client_with(proxy_id, Default::default())
    }

    /// Used to add a client to the model.
    fn add_client_with(
        &mut self,
        proxy_id: Self::ClientId,
        args: Self::ClientArgs,
    ) -> Result<(), ModelError>;

    /// Used to create a graph on a client.
    fn new_graph(
        &mut self,
        proxy_id: Self::GraphId,
        client_proxy_id: Self::ClientId,
        action: Self::Action<'_>,
    ) -> Result<Vec<Self::Effect>, ModelError>;

    /// Used for calling a single action that can emit only on-graph commands.
    fn action(
        &mut self,
        client_proxy_id: Self::ClientId,
        graph_proxy_id: Self::GraphId,
        action: Self::Action<'_>,
    ) -> Result<Vec<Self::Effect>, ModelError>;

    /// Used to sync state with a peer by requesting for new on-graph commands.
    fn sync(
        &mut self,
        graph_proxy_id: Self::GraphId,
        source_client_proxy_id: Self::ClientId,
        dest_client_proxy_id: Self::ClientId,
    ) -> Result<(), ModelError>;

    /// Used to retrieve the public keys associated with a client.
    fn get_public_keys(
        &self,
        client_proxy_id: Self::ClientId,
    ) -> Result<&Self::PublicKeys, ModelError>;

    /// Create a [`Model::Session`] to process ephemeral actions and commands.
    ///
    /// See [`Model::session_actions`] and [`Model::session_receive`] for convenience.
    fn session(
        &self,
        client_proxy_id: Self::ClientId,
        graph_proxy_id: Self::GraphId,
    ) -> Result<Self::Session<'_>>;

    /// Used for calling a set of actions that emit only ephemeral commands.
    fn session_actions<'a>(
        &mut self,
        client_proxy_id: Self::ClientId,
        graph_proxy_id: Self::GraphId,
        actions: impl IntoIterator<Item = Self::Action<'a>>,
    ) -> Result<SessionData<Self::Effect>>;

    /// Used for processing externally received ephemeral commands.
    fn session_receive(
        &mut self,
        client_proxy_id: Self::ClientId,
        graph_proxy_id: Self::GraphId,
        commands: impl IntoIterator<Item = Box<[u8]>>,
    ) -> Result<Vec<Self::Effect>>;
}

/// Holds a collection of effect data.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VecSink<E> {
    /// Effects from executing a policy action.
    pub(crate) effects: Vec<E>,
}

impl<E> VecSink<E> {
    /// Creates a new `VecSink`.
    pub const fn new() -> Self {
        Self {
            effects: Vec::new(),
        }
    }

    /// Returns the collected effects.
    pub fn collect<T>(self) -> Result<Vec<T>, <T as TryFrom<E>>::Error>
    where
        T: TryFrom<E>,
    {
        self.effects.into_iter().map(T::try_from).collect()
    }
}

impl<E> Sink<E> for VecSink<E> {
    fn begin(&mut self) {}

    fn consume(&mut self, effect: E) {
        self.effects.push(effect);
    }

    fn rollback(&mut self) {}

    fn commit(&mut self) {}
}

type Msg = Box<[u8]>;
type SessionData<E> = (Vec<Msg>, Vec<E>);

/// Sink for graph commands.
#[derive(Default)]
pub struct MsgSink {
    cmds: Vec<Msg>,
}

impl MsgSink {
    /// Creates a `MsgSink`.
    pub const fn new() -> Self {
        Self { cmds: Vec::new() }
    }

    /// Returns the collected commands.
    pub fn into_cmds(self) -> Vec<Msg> {
        self.cmds
    }

    /// Returns an iterator over the collected commands.
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.cmds.iter().map(AsRef::as_ref)
    }
}

impl Sink<&[u8]> for MsgSink {
    fn begin(&mut self) {}

    fn consume(&mut self, effect: &[u8]) {
        self.cmds.push(effect.into())
    }

    fn rollback(&mut self) {}

    fn commit(&mut self) {}
}

/// ModelClient
///
/// Holds [`ClientState`] for graphs that belong to the client.
pub struct ModelClient<CF: ClientFactory + ?Sized> {
    /// Holds the [`ClientState`] for each model client.
    pub state: RefCell<ClientState<CF::Engine, CF::StorageProvider>>,
    /// Holds the public key information for each model client.
    pub public_keys: CF::PublicKeys,
}

/// ClientFactory
///
/// [`ClientFactory`] creates generic clients.
pub trait ClientFactory {
    type Engine: Engine;
    type StorageProvider: StorageProvider;
    type PublicKeys;
    type Args;

    fn create_client(&mut self, args: Self::Args) -> ModelClient<Self>;
}

type ClientStorageIds = BTreeMap<ProxyGraphId, GraphId>;
// A map of peer caches for (GraphID, DestClientID, SourceClientID)
type ClientGraphPeerCache =
    BTreeMap<(ProxyGraphId, ProxyClientId, ProxyClientId), RefCell<PeerCache>>;
type Clients<C> = BTreeMap<ProxyClientId, C>;

/// Runtime model.
///
/// Holds a collection of [`ModelClient`] and Graph ID data.
pub struct RuntimeModel<CF: ClientFactory, CID, GID> {
    /// Holds a collection of clients.
    pub clients: Clients<ModelClient<CF>>,
    /// Holds a collection of [`ProxyGraphId`]s and [`GraphId`]s
    pub storage_ids: ClientStorageIds,
    /// Each client holds a `PeerCache` for each client and graph combination.
    pub client_graph_peer_cache: ClientGraphPeerCache,
    client_factory: CF,
    _ph: PhantomData<(CID, GID)>,
}

impl<CF, CID, GID> RuntimeModel<CF, CID, GID>
where
    CF: ClientFactory,
{
    /// Creates a new [`RuntimeModel`]
    pub fn new(client_factory: CF) -> Self {
        RuntimeModel::<CF, CID, GID> {
            clients: BTreeMap::default(),
            storage_ids: BTreeMap::default(),
            client_graph_peer_cache: BTreeMap::default(),
            client_factory,
            _ph: PhantomData,
        }
    }
}

impl<CF, CID, GID> Model for RuntimeModel<CF, CID, GID>
where
    CF: ClientFactory,
    CID: Into<ProxyClientId> + 'static,
    GID: Into<ProxyGraphId> + 'static,
{
    type Effect = <CF::Engine as Engine>::Effect;
    type Action<'a> = <<CF::Engine as Engine>::Policy as Policy>::Action<'a>;
    type PublicKeys = CF::PublicKeys;
    type ClientArgs = CF::Args;
    type Session<'a>
        = Session<'a, CF::Engine, CF::StorageProvider>
    where
        CF: 'a;
    type ClientId = CID;
    type GraphId = GID;

    /// Add a client to the model
    fn add_client_with(
        &mut self,
        proxy_id: Self::ClientId,
        args: Self::ClientArgs,
    ) -> Result<(), ModelError> {
        let Entry::Vacant(e) = self.clients.entry(proxy_id.into()) else {
            return Err(ModelError::DuplicateClient);
        };
        e.insert(self.client_factory.create_client(args));
        Ok(())
    }

    /// Create a graph on a client
    fn new_graph(
        &mut self,
        proxy_id: Self::GraphId,
        client_proxy_id: Self::ClientId,
        action: Self::Action<'_>,
    ) -> Result<Vec<Self::Effect>, ModelError> {
        let Entry::Vacant(storage_id) = self.storage_ids.entry(proxy_id.into()) else {
            return Err(ModelError::DuplicateGraph);
        };

        let mut sink = VecSink::new();

        let mut state = self
            .clients
            .get_mut(&client_proxy_id.into())
            .ok_or(ModelError::ClientNotFound)?
            .state
            .borrow_mut();

        storage_id.insert(
            state
                .new_graph(&[0u8], action, &mut sink)
                .map(|(id, _)| id)?,
        );

        Ok(sink.effects)
    }

    /// Preform an action on a client
    fn action(
        &mut self,
        client_proxy_id: Self::ClientId,
        graph_proxy_id: Self::GraphId,
        action: Self::Action<'_>,
    ) -> Result<Vec<Self::Effect>, ModelError> {
        let storage_id = self
            .storage_ids
            .get(&graph_proxy_id.into())
            .ok_or(ModelError::GraphNotFound)?;

        let mut state = self
            .clients
            .get_mut(&client_proxy_id.into())
            .ok_or(ModelError::ClientNotFound)?
            .state
            .borrow_mut();

        let mut sink = VecSink::new();

        state.action(*storage_id, &mut sink, action)?;

        Ok(sink.effects)
    }

    /// Sync a graph between two clients
    fn sync(
        &mut self,
        graph_proxy_id: Self::GraphId,
        source_client_proxy_id: Self::ClientId,
        dest_client_proxy_id: Self::ClientId,
    ) -> Result<(), ModelError> {
        let graph_proxy_id = graph_proxy_id.into();
        let source_client_proxy_id = source_client_proxy_id.into();
        let dest_client_proxy_id = dest_client_proxy_id.into();
        // Destination of the sync
        let mut request_state = self
            .clients
            .get(&dest_client_proxy_id)
            .ok_or(ModelError::ClientNotFound)?
            .state
            .borrow_mut();

        self.client_graph_peer_cache
            .entry((graph_proxy_id, dest_client_proxy_id, source_client_proxy_id))
            .or_default();
        self.client_graph_peer_cache
            .entry((graph_proxy_id, source_client_proxy_id, dest_client_proxy_id))
            .or_default();

        let mut request_cache = self
            .client_graph_peer_cache
            .get(&(graph_proxy_id, dest_client_proxy_id, source_client_proxy_id))
            .ok_or(ModelError::ClientNotFound)?
            .borrow_mut();
        let mut response_cache = self
            .client_graph_peer_cache
            .get(&(graph_proxy_id, source_client_proxy_id, dest_client_proxy_id))
            .ok_or(ModelError::ClientNotFound)?
            .borrow_mut();

        let mut sink = VecSink::new();

        // Source of the sync
        let mut response_state = self
            .clients
            .get(&source_client_proxy_id)
            .ok_or(ModelError::ClientNotFound)?
            .state
            .borrow_mut();

        let storage_id = self
            .storage_ids
            .get(&graph_proxy_id)
            .ok_or(ModelError::GraphNotFound)?;

        let mut request_syncer = SyncRequester::new(*storage_id, &mut Rng::new(), ());
        assert!(request_syncer.ready());

        let mut request_trx = request_state.transaction(*storage_id);

        while request_syncer.ready() {
            if request_syncer.ready() {
                let mut buffer = [0u8; MAX_SYNC_MESSAGE_SIZE];
                let (len, _) = request_syncer.poll(
                    &mut buffer,
                    request_state.provider(),
                    &mut request_cache,
                )?;

                let mut target = [0u8; MAX_SYNC_MESSAGE_SIZE];
                let len = dispatch::<()>(
                    &buffer[..len],
                    &mut target,
                    response_state.provider(),
                    &mut response_cache,
                )?;
                if len == 0 {
                    break;
                }

                if let Some(cmds) = request_syncer.receive(&target[..len])? {
                    request_state.add_commands(&mut request_trx, &mut sink, &cmds)?;
                };
            }
        }

        request_state.commit(&mut request_trx, &mut sink)?;

        Ok(())
    }

    /// Retrieve public keys from a client
    fn get_public_keys(
        &self,
        client_proxy_id: Self::ClientId,
    ) -> Result<&Self::PublicKeys, ModelError> {
        Ok(&self
            .clients
            .get(&client_proxy_id.into())
            .ok_or(ModelError::ClientNotFound)?
            .public_keys)
    }

    fn session(
        &self,
        client_proxy_id: Self::ClientId,
        graph_proxy_id: Self::GraphId,
    ) -> Result<Self::Session<'_>> {
        let storage_id = *self
            .storage_ids
            .get(&graph_proxy_id.into())
            .ok_or(ModelError::GraphNotFound)?;

        let client = &self
            .clients
            .get(&client_proxy_id.into())
            .ok_or(ModelError::ClientNotFound)?
            .state;

        let session = client.borrow_mut().session(storage_id)?;

        Ok(Session {
            client,
            session,
            effects: VecSink::new(),
            msgs: MsgSink::new(),
        })
    }

    /// Create ephemeral session commands and effects
    fn session_actions<'a>(
        &mut self,
        client_proxy_id: Self::ClientId,
        graph_proxy_id: Self::GraphId,
        actions: impl IntoIterator<Item = Self::Action<'a>>,
    ) -> Result<SessionData<Self::Effect>> {
        let mut session = self.session(client_proxy_id, graph_proxy_id)?;
        for action in actions {
            session.action(action)?;
        }
        Ok(session.observe())
    }

    /// Process ephemeral session commands
    fn session_receive(
        &mut self,
        client_proxy_id: Self::ClientId,
        graph_proxy_id: Self::GraphId,
        commands: impl IntoIterator<Item = Box<[u8]>>,
    ) -> Result<Vec<Self::Effect>> {
        let mut session = self.session(client_proxy_id, graph_proxy_id)?;
        for command in commands {
            session.receive(&command)?;
        }
        Ok(session.observe().1)
    }
}

/// A wrapper around [`aranya_runtime::Session`] for processing ephemeral actions and commands.
pub struct Session<'a, E: Engine, SP: StorageProvider> {
    client: &'a RefCell<ClientState<E, SP>>,
    session: aranya_runtime::Session<SP, E>,
    effects: VecSink<<E as Engine>::Effect>,
    msgs: MsgSink,
}

impl<E: Engine, SP: StorageProvider> Session<'_, E, SP> {
    /// Process an ephemeral action.
    pub fn action(&mut self, action: <<E as Engine>::Policy as Policy>::Action<'_>) -> Result<()> {
        self.session.action(
            &*self.client.borrow(),
            &mut self.effects,
            &mut self.msgs,
            action,
        )?;
        Ok(())
    }

    /// Process a received ephemeral command.
    pub fn receive(&mut self, command: &[u8]) -> Result<()> {
        self.session
            .receive(&*self.client.borrow(), &mut self.effects, command)?;
        Ok(())
    }

    /// Observe and consume the produced effects and commands.
    pub fn observe(&mut self) -> SessionData<<E as Engine>::Effect> {
        (
            mem::take(&mut self.msgs.cmds),
            mem::take(&mut self.effects.effects),
        )
    }
}
