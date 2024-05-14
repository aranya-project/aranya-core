//! Interface for simulating or testing Aranya.
//!
//! The Aranya Model is a library which provides APIs to construct one or more clients, execute actions on the clients, sync between clients, and gather performance metrics about the operations performed.

extern crate alloc;
use alloc::{collections::BTreeMap, vec::Vec};
use core::{
    cell::RefCell,
    fmt::{self, Debug, Display},
};

use crypto::Rng;
use policy_compiler::CompileError;
use policy_lang::lang::ParseError;
use runtime::{
    engine::{Engine, EngineError, Policy, PolicyId, Sink},
    storage::GraphId,
    vm_policy::{VmEffect, VmPolicy, VmPolicyError},
    ClientError, ClientState, StorageProvider, SyncError, SyncRequester, SyncResponder,
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
    E: crypto::Engine,
{
    /// Creates a new ModelEngine instance with a [`VmPolicy`].
    pub fn new(policy: VmPolicy<E>) -> Self {
        Self { policy }
    }
}

impl<E> Engine for ModelEngine<E>
where
    E: crypto::Engine,
{
    type Policy = VmPolicy<E>;
    type Effect = ModelEffect;

    fn add_policy(&mut self, policy: &[u8]) -> Result<PolicyId, EngineError> {
        // TODO: (Scott) Implement once `add_policy` method is implemented in the policy_vm
        // For now return dummy PolicyId
        Ok(PolicyId::new(policy[0] as usize))
    }

    fn get_policy<'a>(&'a self, _id: &PolicyId) -> Result<&'a Self::Policy, EngineError> {
        Ok(&self.policy)
    }
}

/// An error returned by the model engine.
#[derive(Debug)]
pub enum ModelError {
    Client(ClientError),
    ClientNotFound,
    GraphNotFound,
    DuplicateClient,
    DuplicateGraph,
    Engine(EngineError),
    Sync(SyncError),
    VmPolicy(VmPolicyError),
    Parse(ParseError),
    Compile(CompileError),
}

impl From<ClientError> for ModelError {
    fn from(err: ClientError) -> Self {
        ModelError::Client(err)
    }
}

impl From<EngineError> for ModelError {
    fn from(err: EngineError) -> Self {
        ModelError::Engine(err)
    }
}

impl From<SyncError> for ModelError {
    fn from(err: SyncError) -> Self {
        ModelError::Sync(err)
    }
}

impl From<VmPolicyError> for ModelError {
    fn from(err: VmPolicyError) -> Self {
        ModelError::VmPolicy(err)
    }
}

impl From<ParseError> for ModelError {
    fn from(err: ParseError) -> Self {
        ModelError::Parse(err)
    }
}

impl From<CompileError> for ModelError {
    fn from(err: CompileError) -> Self {
        ModelError::Compile(err)
    }
}

impl Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(err) => write!(f, "{}", err),
            Self::ClientNotFound => write!(f, "client not found"),
            Self::GraphNotFound => write!(f, "graph not found"),
            Self::DuplicateClient => write!(f, "duplicate client"),
            Self::DuplicateGraph => write!(f, "duplicate graph"),
            Self::Engine(err) => write!(f, "{}", err),
            Self::Sync(err) => write!(f, "{}", err),
            Self::VmPolicy(err) => write!(f, "{}", err),
            Self::Parse(err) => write!(f, "{}", err),
            Self::Compile(err) => write!(f, "{}", err),
        }
    }
}

impl trouble::Error for ModelError {}

type ProxyClientID = u64;
/// Proxy ID for graphs
pub type ProxyGraphID = u64;

/// The [`Model`] manages adding clients, graphs, actions, and syncing client state.
pub trait Model {
    type Effect;
    type Action<'a>;
    type PublicKeys;

    fn add_client(&mut self, proxy_id: ProxyClientID) -> Result<(), ModelError>;

    fn new_graph(
        &mut self,
        proxy_id: ProxyGraphID,
        client_proxy_id: ProxyClientID,
        action: Self::Action<'_>,
    ) -> Result<Self::Effect, ModelError>;

    fn action(
        &mut self,
        client_proxy_id: ProxyClientID,
        graph_proxy_id: ProxyGraphID,
        action: Self::Action<'_>,
    ) -> Result<Self::Effect, ModelError>;

    fn sync(
        &mut self,
        graph_proxy_id: ProxyGraphID,
        source_client_proxy_id: ProxyClientID,
        dest_client_proxy_id: ProxyClientID,
    ) -> Result<(), ModelError>;

    fn get_public_keys(
        &self,
        client_proxy_id: ProxyClientID,
    ) -> Result<&Self::PublicKeys, ModelError>;
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

    fn create_client(&mut self) -> ModelClient<Self>;
}

type ClientStorageIds = BTreeMap<ProxyGraphID, GraphId>;
type Clients<C> = BTreeMap<ProxyClientID, C>;

/// Runtime model.
///
/// Holds a collection of [`ModelClient`] and Graph ID data.
pub struct RuntimeModel<CF: ClientFactory> {
    /// Holds a collection of clients.
    pub clients: Clients<ModelClient<CF>>,
    /// Holds a collection of [`ProxyGraphID`]s and [`GraphId`]s
    pub storage_ids: ClientStorageIds,
    client_factory: CF,
}

impl<CF> RuntimeModel<CF>
where
    CF: ClientFactory,
{
    /// Creates a new [`RuntimeModel`]
    pub fn new(client_factory: CF) -> Self {
        RuntimeModel {
            clients: BTreeMap::default(),
            storage_ids: BTreeMap::default(),
            client_factory,
        }
    }
}

impl<CF: ClientFactory> Model for RuntimeModel<CF> {
    type Effect = Vec<<CF::Engine as Engine>::Effect>;
    type Action<'a> = <<CF::Engine as Engine>::Policy as Policy>::Action<'a>;
    type PublicKeys = CF::PublicKeys;

    fn add_client(&mut self, proxy_id: ProxyClientID) -> Result<(), ModelError> {
        if self.clients.contains_key(&proxy_id) {
            return Err(ModelError::DuplicateClient);
        };

        self.clients
            .insert(proxy_id, self.client_factory.create_client());

        Ok(())
    }

    fn new_graph(
        &mut self,
        proxy_id: ProxyGraphID,
        client_proxy_id: ProxyClientID,
        action: Self::Action<'_>,
    ) -> Result<Self::Effect, ModelError> {
        if self.storage_ids.contains_key(&proxy_id) {
            return Err(ModelError::DuplicateGraph);
        }

        let mut sink = VecSink::new();

        let mut state = self
            .clients
            .get_mut(&client_proxy_id)
            .ok_or(ModelError::ClientNotFound)?
            .state
            .borrow_mut();

        let storage_id = state.new_graph(&[0u8], action, &mut sink)?;

        self.storage_ids.insert(proxy_id, storage_id);

        Ok(sink.effects)
    }

    fn action(
        &mut self,
        client_proxy_id: ProxyClientID,
        graph_proxy_id: ProxyGraphID,
        action: Self::Action<'_>,
    ) -> Result<Self::Effect, ModelError> {
        let storage_id = self
            .storage_ids
            .get(&(graph_proxy_id))
            .ok_or(ModelError::GraphNotFound)?;

        let mut state = self
            .clients
            .get_mut(&client_proxy_id)
            .ok_or(ModelError::ClientNotFound)?
            .state
            .borrow_mut();

        let mut sink = VecSink::new();

        state.action(storage_id, &mut sink, action)?;

        Ok(sink.effects)
    }

    fn sync(
        &mut self,
        graph_proxy_id: ProxyGraphID,
        source_client_proxy_id: ProxyClientID,
        dest_client_proxy_id: ProxyClientID,
    ) -> Result<(), ModelError> {
        // Destination of the sync
        let mut request_state = self
            .clients
            .get(&dest_client_proxy_id)
            .ok_or(ModelError::ClientNotFound)?
            .state
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
            .get(&(graph_proxy_id))
            .ok_or(ModelError::GraphNotFound)?;

        let mut request_syncer = SyncRequester::new(*storage_id, &mut Rng::new());
        let mut response_syncer = SyncResponder::new();
        assert!(request_syncer.ready());

        let mut request_trx = request_state.transaction(storage_id);

        loop {
            if !request_syncer.ready() && !response_syncer.ready() {
                break;
            }

            if request_syncer.ready() {
                let mut buffer = [0u8; MAX_SYNC_MESSAGE_SIZE];
                let len = request_syncer.poll(&mut buffer, request_state.provider())?;

                response_syncer.receive(&buffer[..len])?;
            }

            if response_syncer.ready() {
                let mut buffer = [0u8; MAX_SYNC_MESSAGE_SIZE];
                let len = response_syncer.poll(&mut buffer, response_state.provider())?;

                if len == 0 {
                    break;
                }

                if let Some(cmds) = request_syncer.receive(&buffer[..len])? {
                    request_state.add_commands(&mut request_trx, &mut sink, &cmds)?;
                };
            }
        }

        request_state.commit(&mut request_trx, &mut sink)?;

        Ok(())
    }

    fn get_public_keys(
        &self,
        client_proxy_id: ProxyClientID,
    ) -> Result<&Self::PublicKeys, ModelError> {
        Ok(&self
            .clients
            .get(&client_proxy_id)
            .ok_or(ModelError::ClientNotFound)?
            .public_keys)
    }
}
