//! Interface for simulating or testing Aranya.
//!
//! The Aranya Model is a library which provides APIs to construct one or more clients, execute actions on the clients, sync between clients, and gather performance metrics about the operations performed.

extern crate alloc;
use alloc::{string::String, vec::Vec};
use core::fmt::{self, Debug, Display};

use policy_vm::KVPair;
use runtime::{
    engine::{Engine, EngineError, PolicyId},
    metrics::MetricError,
    vm_policy::VmPolicy,
    ClientError, SyncError,
};

/// Model engine effect.
///
/// An Effect is a struct used in policy `finish` and `recall` blocks to describe the shape of side effects emitted from processed commands.
pub type ModelEffect = (String, Vec<KVPair>);

/// Model engine.
///
/// Holds the [`VmPolicy`] model engine methods.
pub struct ModelEngine<E> {
    policy: VmPolicy<E>,
}

impl<E> ModelEngine<E> {
    /// Creates a new ModelEngine instance with a [`VmPolicy`].
    pub fn new(policy: VmPolicy<E>) -> Self {
        Self { policy }
    }
}

impl<E: crypto::Engine> Engine for ModelEngine<E> {
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
    DuplicateClient,
    DuplicateGraph,
    Engine(EngineError),
    Sync(SyncError),
    Metric(MetricError),
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

impl From<MetricError> for ModelError {
    fn from(err: MetricError) -> Self {
        ModelError::Metric(err)
    }
}

impl From<SyncError> for ModelError {
    fn from(err: SyncError) -> Self {
        ModelError::Sync(err)
    }
}

impl Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(err) => write!(f, "{}", err),
            Self::DuplicateClient => write!(f, "duplicate client"),
            Self::DuplicateGraph => write!(f, "duplicate graph"),
            Self::Engine(err) => write!(f, "{}", err),
            Self::Sync(err) => write!(f, "{}", err),
            Self::Metric(err) => write!(f, "{}", err),
        }
    }
}

impl trouble::Error for ModelError {}

pub type ProxyClientID = u64;
pub type ProxyGraphID = u64;

/// The [`Model`] manages adding clients, graphs, actions, and syncing client state.
pub trait Model {
    type Effect;
    type Action<'a>;

    fn add_client(
        &mut self,
        client_proxy_id: ProxyClientID,
        policy: &str,
    ) -> Result<(), ModelError>;

    fn new_graph(
        &mut self,
        proxy_id: ProxyGraphID,
        client_proxy_id: ProxyClientID,
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
}
