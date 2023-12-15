#![cfg(feature = "model")]

extern crate alloc;
use alloc::{string::String, vec::Vec};

use policy_vm::KVPair;

use crate::{
    engine::{Engine, EngineError, PolicyId},
    vm_policy::VmPolicy,
    ClientError,
};

pub type ModelEffect = (String, Vec<KVPair>);

pub struct ModelEngine {
    policy: VmPolicy,
}

impl ModelEngine {
    pub fn new(policy: VmPolicy) -> ModelEngine {
        ModelEngine { policy }
    }
}

impl Engine for ModelEngine {
    type Policy = VmPolicy;
    type Effects = ModelEffect;

    fn add_policy(&mut self, policy: &[u8]) -> Result<PolicyId, EngineError> {
        // TODO: (Scott) Implement once this is implemented in the policy_vm
        Ok(PolicyId::new(policy[0] as usize))
    }

    fn get_policy<'a>(&'a self, _id: &PolicyId) -> Result<&'a Self::Policy, EngineError> {
        Ok(&self.policy)
    }
}

#[derive(Debug)]
pub enum ModelError {
    Client(ClientError),
    DuplicateClient,
    DuplicateGraph,
    Engine(EngineError),
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

pub type ProxyClientID = u64;
pub type ProxyGraphID = u64;

pub trait Model {
    type Effects;
    type Metrics;
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
    ) -> Result<Self::Effects, ModelError>;

    fn action(
        &mut self,
        client_proxy_id: ProxyClientID,
        graph_proxy_id: ProxyGraphID,
        action: Self::Action<'_>,
    ) -> Result<Self::Effects, ModelError>;

    fn get_statistics(
        &self,
        client_proxy_id: ProxyClientID,
        graph_proxy_id: ProxyGraphID,
    ) -> Result<Self::Metrics, ModelError>;

    fn sync(
        &mut self,
        graph_proxy_id: ProxyGraphID,
        client_proxy_id: ProxyClientID,
        source_client_proxy_id: ProxyClientID,
    ) -> Result<Self::Effects, ModelError>;
}

#[cfg(test)]
mod tests;
