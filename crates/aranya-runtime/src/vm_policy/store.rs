use alloc::{
    collections::{BTreeMap, btree_map::Entry},
    sync::Arc,
    vec::Vec,
};

use aranya_crypto::{Engine, PolicyId};
use aranya_policy_vm::{Identifier, Machine, Module, ModuleData};
use tracing::error;

use super::{FfiCallable, VmEffect, VmPolicy};
use crate::{ByteStore, PolicyStore, PolicyStoreError};

#[derive(Debug, thiserror::Error)]
#[error("duplicate ffi name: {0}")]
pub struct DuplicateFfiName(Identifier);

#[derive(Debug, thiserror::Error)]
#[error("missing ffi name: {0}")]
pub struct MissingFfiName(Identifier);

/// [`PolicyStore`] implementation which holds [`VmPolicy`].
pub struct VmPolicyStore<BS, CE: Engine> {
    byte_store: BS,
    engine: CE,
    ffis: FfiSet<CE>,
    policies: BTreeMap<PolicyId, Arc<VmPolicy<CE>>>,
}

impl<BS, CE: Engine> VmPolicyStore<BS, CE> {
    /// Create a new VM policy store.
    pub fn new(byte_store: BS, engine: CE, ffis: FfiSet<CE>) -> Self {
        Self {
            byte_store,
            engine,
            ffis,
            policies: BTreeMap::new(),
        }
    }
}

impl<BS: ByteStore, CE: Engine + Clone> VmPolicyStore<BS, CE> {
    /// Load a serialized policy module into a vm policy instance.
    fn load_policy(&mut self, policy: &[u8]) -> Result<Arc<VmPolicy<CE>>, PolicyStoreError> {
        let module = Module::read_from_slice(policy).map_err(|error| {
            error!(%error, "could not load policy");
            PolicyStoreError::InvalidPolicy
        })?;

        let ffi_names = match &module.data {
            ModuleData::V0(_) => {
                error!("cannot add module V0 into policy store");
                return Err(PolicyStoreError::UnsupportedPolicy);
            }
            ModuleData::V1(m) => m.contract.ffis.iter().map(|f| f.name.clone()),
        };

        let ffis = self.ffis.select(ffi_names).map_err(|error| {
            error!(%error, "could not select FFIs for module");
            PolicyStoreError::UnsupportedPolicy
        })?;

        let machine = Machine::from_module(module).map_err(|error| {
            error!(%error, "could not create VM from module");
            PolicyStoreError::UnsupportedPolicy
        })?;

        let policy = VmPolicy::new(machine, self.engine.clone(), ffis).map_err(|error| {
            error!(%error, "could not create VmPolicy");
            PolicyStoreError::UnsupportedPolicy
        })?;

        Ok(Arc::new(policy))
    }
}

impl<BS: ByteStore, CE: Engine + Clone> PolicyStore for VmPolicyStore<BS, CE> {
    type Policy = Arc<VmPolicy<CE>>;
    type Effect = VmEffect;

    fn add_policy(&mut self, policy_bytes: &[u8]) -> Result<PolicyId, PolicyStoreError> {
        use aranya_crypto::id::IdExt as _;

        let id =
            PolicyId::new::<<CE as Engine>::CS>(b"VmPolicyId-v1", core::iter::once(policy_bytes));

        if !self.policies.contains_key(&id) {
            self.byte_store.put(id, policy_bytes).map_err(|e| {
                tracing::error!(error = %e, "could not store policy bytes");
                PolicyStoreError::Io
            })?;
            let policy = self.load_policy(policy_bytes)?;
            self.policies.insert(id, policy);
        }

        Ok(id)
    }

    fn get_policy(&mut self, id: PolicyId) -> Result<Self::Policy, PolicyStoreError> {
        if let Some(policy) = self.policies.get(&id).cloned() {
            return Ok(policy);
        }

        let bytes = self
            .byte_store
            .get(id)
            .map_err(|e| {
                tracing::error!(error = %e, "could not load policy bytes");
                PolicyStoreError::Io
            })?
            .ok_or(PolicyStoreError::UnknownPolicy)?;

        let policy = self.load_policy(&bytes)?;
        self.policies.insert(id, Arc::clone(&policy));
        Ok(policy)
    }
}

/// A set of FFIs, identified by name.
///
/// This is expected to hold all FFIs used within a policy store.
pub struct FfiSet<CE> {
    inner: BTreeMap<Identifier, Arc<dyn FfiCallable<CE> + Send + Sync>>,
}

impl<CE> FfiSet<CE> {
    /// Create an empty FFI set.
    pub const fn new() -> Self {
        Self {
            inner: BTreeMap::new(),
        }
    }

    /// Add an FFI to the set.
    pub fn add(
        &mut self,
        ffi: impl FfiCallable<CE> + Send + Sync + 'static,
    ) -> Result<(), DuplicateFfiName> {
        match self.inner.entry(ffi.schema().name) {
            Entry::Occupied(e) => Err(DuplicateFfiName(e.get().schema().name)),
            Entry::Vacant(e) => {
                e.insert(Arc::new(ffi));
                Ok(())
            }
        }
    }

    /// Add an FFI to the set, returning `Self` for chaining.
    pub fn with(
        mut self,
        ffi: impl FfiCallable<CE> + Send + Sync + 'static,
    ) -> Result<Self, DuplicateFfiName> {
        self.add(ffi)?;
        Ok(self)
    }

    /// Get FFIs by name.
    ///
    /// Used by the policy store to select FFIs when loading a module.
    fn select(
        &self,
        names: impl IntoIterator<Item = Identifier>,
    ) -> Result<Vec<Arc<dyn FfiCallable<CE> + Send + Sync>>, MissingFfiName> {
        names
            .into_iter()
            .map(|name| {
                self.inner
                    .get(name.as_ref())
                    .cloned()
                    .ok_or(MissingFfiName(name))
            })
            .collect()
    }
}

impl<CE> Default for FfiSet<CE> {
    fn default() -> Self {
        Self::new()
    }
}
