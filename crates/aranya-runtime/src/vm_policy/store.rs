use alloc::{
    collections::{BTreeMap, btree_map::Entry},
    sync::Arc,
    vec::Vec,
};

use aranya_crypto::{Engine, PolicyId};
use aranya_policy_vm::{Identifier, Machine, Module, ModuleData};
use tracing::error;

use super::{FfiCallable, SealCtx, VmEffect, VmPolicy};
use crate::{Policy, PolicyError, PolicyStore};

#[derive(Debug, thiserror::Error)]
#[error("duplicate ffi name: {0}")]
pub struct DuplicateFfiName(Identifier);

#[derive(Debug, thiserror::Error)]
#[error("missing ffi name: {0}")]
pub struct MissingFfiName(Identifier);

/// [`PolicyStore`] implementation which holds [`VmPolicy`].
pub struct VmPolicyStore<CE: Engine> {
    engine: CE,
    seal_ctx: Option<SealCtx<CE>>,
    ffis: FfiSet<CE>,
    policies: BTreeMap<PolicyId, VmPolicy<CE>>,
}

impl<CE: Engine> VmPolicyStore<CE> {
    pub fn new(engine: CE, ffis: FfiSet<CE>, seal_ctx: SealCtx<CE>) -> Self {
        Self {
            engine,
            seal_ctx: Some(seal_ctx),
            ffis,
            policies: BTreeMap::new(),
        }
    }

    pub fn new_readonly(engine: CE, ffis: FfiSet<CE>) -> Self {
        Self {
            engine,
            seal_ctx: None,
            ffis,
            policies: BTreeMap::new(),
        }
    }

    /// Get the serialized verifying key based on the seal context.
    #[cfg(any(test, feature = "testing"))]
    pub fn verifying_key(&self) -> Vec<u8> {
        postcard::to_allocvec(
            &self
                .seal_ctx
                .as_ref()
                .expect("has seal ctx")
                .key
                .public()
                .expect("can compute verifying key"),
        )
        .expect("can serialize verifying key")
    }
}

impl<CE: Engine + Clone> VmPolicyStore<CE> {
    /// Load a serialized policy module into a vm policy instance.
    fn load_policy(&mut self, policy: &[u8]) -> Result<VmPolicy<CE>, PolicyError> {
        let module = Module::read_from_slice(policy).map_err(|error| {
            error!(%error, "could not load policy");
            PolicyError::InternalError
        })?;

        let ffi_names = match &module.data {
            ModuleData::V0(_) => {
                error!("cannot add module V0 into policy store");
                return Err(PolicyError::InternalError);
            }
            ModuleData::V1(m) => m.contract.ffis.iter().map(|f| f.name.clone()),
        };

        let ffis = self.ffis.select(ffi_names).map_err(|error| {
            error!(%error, "could not select FFIs for module");
            PolicyError::InternalError
        })?;

        let machine = Machine::from_module(module).map_err(|error| {
            error!(%error, "could not create VM from module");
            PolicyError::InternalError
        })?;

        let policy = VmPolicy::new(machine, self.engine.clone(), ffis).map_err(|error| {
            error!(%error, "could not create VmPolicy");
            PolicyError::InternalError
        })?;

        Ok(policy)
    }
}

impl<CE: Engine + Clone> PolicyStore for VmPolicyStore<CE> {
    type Policy = VmPolicy<CE>;
    type Effect = VmEffect;

    fn add_policy(&mut self, policy_bytes: &[u8]) -> Result<PolicyId, PolicyError> {
        use aranya_crypto::id::IdExt as _;

        let id =
            PolicyId::new::<<CE as Engine>::CS>(b"VmPolicyId-v1", core::iter::once(policy_bytes));

        if !self.policies.contains_key(&id) {
            let policy = self.load_policy(policy_bytes)?;
            self.policies.insert(id, policy);
        }

        Ok(id)
    }

    fn get_policy(&self, id: PolicyId) -> Result<&Self::Policy, PolicyError> {
        self.policies.get(&id).ok_or(PolicyError::InternalError)
    }

    fn seal_ctx(&self, _id: PolicyId) -> Result<&<Self::Policy as Policy>::SealCtx, PolicyError> {
        self.seal_ctx.as_ref().ok_or(PolicyError::InternalError)
    }
}

/// A set of FFIs, identified by name.
///
/// This is expected to hold all FFIs used within a policy store.
pub struct FfiSet<CE> {
    inner: BTreeMap<Identifier, Arc<dyn FfiCallable<CE> + Send + 'static>>,
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
        ffi: impl FfiCallable<CE> + Send + 'static,
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
        ffi: impl FfiCallable<CE> + Send + 'static,
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
    ) -> Result<Vec<Arc<dyn FfiCallable<CE> + Send + 'static>>, MissingFfiName> {
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
