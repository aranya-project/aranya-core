use aranya_crypto::Engine;
use aranya_runtime::{
    policy::{PolicyError, PolicyId, PolicyStore},
    vm_policy::{SealCtx, VmEffect, VmPolicy},
};

/// A single-policy store backed by [`VmPolicy`].
///
/// This is the concrete policy store used by [`crate::ClientState`].
pub struct VmPolicyStore<CE: Engine> {
    policy: VmPolicy<CE>,
    policy_id: PolicyId,
    seal_ctx: SealCtx<CE>,
}

impl<CE: Engine> VmPolicyStore<CE> {
    /// Creates a new `VmPolicyStore` from a [`VmPolicy`].
    pub fn new(policy: VmPolicy<CE>, seal_ctx: SealCtx<CE>) -> Self {
        Self {
            policy,
            policy_id: PolicyId::default(),
            seal_ctx,
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

    fn seal_ctx(
        &self,
        _id: PolicyId,
    ) -> Result<&<Self::Policy as aranya_runtime::Policy>::SealCtx, PolicyError> {
        Ok(&self.seal_ctx)
    }
}
