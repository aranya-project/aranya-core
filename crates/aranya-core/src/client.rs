use aranya_crypto::Engine;
use aranya_runtime::{PolicyError, PolicyId, PolicyStore, VmEffect, VmPolicy};

/// A single-policy store backed by [`VmPolicy`].
///
/// This is the concrete policy store used by [`crate::ClientState`].
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
