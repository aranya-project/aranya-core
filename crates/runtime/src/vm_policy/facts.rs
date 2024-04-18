extern crate alloc;

use alloc::{string::String, vec::Vec};

use policy_vm::{FactKey, FactValue, MachineIOError};
use tracing::error;

use crate::{FactPerspective, Query};

/// An Iterator that returns a sequence of matching facts from a query. It is produced by
/// the [VmPolicyIO](super::VmPolicyIO) when a query is made by the VM.
pub struct VmFactCursor<'o, P: Query + 'o> {
    iter: P::QueryIterator<'o>,
}

impl<'o, P: Query + 'o> VmFactCursor<'o, P> {
    /// Create a new `VmFactCursor` from the fact name, key, and a reference to a
    /// `FactPerspective`.
    pub fn new(name: String, key: Vec<FactKey>, facts: &'o P) -> Result<Self, MachineIOError> {
        let fk = (name, key);
        let key_vec = postcard::to_allocvec(&fk).map_err(|e| {
            error!("could not serialize keys: {e}");
            MachineIOError::Internal
        })?;
        let iter = facts.query_prefix(&key_vec).map_err(|e| {
            error!("query failed: {e}");
            MachineIOError::Internal
        })?;
        Ok(VmFactCursor { iter })
    }
}

impl<'o, P> Iterator for VmFactCursor<'o, P>
where
    P: FactPerspective,
{
    type Item = Result<(Vec<FactKey>, Vec<FactValue>), MachineIOError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|b| -> Self::Item {
            let b = b.map_err(|e| {
                error!("error during query: {e}");
                MachineIOError::Internal
            })?;
            let (_, k): (String, Vec<FactKey>) = postcard::from_bytes(&b.key).map_err(|e| {
                error!("could not deserialize keys: {e}");
                MachineIOError::Internal
            })?;
            let v: Vec<FactValue> = postcard::from_bytes(&b.value).map_err(|e| {
                error!("could not deserialize values: {e}");
                MachineIOError::Internal
            })?;

            Ok((k, v))
        })
    }
}
