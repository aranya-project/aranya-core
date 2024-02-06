extern crate alloc;

use alloc::{string::String, vec::Vec};

use policy_vm::{FactKey, FactValue, MachineIOError};

use crate::FactPerspective;

/// An Iterator that returns a sequence of matching facts from a query. It is produced by
/// the [VmPolicyIO](super::VmPolicyIO) when a query is made by the VM.
pub struct VmFactCursor<'o, P>
where
    P: FactPerspective,
{
    facts: &'o P,
    key: Vec<FactKey>,
    key_vec: heapless::Vec<u8, 256>,
}

impl<'o, P> VmFactCursor<'o, P>
where
    P: FactPerspective,
{
    /// Create a new `VmFactCursor` from the fact name, key, and a reference to a
    /// `FactPerspective`.
    pub fn new(
        name: String,
        key: Vec<FactKey>,
        facts: &'o P,
    ) -> Result<VmFactCursor<'o, P>, MachineIOError> {
        let fk = (name, key);
        let key_vec: heapless::Vec<u8, 256> =
            postcard::to_vec(&fk).map_err(|_| MachineIOError::Internal)?;
        Ok(VmFactCursor {
            facts,
            key: fk.1,
            key_vec,
        })
    }
}

impl<'o, P> Iterator for VmFactCursor<'o, P>
where
    P: FactPerspective,
{
    type Item = Result<(Vec<FactKey>, Vec<FactValue>), MachineIOError>;

    fn next(&mut self) -> Option<Self::Item> {
        let r = self.facts.query(&self.key_vec).expect("query");
        r.map(|b| -> Self::Item {
            let v: Vec<FactValue> =
                postcard::from_bytes(&b).map_err(|_| MachineIOError::Internal)?;
            Ok((self.key.clone(), v))
        })
    }
}
