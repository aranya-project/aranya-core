extern crate alloc;

use alloc::{borrow::Cow, string::String, vec, vec::Vec};

use policy_vm::{
    FactKey, FactValue, KVPair, Machine, MachineError, MachineErrorType, MachineIO, MachineIOError,
    MachineStatus, Stack, Struct, Value,
};

use crate::{
    command::{Command, Id, Priority},
    engine::{EngineError, Policy, Sink},
    storage::MAX_COMMAND_LENGTH,
    FactPerspective, MergeIds, Perspective, Prior,
};

mod error;
pub use error::VmPolicyError;
use serde::{Deserialize, Serialize};

/// The data inside a [VmCommand]. It gets serialized and deserialized over the wire.
#[derive(Debug, Serialize, Deserialize)]
pub enum VmCommandData {
    Init {
        policy: [u8; 8],
    },
    Merge {
        left: Id,
        right: Id,
    },
    Basic {
        parent: Id,
        kind: String,
        fields: Vec<KVPair>,
    },
}

/// The Command implementation as used by the VM. It deserializes the interior data into a
/// [VmCommandData] struct, and it keeps the original serialized copy around for quick
/// access to that.
#[derive(Debug)]
pub struct VmCommand<'a> {
    data: &'a [u8],
    id: Id,
    unpacked: VmCommandData,
}

impl<'a> Command<'a> for VmCommand<'a> {
    fn priority(&self) -> Priority {
        match &self.unpacked {
            VmCommandData::Init { .. } => Priority::Init,
            VmCommandData::Merge { .. } => Priority::Merge,
            // TODO(chip): implement actual message priorities
            VmCommandData::Basic { .. } => Priority::Basic(0),
        }
    }

    fn id(&self) -> Id {
        self.id
    }

    fn parent(&self) -> Prior<Id> {
        match self.unpacked {
            VmCommandData::Init { .. } => Prior::None,
            VmCommandData::Merge { left, right } => Prior::Merge(left, right),
            VmCommandData::Basic { parent, .. } => Prior::Single(parent),
        }
    }

    fn policy(&self) -> Option<&[u8]> {
        match self.unpacked {
            VmCommandData::Init { ref policy } => Some(policy),
            _ => None,
        }
    }

    fn bytes(&self) -> &[u8] {
        self.data
    }
}

/// An Iterator that returns a sequence of matching facts from a query. It is produced by
/// the [VmPolicyIO] when a query is made by the VM.
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

/// Implements the `MachineIO` interface for [VmPolicy].
pub struct VmPolicyIO<'o, P, S>
where
    P: FactPerspective,
    S: Sink<(String, Vec<KVPair>)>,
{
    facts: &'o mut P,
    sink: &'o mut S,
    emit_stack: Vec<(String, Vec<KVPair>)>,
}

impl<'o, P, S> VmPolicyIO<'o, P, S>
where
    P: FactPerspective,
    S: Sink<(String, Vec<KVPair>)>,
{
    /// Creates a new `VmPolicyIO` for a [FactPerspective](crate::storage::FactPerspective) and a
    /// [Sink](crate::engine::Sink).
    pub fn new<'a, 'b>(facts: &'a mut P, sink: &'b mut S) -> VmPolicyIO<'o, P, S>
    where
        'a: 'o,
        'b: 'o,
    {
        VmPolicyIO {
            facts,
            sink,
            emit_stack: vec![],
        }
    }

    /// Consumes the `VmPolicyIO object and produces the emit stack.
    fn into_emit_stack(self) -> Vec<(String, Vec<KVPair>)> {
        self.emit_stack
    }
}

impl<'o, P, S, ST> MachineIO<ST> for VmPolicyIO<'o, P, S>
where
    P: FactPerspective,
    S: Sink<(String, Vec<KVPair>)>,
    ST: Stack,
{
    type QueryIterator<'c> = VmFactCursor<'c, P> where Self: 'c;

    fn fact_insert(
        &mut self,
        name: String,
        key: impl IntoIterator<Item = FactKey>,
        value: impl IntoIterator<Item = FactValue>,
    ) -> Result<(), MachineIOError> {
        let key: Vec<_> = key.into_iter().collect();
        let key_vec: heapless::Vec<u8, 256> =
            postcard::to_vec(&(name, key)).map_err(|_| MachineIOError::Internal)?;
        let value: Vec<_> = value.into_iter().collect();
        let value_vec: heapless::Vec<u8, 256> =
            postcard::to_vec(&value).map_err(|_| MachineIOError::Internal)?;
        self.facts.insert(&key_vec, &value_vec);
        Ok(())
    }

    fn fact_delete(
        &mut self,
        name: String,
        key: impl IntoIterator<Item = FactKey>,
    ) -> Result<(), MachineIOError> {
        let key: Vec<_> = key.into_iter().collect();
        let key_vec: heapless::Vec<u8, 256> =
            postcard::to_vec(&(name, key)).map_err(|_| MachineIOError::Internal)?;
        self.facts.delete(&key_vec);
        Ok(())
    }

    fn fact_query(
        &self,
        name: String,
        key: impl IntoIterator<Item = FactKey>,
    ) -> Result<Self::QueryIterator<'_>, MachineIOError> {
        let key: Vec<_> = key.into_iter().collect();
        let c = VmFactCursor::new(name, key, self.facts)?;
        Ok(c)
    }

    fn emit(&mut self, name: String, fields: impl IntoIterator<Item = KVPair>) {
        let fields: Vec<_> = fields.into_iter().collect();
        self.emit_stack.push((name, fields));
    }

    fn effect(&mut self, name: String, fields: impl IntoIterator<Item = KVPair>) {
        let fields: Vec<_> = fields.into_iter().collect();
        self.sink.consume((name, fields));
    }

    fn call(
        &mut self,
        _module: usize,
        _procedure: usize,
        _stack: &mut ST,
    ) -> Result<(), MachineError> {
        // FFI not implemented in this yet
        Err(MachineError::new(MachineErrorType::Unknown))
    }
}

/// A [Policy](crate::engine::Policy) implementation that uses the Policy VM.
pub struct VmPolicy {
    machine: Machine,
}

impl VmPolicy {
    /// Create a new `VmPolicy` by compiling a policy document. Returns [VmPolicyError]
    /// if the document cannot be compiled.
    pub fn new(machine: Machine) -> Result<VmPolicy, VmPolicyError> {
        Ok(VmPolicy { machine })
    }

    fn evaluate_rule<'a, P>(
        &self,
        kind: &str,
        fields: &[KVPair],
        facts: &'a mut P,
        sink: &'a mut impl Sink<(String, Vec<KVPair>)>,
    ) -> Result<bool, EngineError>
    where
        P: FactPerspective,
    {
        let mut io = VmPolicyIO::new(facts, sink);
        let mut rs = self.machine.create_run_state(&mut io);
        let self_data = Struct::new(kind, fields);
        match rs.call_command_policy(&self_data.name, &self_data) {
            Ok(status) => match status {
                MachineStatus::Exited => Ok(true),
                MachineStatus::Panicked => Ok(false),
                // call_command_policy should never return Executing
                MachineStatus::Executing => Err(EngineError::InternalError),
            },
            Err(_) => {
                // TODO(chip): Report the VM error somehow
                Err(EngineError::InternalError)
            }
        }
    }
}

impl Policy for VmPolicy {
    type Payload<'a> = (String, Vec<KVPair>);

    type Actions<'a> = (&'a str, Cow<'a, [Value]>);

    type Effects = (String, Vec<KVPair>);

    type Command<'a> = VmCommand<'a>;

    fn serial(&self) -> u32 {
        // TODO(chip): Implement an actual serial number
        0u32
    }

    fn call_rule<'a>(
        &self,
        command: &impl Command<'a>,
        facts: &mut impl FactPerspective,
        sink: &mut impl Sink<Self::Effects>,
    ) -> Result<bool, EngineError> {
        let unpacked: VmCommandData =
            postcard::from_bytes(command.bytes()).map_err(|_| EngineError::Read)?;

        let passed = match unpacked {
            // Init always passes, since it is the root
            VmCommandData::Init { .. } => true,
            // Merges always pass because they're an artifact of the graph
            VmCommandData::Merge { .. } => true,
            VmCommandData::Basic { kind, fields, .. } => {
                self.evaluate_rule(&kind, fields.as_slice(), facts, sink)?
            }
        };

        Ok(passed)
    }

    fn call_action(
        &self,
        parent: &Id,
        (name, args): Self::Actions<'_>,
        facts: &mut impl Perspective,
        sink: &mut impl Sink<Self::Effects>,
    ) -> Result<bool, EngineError> {
        let emit_stack = {
            let mut io = VmPolicyIO::new(facts, sink);
            let mut rs = self.machine.create_run_state(&mut io);
            let status = match args {
                Cow::Borrowed(args) => rs.call_action(name, args.iter().cloned()),
                Cow::Owned(args) => rs.call_action(name, args),
            }
            .map_err(|_| EngineError::InternalError)?;
            match status {
                MachineStatus::Exited => (),
                MachineStatus::Panicked => return Ok(false),
                MachineStatus::Executing => return Err(EngineError::InternalError),
            };
            io.into_emit_stack()
        };
        for c in emit_stack {
            let mut buffer = [0u8; MAX_COMMAND_LENGTH];
            let new_command = self.basic(&mut buffer, *parent, c.clone())?;

            let passed = self.evaluate_rule(&c.0, &c.1, facts, sink)?;
            if passed {
                facts
                    .add_command(&new_command)
                    .map_err(|_| EngineError::Write)?;
            } else {
                // Should this early return on failure or continue the
                // rest of the queued commands?
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn read_command<'a>(&self, data: &'a [u8]) -> Result<Self::Command<'a>, EngineError> {
        let unpacked: VmCommandData = postcard::from_bytes(data).map_err(|_| EngineError::Read)?;
        let id = Id::hash_for_testing_only(data);
        Ok(VmCommand { data, id, unpacked })
    }

    fn init<'a>(
        &self,
        target: &'a mut [u8],
        _policy_data: &[u8],
        _payload: Self::Payload<'_>,
    ) -> Result<Self::Command<'a>, EngineError> {
        let c = VmCommandData::Init {
            // TODO(chip): this is a placeholder and needs to be updated to a real
            // policy... whatever this is for.
            policy: 0u64.to_le_bytes(),
        };
        postcard::to_slice(&c, target).map_err(|_| EngineError::Write)?;
        // TODO(chip): calculate the proper ID including the signature
        let id = Id::hash_for_testing_only(target);
        Ok(VmCommand {
            data: target,
            id,
            unpacked: c,
        })
    }

    fn merge<'a>(
        &self,
        target: &'a mut [u8],
        ids: MergeIds,
    ) -> Result<Self::Command<'a>, EngineError> {
        let (left, right) = ids.into();
        let c = VmCommandData::Merge { left, right };
        postcard::to_slice(&c, target).map_err(|_| EngineError::Write)?;
        let id = Id::hash_for_testing_only(target);
        Ok(VmCommand {
            data: target,
            id,
            unpacked: c,
        })
    }

    fn basic<'a>(
        &self,
        target: &'a mut [u8],
        parent: Id,
        (kind, fields): Self::Payload<'_>,
    ) -> Result<Self::Command<'a>, EngineError> {
        let c = VmCommandData::Basic {
            parent,
            kind,
            fields,
        };
        let data = postcard::to_slice(&c, target).map_err(|_| EngineError::Write)?;
        let id = Id::hash_for_testing_only(data);
        Ok(VmCommand {
            data,
            id,
            unpacked: c,
        })
    }
}

#[cfg(test)]
mod tests;
