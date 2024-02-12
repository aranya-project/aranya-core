extern crate alloc;

use alloc::{boxed::Box, string::String, vec, vec::Vec};

use crypto::default::{DefaultCipherSuite, DefaultEngine, Rng};
use perspective_ffi::FfiPerspective;
use policy_vm::{
    ffi::FfiModule, CommandContext, FactKey, FactValue, KVPair, MachineError, MachineErrorType,
    MachineIO, MachineIOError, Stack,
};

use super::ffi::envelope::FfiEnvelope;
use crate::{FactPerspective, Sink, StorageError, VmFactCursor};

/// Implements the `MachineIO` interface for [VmPolicy](super::VmPolicy).
pub struct VmPolicyIO<'o, P, S>
where
    P: FactPerspective,
    S: Sink<(String, Vec<KVPair>)>,
{
    facts: &'o mut P,
    sink: &'o mut S,
    emit_stack: Vec<(String, Vec<KVPair>)>,
    engine: DefaultEngine<Rng, DefaultCipherSuite>,
    // FFI modules
    envelope_module: FfiEnvelope,
    perspective_module: FfiPerspective,
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
        let (engine, _) = DefaultEngine::from_entropy(Rng);
        VmPolicyIO {
            facts,
            sink,
            emit_stack: vec![],
            engine,
            envelope_module: FfiEnvelope {},
            perspective_module: FfiPerspective {},
        }
    }

    /// Consumes the `VmPolicyIO object and produces the emit stack.
    pub fn into_emit_stack(self) -> Vec<(String, Vec<KVPair>)> {
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
        module: usize,
        procedure: usize,
        stack: &mut ST,
        ctx: &CommandContext<'_>,
    ) -> Result<(), MachineError> {
        match module {
            0 => self
                .envelope_module
                .call(procedure, stack, ctx, &mut self.engine)
                .map_err(|e| MachineError::new(MachineErrorType::IO(e))),
            1 => self
                .perspective_module
                .call(procedure, stack, ctx, &mut self.engine)
                .map_err(|_| MachineError::new(MachineErrorType::Unknown)),
            _ => Err(MachineError::new(MachineErrorType::FfiModuleNotDefined(
                module,
            ))),
        }
    }
}

pub struct NullFacts;

impl FactPerspective for NullFacts {
    fn query(&self, _key: &[u8]) -> Result<Option<Box<[u8]>>, StorageError> {
        Err(StorageError::IoError)
    }

    fn insert(&mut self, _key: &[u8], _value: &[u8]) {}

    fn delete(&mut self, _key: &[u8]) {}
}
