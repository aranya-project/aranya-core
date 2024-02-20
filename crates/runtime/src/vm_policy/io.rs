extern crate alloc;

use alloc::{boxed::Box, string::String, vec, vec::Vec};
use core::ops::{Deref, DerefMut};

use crypto::default::{DefaultCipherSuite, DefaultEngine, Rng};
use policy_vm::{
    ffi::FfiModule, CommandContext, FactKey, FactValue, KVPair, MachineError, MachineErrorType,
    MachineIO, MachineIOError, MachineStack,
};

use crate::{FactPerspective, Sink, StorageError, VmFactCursor};

/// Object safe wrapper for [`FfiModule`].
pub trait FfiCallable<E> {
    /// Invokes a function in the module.
    fn call(
        &mut self,
        procedure: usize,
        stack: &mut MachineStack,
        ctx: &CommandContext<'_>,
        eng: &mut E,
    ) -> Result<(), MachineError>;
}

impl<FM, E> FfiCallable<E> for FM
where
    FM: FfiModule,
    E: crypto::Engine,
{
    fn call(
        &mut self,
        procedure: usize,
        stack: &mut MachineStack,
        ctx: &CommandContext<'_>,
        eng: &mut E,
    ) -> Result<(), MachineError> {
        FM::call(self, procedure, stack, ctx, eng).map_err(Into::into)
    }
}

/// Implements the `MachineIO` interface for [VmPolicy](super::VmPolicy).
pub struct VmPolicyIO<'o, P, S, FFI>
where
    P: FactPerspective,
    S: Sink<(String, Vec<KVPair>)>,
{
    facts: &'o mut P,
    sink: &'o mut S,
    emit_stack: Vec<(String, Vec<KVPair>)>,
    engine: DefaultEngine<Rng, DefaultCipherSuite>,
    ffis: &'o mut [FFI],
}

impl<'o, P, S, FFI> VmPolicyIO<'o, P, S, FFI>
where
    P: FactPerspective,
    S: Sink<(String, Vec<KVPair>)>,
{
    /// Creates a new `VmPolicyIO` for a [FactPerspective](crate::storage::FactPerspective) and a
    /// [Sink](crate::engine::Sink).
    pub fn new(
        facts: &'o mut P,
        sink: &'o mut S,
        ffis: &'o mut [FFI],
    ) -> VmPolicyIO<'o, P, S, FFI> {
        let (engine, _) = DefaultEngine::from_entropy(Rng);

        VmPolicyIO {
            facts,
            sink,
            emit_stack: vec![],
            engine,
            ffis,
        }
    }

    /// Consumes the `VmPolicyIO object and produces the emit stack.
    pub fn into_emit_stack(self) -> Vec<(String, Vec<KVPair>)> {
        self.emit_stack
    }
}

impl<'o, P, S, FFI> MachineIO<MachineStack> for VmPolicyIO<'o, P, S, FFI>
where
    P: FactPerspective,
    S: Sink<(String, Vec<KVPair>)>,
    FFI: DerefMut,
    <FFI as Deref>::Target: FfiCallable<DefaultEngine<Rng>>,
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
        stack: &mut MachineStack,
        ctx: &CommandContext<'_>,
    ) -> Result<(), MachineError> {
        self.ffis.get_mut(module).map_or(
            Err(MachineError::new(MachineErrorType::FfiModuleNotDefined(
                module,
            ))),
            |ffi| ffi.call(procedure, stack, ctx, &mut self.engine),
        )
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
