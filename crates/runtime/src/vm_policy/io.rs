extern crate alloc;

use alloc::{boxed::Box, string::String, vec, vec::Vec};
use core::ops::{Deref, DerefMut};

use policy_vm::{
    ffi::FfiModule, CommandContext, FactKey, FactValue, KVPair, MachineError, MachineErrorType,
    MachineIO, MachineIOError, MachineStack,
};
use tracing::error;

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
pub struct VmPolicyIO<'o, P, S, E, FFI> {
    facts: &'o mut P,
    sink: &'o mut S,
    emit_stack: Vec<(String, Vec<KVPair>)>,
    engine: &'o mut E,
    ffis: &'o mut [FFI],
}

pub type FfiList<'a, E> = &'a mut [&'a mut dyn FfiCallable<E>];

impl<'o, P, S, E, FFI> VmPolicyIO<'o, P, S, E, FFI> {
    /// Creates a new `VmPolicyIO` for a [FactPerspective](crate::storage::FactPerspective) and a
    /// [Sink](crate::engine::Sink).
    pub fn new(
        facts: &'o mut P,
        sink: &'o mut S,
        engine: &'o mut E,
        ffis: &'o mut [FFI],
    ) -> VmPolicyIO<'o, P, S, E, FFI> {
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

impl<'o, P, S, E, FFI> MachineIO<MachineStack> for VmPolicyIO<'o, P, S, E, FFI>
where
    P: FactPerspective,
    S: Sink<(String, Vec<KVPair>)>,
    E: crypto::Engine,
    FFI: DerefMut,
    <FFI as Deref>::Target: FfiCallable<E>,
{
    type QueryIterator<'c> = VmFactCursor<'c, P> where Self: 'c;

    fn fact_insert(
        &mut self,
        name: String,
        key: impl IntoIterator<Item = FactKey>,
        value: impl IntoIterator<Item = FactValue>,
    ) -> Result<(), MachineIOError> {
        let key: Vec<_> = key.into_iter().collect();
        let key_vec = postcard::to_allocvec(&(name, key)).map_err(|e| {
            error!("fact_insert: could not serialize key: {e}");
            MachineIOError::Internal
        })?;
        let value: Vec<_> = value.into_iter().collect();
        let value_vec = postcard::to_allocvec(&value).map_err(|e| {
            error!("fact_insert: could not serialize value: {e}");
            MachineIOError::Internal
        })?;
        self.facts.insert(&key_vec, &value_vec);
        Ok(())
    }

    fn fact_delete(
        &mut self,
        name: String,
        key: impl IntoIterator<Item = FactKey>,
    ) -> Result<(), MachineIOError> {
        let key: Vec<_> = key.into_iter().collect();
        let key_vec = postcard::to_allocvec(&(name, key)).map_err(|e| {
            error!("fact_delete: could not serialize key: {e}");
            MachineIOError::Internal
        })?;
        self.facts.delete(&key_vec);
        Ok(())
    }

    fn fact_query(
        &self,
        name: String,
        key: impl IntoIterator<Item = FactKey>,
    ) -> Result<Self::QueryIterator<'_>, MachineIOError> {
        let key: Vec<_> = key.into_iter().collect();
        let c = VmFactCursor::new(name, key, self.facts).map_err(|e| {
            error!("fact_query: could not crate cursor: {e}");
            MachineIOError::Internal
        })?;
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
            |ffi| ffi.call(procedure, stack, ctx, self.engine),
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
