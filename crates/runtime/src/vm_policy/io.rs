extern crate alloc;

use alloc::{boxed::Box, string::String, vec, vec::Vec};
use core::ops::{Deref, DerefMut};

use policy_vm::{
    ffi::FfiModule, CommandContext, FactKey, FactValue, KVPair, MachineError, MachineErrorType,
    MachineIO, MachineIOError, MachineStack,
};
use tracing::error;

use crate::{FactPerspective, Keys, Query, Sink, VmEffect};

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
    publish_stack: Vec<(String, Vec<KVPair>)>,
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
            publish_stack: vec![],
            engine,
            ffis,
        }
    }

    /// Consumes the `VmPolicyIO` object and produces the publish stack.
    pub fn into_publish_stack(self) -> Vec<(String, Vec<KVPair>)> {
        self.publish_stack
    }
}

impl<'o, P, S, E, FFI> MachineIO<MachineStack> for VmPolicyIO<'o, P, S, E, FFI>
where
    P: FactPerspective,
    S: Sink<VmEffect>,
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
        let keys = ser_keys(key)?;
        let value = ser_values(value)?;
        self.facts.insert(name, keys, value);
        Ok(())
    }

    fn fact_delete(
        &mut self,
        name: String,
        key: impl IntoIterator<Item = FactKey>,
    ) -> Result<(), MachineIOError> {
        let keys = ser_keys(key)?;
        self.facts.delete(name, keys);
        Ok(())
    }

    fn fact_query(
        &self,
        name: String,
        key: impl IntoIterator<Item = FactKey>,
    ) -> Result<Self::QueryIterator<'_>, MachineIOError> {
        let keys = ser_keys(key)?;
        let iter = self.facts.query_prefix(&name, &keys).map_err(|e| {
            error!("query failed: {e}");
            MachineIOError::Internal
        })?;
        Ok(VmFactCursor { iter })
    }

    fn publish(&mut self, name: String, fields: impl IntoIterator<Item = KVPair>) {
        let fields: Vec<_> = fields.into_iter().collect();
        self.publish_stack.push((name, fields));
    }

    fn effect(&mut self, name: String, fields: impl IntoIterator<Item = KVPair>) {
        let fields: Vec<_> = fields.into_iter().collect();
        self.sink.consume(VmEffect { name, fields });
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

fn ser_keys(key: impl IntoIterator<Item = FactKey>) -> Result<Keys, MachineIOError> {
    key.into_iter()
        .map(|k| postcard::to_allocvec(&k))
        .collect::<Result<Keys, _>>()
        .map_err(|e| {
            error!("could not serialize key: {e}");
            MachineIOError::Internal
        })
}

fn deser_keys(keys: Keys) -> Result<Vec<FactKey>, MachineIOError> {
    keys.as_ref()
        .iter()
        .map(|k| postcard::from_bytes(k))
        .collect::<Result<_, _>>()
        .map_err(|e| {
            error!("could not deserialize key: {e}");
            MachineIOError::Internal
        })
}

fn ser_values(value: impl IntoIterator<Item = FactValue>) -> Result<Box<[u8]>, MachineIOError> {
    let value: Vec<_> = value.into_iter().collect();
    let bytes = postcard::to_allocvec(&value).map_err(|e| {
        error!("fact_insert: could not serialize value: {e}");
        MachineIOError::Internal
    })?;
    Ok(bytes.into())
}

fn deser_values(value: Box<[u8]>) -> Result<Vec<FactValue>, MachineIOError> {
    postcard::from_bytes(&value).map_err(|e| {
        error!("could not deserialize values: {e}");
        MachineIOError::Internal
    })
}

/// An Iterator that returns a sequence of matching facts from a query. It is produced by
/// the [VmPolicyIO](super::VmPolicyIO) when a query is made by the VM.
pub struct VmFactCursor<'o, P: Query + 'o> {
    iter: P::QueryIterator<'o>,
}

impl<'o, P: Query> Iterator for VmFactCursor<'o, P> {
    type Item = Result<(Vec<FactKey>, Vec<FactValue>), MachineIOError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|b| -> Self::Item {
            let b = b.map_err(|e| {
                error!("error during query: {e}");
                MachineIOError::Internal
            })?;
            let k = deser_keys(b.key)?;
            let v = deser_values(b.value)?;
            Ok((k, v))
        })
    }
}
