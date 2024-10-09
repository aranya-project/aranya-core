extern crate alloc;

use alloc::{boxed::Box, string::String, vec, vec::Vec};
use core::ops::{Deref, DerefMut};

use aranya_crypto::Id;
use aranya_policy_vm::{
    ffi::FfiModule, CommandContext, FactKey, FactValue, HashableValue, KVPair, MachineError,
    MachineErrorType, MachineIO, MachineIOError, MachineStack,
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
    E: aranya_crypto::Engine,
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
    /// Creates a new `VmPolicyIO` for a [`crate::storage::FactPerspective`] and a
    /// [`crate::engine::Sink`].
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
    E: aranya_crypto::Engine,
    FFI: DerefMut,
    <FFI as Deref>::Target: FfiCallable<E>,
{
    type QueryIterator = VmFactCursor<P>;

    fn fact_insert(
        &mut self,
        name: String,
        key: impl IntoIterator<Item = FactKey>,
        value: impl IntoIterator<Item = FactValue>,
    ) -> Result<(), MachineIOError> {
        let keys = ser_keys(key);
        let value = ser_values(value)?;
        self.facts.insert(name, keys, value);
        Ok(())
    }

    fn fact_delete(
        &mut self,
        name: String,
        key: impl IntoIterator<Item = FactKey>,
    ) -> Result<(), MachineIOError> {
        let keys = ser_keys(key);
        self.facts.delete(name, keys);
        Ok(())
    }

    fn fact_query(
        &self,
        name: String,
        key: impl IntoIterator<Item = FactKey>,
    ) -> Result<Self::QueryIterator, MachineIOError> {
        let keys = ser_keys(key);
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

    fn effect(
        &mut self,
        name: String,
        fields: impl IntoIterator<Item = KVPair>,
        command: Id,
        recalled: bool,
    ) {
        let fields: Vec<_> = fields.into_iter().collect();
        self.sink.consume(VmEffect {
            name,
            fields,
            command: command.into(),
            recalled,
        });
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

// pub(crate) for testing
/// Serializes an iterator of [`FactKey`]s into [`Keys`] for storage.
pub(crate) fn ser_keys(keys: impl IntoIterator<Item = FactKey>) -> Keys {
    keys.into_iter().map(|key| ser_key(&key)).collect()
}

/// Deserializes [`Keys`] into a sequence of [`FactKey`]s.
fn deser_keys(keys: Keys) -> Result<Vec<FactKey>, MachineIOError> {
    keys.as_ref()
        .iter()
        .map(|key| {
            deser_key(key).map_err(|err| {
                error!(?err, ?key, "could not deserialize key");
                MachineIOError::Internal
            })
        })
        .collect::<Result<_, _>>()
}

#[repr(u8)]
enum KeyType {
    Int,
    Bool,
    String,
    Id,
}

impl KeyType {
    fn from_u8(val: u8) -> Option<KeyType> {
        Some(match val {
            0 => KeyType::Int,
            1 => KeyType::Bool,
            2 => KeyType::String,
            3 => KeyType::Id,
            _ => return None,
        })
    }
}

/// Serializes a `FactKey` into bytes.
///
/// This preserves the ordering for two facts with the same identifier and value type.
/// This is important for the ordering of fact iteration in prefix queries.
fn ser_key(FactKey { identifier, value }: &FactKey) -> Box<[u8]> {
    let identifier_len = (identifier.len() as u64).to_be_bytes();

    let int_bytes;
    let (tag, value_bytes) = match value {
        &HashableValue::Int(int) => {
            // flip sign bit and use big-endian to preserve ordering.
            int_bytes = i64::to_be_bytes(int ^ (1 << 63));
            (KeyType::Int, int_bytes.as_slice())
        }
        &HashableValue::Bool(bool) => {
            let bytes = if bool { &[1] } else { &[0] };
            (KeyType::Bool, bytes.as_slice())
        }
        HashableValue::String(string) => (KeyType::String, string.as_bytes()),
        HashableValue::Id(id) => (KeyType::Id, id.as_bytes()),
    };

    [
        identifier_len.as_slice(),
        identifier.as_bytes(),
        &[tag as u8],
        value_bytes,
    ]
    .concat()
    .into_boxed_slice()
}

/// Deserializes a key serialized by [`ser_key`].
fn deser_key(bytes: &[u8]) -> Result<FactKey, &'static str> {
    let (&identifier_len, bytes) = bytes
        .split_first_chunk()
        .ok_or("missing identifier length")?;
    let identifier_len =
        usize::try_from(u64::from_be_bytes(identifier_len)).map_err(|_| "identifier too long")?;

    if identifier_len > bytes.len() {
        return Err("identifier too short");
    }
    let (identifier, bytes) = bytes.split_at(identifier_len);
    let identifier = core::str::from_utf8(identifier).map_err(|_| "identifier not utf8")?;

    let (&tag, bytes) = bytes.split_first().ok_or("missing tag")?;
    let tag = KeyType::from_u8(tag).ok_or("invalid tag")?;

    let value = match tag {
        KeyType::Int => {
            let bytes = bytes.try_into().map_err(|_| "invalid integer length")?;
            let int = i64::from_be_bytes(bytes) ^ (1 << 63);
            HashableValue::Int(int)
        }
        KeyType::Bool => {
            let bool = match bytes {
                [0] => false,
                [1] => true,
                _ => return Err("invalid boolean")?,
            };
            HashableValue::Bool(bool)
        }
        KeyType::String => {
            let string = core::str::from_utf8(bytes).map_err(|_| "string not utf8")?;
            HashableValue::String(string.into())
        }
        KeyType::Id => {
            let bytes = bytes.try_into().map_err(|_| "invalid ID length")?;
            let id = Id::from_bytes(bytes);
            HashableValue::Id(id)
        }
    };

    Ok(FactKey {
        identifier: identifier.into(),
        value,
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
pub struct VmFactCursor<P: Query> {
    iter: P::QueryIterator,
}

impl<P: Query> Iterator for VmFactCursor<P> {
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

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10_000))]

        #[test]
        fn test_round_trip(fk1: FactKey) {
            let bytes = ser_key(&fk1);
            let fk2: FactKey = deser_key(&bytes).unwrap();
            assert_eq!(fk1, fk2);
        }

        // These ord tests ensure the encoded values compare the same as the original values.

        #[test]
        fn test_int_ord(identifier: String, v1: i64, v2: i64) {
            let b1 = ser_key(&FactKey {
                identifier: identifier.clone(),
                value: HashableValue::Int(v1),
            });
            let b2 = ser_key(&FactKey {
                identifier,
                value: HashableValue::Int(v2),
            });
            assert_eq!(v1.cmp(&v2), b1.cmp(&b2),  "{b1:?} <=> {b2:?}");
        }

        #[test]
        fn test_bool_ord(identifier: String, v1: bool, v2: bool) {
            let b1 = ser_key(&FactKey {
                identifier: identifier.clone(),
                value: HashableValue::Bool(v1),
            });
            let b2 = ser_key(&FactKey {
                identifier,
                value: HashableValue::Bool(v2),
            });
            assert_eq!(v1.cmp(&v2), b1.cmp(&b2),  "{b1:?} <=> {b2:?}");
        }

        #[test]
        fn test_string_ord(identifier: String, v1: String, v2: String) {
            let cmp = v1.cmp(&v2);
            let b1 = ser_key(&FactKey {
                identifier: identifier.clone(),
                value: HashableValue::String(v1),
            });
            let b2 = ser_key(&FactKey {
                identifier,
                value: HashableValue::String(v2),
            });
            assert_eq!(cmp, b1.cmp(&b2), "{b1:?} <=> {b2:?}");
        }

        #[test]
        fn test_id_ord(identifier: String, v1: Id, v2: Id) {
            let b1 = ser_key(&FactKey {
                identifier: identifier.clone(),
                value: HashableValue::Id(v1),
            });
            let b2 = ser_key(&FactKey {
                identifier,
                value: HashableValue::Id(v2),
            });
            assert_eq!(v1.cmp(&v2), b1.cmp(&b2),  "{b1:?} <=> {b2:?}");
        }
    }
}
