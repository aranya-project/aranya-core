//! Type driven serialization and deserialization.

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

use aranya_policy_ast::{FieldDefinition, Identifier, TypeKind};

use crate::{Struct, Value, error::MachineError};

pub(crate) fn serialize_struct(
    defs: &BTreeMap<Identifier, Vec<FieldDefinition>>,
    s: &Struct,
) -> Result<Vec<u8>, MachineError> {
    serialize_struct_(defs, s, Vec::new())
}

pub(crate) fn deserialize_struct(
    defs: &BTreeMap<Identifier, Vec<FieldDefinition>>,
    name: Identifier,
    mut bytes: &[u8],
) -> Result<Struct, MachineError> {
    deserialize_struct_(defs, name, &mut bytes)
}

fn serialize_struct_(
    defs: &BTreeMap<Identifier, Vec<FieldDefinition>>,
    s: &Struct,
    mut out: Vec<u8>,
) -> Result<Vec<u8>, MachineError> {
    let def = defs.get(&s.name).unwrap();
    for d in def {
        let v = s.fields.get(d.identifier.as_str()).unwrap();
        out = serialize_value(defs, v, out)?;
    }
    Ok(out)
}

fn deserialize_struct_(
    defs: &BTreeMap<Identifier, Vec<FieldDefinition>>,
    name: Identifier,
    bytes: &mut &[u8],
) -> Result<Struct, MachineError> {
    let def = defs.get(&name).unwrap();
    let mut fields = BTreeMap::new();
    for d in def {
        let v = deserialize_value(defs, &d.field_type.kind, bytes)?;
        fields.insert(d.identifier.name.clone(), v);
    }
    Ok(Struct::new(name, fields))
}

fn serialize_value(
    defs: &BTreeMap<Identifier, Vec<FieldDefinition>>,
    v: &Value,
    mut out: Vec<u8>,
) -> Result<Vec<u8>, MachineError> {
    Ok(match v {
        Value::Int(x) => postcard::to_extend(x, out).unwrap(),
        Value::Bool(x) => postcard::to_extend(x, out).unwrap(),
        Value::String(x) => postcard::to_extend(x, out).unwrap(),
        Value::Bytes(x) => postcard::to_extend(x, out).unwrap(),
        Value::Struct(x) => serialize_struct_(defs, x, out).unwrap(),
        Value::Id(x) => postcard::to_extend(x, out).unwrap(),
        Value::Enum(_, x) => postcard::to_extend(x, out).unwrap(),
        Value::Option(x) => match x {
            None => {
                out.push(0);
                out
            }
            Some(x) => {
                out.push(1);
                serialize_value(defs, x, out).unwrap()
            }
        },
        Value::Result(x) => match x {
            Err(x) => {
                out.push(0);
                serialize_value(defs, x, out).unwrap()
            }
            Ok(x) => {
                out.push(1);
                serialize_value(defs, x, out).unwrap()
            }
        },
        Value::Identifier(_) | Value::Fact(_) => unreachable!(),
    })
}

fn deserialize_value(
    defs: &BTreeMap<Identifier, Vec<FieldDefinition>>,
    kind: &TypeKind,
    bytes: &mut &[u8],
) -> Result<Value, MachineError> {
    Ok(match kind {
        TypeKind::String => {
            let x;
            (x, *bytes) = postcard::take_from_bytes(*bytes).unwrap();
            Value::String(x)
        }
        TypeKind::Bytes => {
            let x;
            (x, *bytes) = postcard::take_from_bytes(*bytes).unwrap();
            Value::Bytes(x)
        }
        TypeKind::Int => {
            let x;
            (x, *bytes) = postcard::take_from_bytes(*bytes).unwrap();
            Value::Int(x)
        }
        TypeKind::Bool => {
            let x;
            (x, *bytes) = postcard::take_from_bytes(*bytes).unwrap();
            Value::Bool(x)
        }
        TypeKind::Id => {
            let x;
            (x, *bytes) = postcard::take_from_bytes(*bytes).unwrap();
            Value::Id(x)
        }
        TypeKind::Struct(ident) => {
            let x = deserialize_struct_(defs, ident.name.clone(), bytes)?;
            Value::Struct(x)
        }
        TypeKind::Enum(ident) => {
            let x;
            (x, *bytes) = postcard::take_from_bytes(*bytes).unwrap();
            Value::Enum(ident.name.clone(), x)
        }
        TypeKind::Optional(vtype) => {
            let &tag = bytes.split_off_first().unwrap();
            match tag {
                0 => Value::NONE,
                1 => Value::Option(Some(Box::new(deserialize_value(defs, &vtype.kind, bytes)?))),
                _ => panic!(),
            }
        }
        TypeKind::Result(res) => {
            let &tag = bytes.split_off_first().unwrap();
            Value::Result(match tag {
                0 => Err(Box::new(deserialize_value(defs, &res.err.kind, bytes)?)),
                1 => Ok(Box::new(deserialize_value(defs, &res.ok.kind, bytes)?)),
                _ => panic!(),
            })
        }
        TypeKind::Never => todo!(),
    })
}
