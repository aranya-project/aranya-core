//! Type driven serialization and deserialization.
//!
//! Since we know the exact type of policy values, we can greatly reduce the serialized size by serializing only the underlying values in schema order.
//!
//! This should match the postcard serialization of the corresponding rust type.

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::convert::Infallible;

use aranya_id::BaseId;
use aranya_policy_ast::{FieldDefinition, Identifier, TypeKind};
use postcard_core::de::Flavor as _;

use crate::{Struct, Value};

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SerializeError {
    #[error("unknown struct {0}")]
    UnknownStruct(Identifier),
    #[error("missing field {0}")]
    MissingField(Identifier),
    #[error("field length mismatch")]
    FieldLengthMismatch,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum DeserializeError {
    #[error("unexpected end")]
    UnexpectedEnd,
    #[error("trailing data")]
    TrailingData,
    #[error("bad input")]
    BadInput,
}

use DeserializeError::BadInput as Bad;

pub(crate) fn serialize_struct(
    defs: &BTreeMap<Identifier, Vec<FieldDefinition>>,
    s: &Struct,
) -> Result<Vec<u8>, SerializeError> {
    let mut ctx = SerializeCtx {
        defs,
        out: Vec::new(),
    };
    ctx.serialize_struct(s)?;
    Ok(ctx.out)
}

pub(crate) fn deserialize_struct(
    defs: &BTreeMap<Identifier, Vec<FieldDefinition>>,
    name: Identifier,
    bytes: &[u8],
) -> Result<Struct, DeserializeError> {
    let mut ctx = DeserializeCtx { defs, bytes };
    let s = ctx.deserialize_struct(name)?;
    if !ctx.bytes.is_empty() {
        return Err(DeserializeError::TrailingData);
    }
    Ok(s)
}

struct SerializeCtx<'a> {
    defs: &'a BTreeMap<Identifier, Vec<FieldDefinition>>,
    out: Vec<u8>,
}

impl SerializeCtx<'_> {
    fn serialize_struct(&mut self, s: &Struct) -> Result<(), SerializeError> {
        let def = self
            .defs
            .get(&s.name)
            .ok_or_else(|| SerializeError::UnknownStruct(s.name.clone()))?;
        if def.len() != s.fields.len() {
            return Err(SerializeError::FieldLengthMismatch);
        }
        for d in def {
            let v = s
                .fields
                .get(d.identifier.as_str())
                .ok_or_else(|| SerializeError::MissingField(d.identifier.name.clone()))?;
            self.serialize_value(v)?;
        }
        Ok(())
    }

    fn serialize_value(&mut self, v: &Value) -> Result<(), SerializeError> {
        match v {
            Value::Int(x) => postcard_core::ser::try_push_i64(self, *x)?,
            Value::Bool(x) => postcard_core::ser::try_push_bool(self, *x)?,
            Value::String(x) => postcard_core::ser::try_push_str(self, x)?,
            Value::Bytes(x) => postcard_core::ser::try_push_bytes(self, x)?,
            Value::Struct(x) => self.serialize_struct(x)?,
            Value::Id(x) => {
                self.out.push(32);
                self.out.extend_from_slice(x.as_bytes());
            }
            Value::Enum(_, x) => postcard_core::ser::try_push_i64(self, *x)?,
            Value::Option(x) => match x {
                None => {
                    self.out.push(0);
                }
                Some(x) => {
                    self.out.push(1);
                    self.serialize_value(x)?;
                }
            },
            Value::Result(x) => match x {
                Ok(x) => {
                    self.out.push(0);
                    self.serialize_value(x)?;
                }
                Err(x) => {
                    self.out.push(1);
                    self.serialize_value(x)?;
                }
            },
            Value::Identifier(_) | Value::Fact(_) => unreachable!(),
        }
        Ok(())
    }
}

impl postcard_core::ser::Flavor for SerializeCtx<'_> {
    type Output = Vec<u8>;
    type PushError = Infallible;
    type FinalizeError = Infallible;

    fn try_push(&mut self, data: u8) -> Result<(), Self::PushError> {
        self.out.push(data);
        Ok(())
    }

    fn finalize(self) -> Result<Self::Output, Self::FinalizeError> {
        Ok(self.out)
    }

    fn try_extend(&mut self, data: &[u8]) -> Result<(), Self::PushError> {
        self.out.extend_from_slice(data);
        Ok(())
    }
}

struct DeserializeCtx<'a> {
    defs: &'a BTreeMap<Identifier, Vec<FieldDefinition>>,
    bytes: &'a [u8],
}

impl DeserializeCtx<'_> {
    fn deserialize_struct(&mut self, name: Identifier) -> Result<Struct, DeserializeError> {
        let def = self.defs.get(&name).ok_or(Bad)?;
        let mut fields = BTreeMap::new();
        for d in def {
            let v = self.deserialize_value(&d.field_type.kind)?;
            fields.insert(d.identifier.name.clone(), v);
        }
        Ok(Struct::new(name, fields))
    }

    fn deserialize_value(&mut self, kind: &TypeKind) -> Result<Value, DeserializeError> {
        Ok(match kind {
            TypeKind::String => {
                let x = postcard_core::de::try_take_str_temp(self)?.ok_or(Bad)?;
                let x = x.parse().map_err(|_| Bad)?;
                Value::String(x)
            }
            TypeKind::Bytes => {
                let x = postcard_core::de::try_take_bytes_temp(self)?.ok_or(Bad)?;
                Value::Bytes(x.to_vec())
            }
            TypeKind::Int => {
                let x = postcard_core::de::try_take_i64(self)?.ok_or(Bad)?;
                Value::Int(x)
            }
            TypeKind::Bool => {
                let x = postcard_core::de::try_take_bool(self)?.ok_or(Bad)?;
                Value::Bool(x)
            }
            TypeKind::Id => {
                let len = self.pop()?;
                if len != 32 {
                    return Err(Bad);
                }
                let x = self.take_exact()?;
                Value::Id(BaseId::from_bytes(*x))
            }
            TypeKind::Struct(ident) => {
                let x = self.deserialize_struct(ident.name.clone())?;
                Value::Struct(x)
            }
            TypeKind::Enum(ident) => {
                let x = postcard_core::de::try_take_i64(self)?.ok_or(Bad)?;
                Value::Enum(ident.name.clone(), x)
            }
            TypeKind::Optional(vtype) => {
                let tag = self.pop()?;
                match tag {
                    0 => Value::NONE,
                    1 => Value::Option(Some(Box::new(self.deserialize_value(&vtype.kind)?))),
                    _ => return Err(Bad),
                }
            }
            TypeKind::Result(res) => {
                let tag = self.pop()?;
                Value::Result(match tag {
                    0 => Ok(Box::new(self.deserialize_value(&res.ok.kind)?)),
                    1 => Err(Box::new(self.deserialize_value(&res.err.kind)?)),
                    _ => return Err(Bad),
                })
            }
            TypeKind::Never => return Err(Bad),
        })
    }

    fn take_exact<const N: usize>(&mut self) -> Result<&[u8; N], DeserializeError> {
        let x;
        (x, self.bytes) = self
            .bytes
            .split_first_chunk()
            .ok_or(DeserializeError::UnexpectedEnd)?;
        Ok(x)
    }
}

impl<'de, 'i: 'de> postcard_core::de::Flavor<'de> for DeserializeCtx<'i> {
    type Remainder = &'i [u8];
    type Source = ();
    type PopError = DeserializeError;
    type FinalizeError = Infallible;

    fn pop(&mut self) -> Result<u8, Self::PopError> {
        self.bytes
            .split_off_first()
            .copied()
            .ok_or(DeserializeError::UnexpectedEnd)
    }

    fn try_take_n(&mut self, ct: usize) -> Result<&'de [u8], Self::PopError> {
        self.bytes
            .split_off(..ct)
            .ok_or(DeserializeError::UnexpectedEnd)
    }

    fn finalize(self) -> Result<Self::Remainder, Self::FinalizeError> {
        Ok(self.bytes)
    }
}

impl From<Infallible> for SerializeError {
    fn from(err: Infallible) -> Self {
        match err {}
    }
}

impl From<Infallible> for DeserializeError {
    fn from(err: Infallible) -> Self {
        match err {}
    }
}
