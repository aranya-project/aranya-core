//! Type driven serialization and deserialization.
//!
//! Since we know the exact type of policy values, we can greatly reduce the serialized size by
//! serializing only the underlying values in schema order.
//!
//! This uses the same format as if we serialized the corresponding rust types with postcard.

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::convert::Infallible;

use aranya_id::BaseId;
use aranya_policy_ast::{FieldDefinition, Identifier, TypeKind};
use postcard_core::de::Flavor as _;

use crate::{Struct, Value};

/// Serialize error.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SerializeError {
    /// Cannot find definition for this struct.
    #[error("cannot find definition for `struct {0}`")]
    UnknownStruct(Identifier),
    /// Struct value was missing field from definition.
    #[error("struct value was missing field `{0}`")]
    MissingField(Identifier),
    /// Struct value and definition have a different number of fields.
    #[error("struct value and definition have a different number of fields")]
    FieldLengthMismatch,
    /// Cannot serialize internal value.
    #[error("cannot serialize internal value")]
    InternalValue,
}

/// Deserialize error.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum DeserializeError {
    /// Cannot find definition for this struct.
    #[error("cannot find definition for `struct {0}`")]
    UnknownStruct(Identifier),
    /// Expected more bytes at end of input.
    #[error("expected more bytes at end of input")]
    UnexpectedEnd,
    /// Input has extra data after deserialization has finished.
    #[error("input has extra data after deserialization has finished")]
    TrailingData,
    /// The contents of the input data are invalid for the schema.
    #[error("the contents of the input data are invalid for the schema")]
    BadInput,
}

type StructDefs = BTreeMap<Identifier, Vec<FieldDefinition>>;

/// Serialize a [`Struct`] to be deserialized with [`deserialize_struct`].
pub(crate) fn serialize_struct(defs: &StructDefs, s: &Struct) -> Result<Vec<u8>, SerializeError> {
    let mut ctx = SerializeCtx {
        defs,
        out: Vec::new(),
    };
    ctx.serialize_struct(s)?;
    Ok(ctx.out)
}

/// Deserialize a [`Struct`] which was serialized with [`deserialize_struct`].
pub(crate) fn deserialize_struct(
    defs: &StructDefs,
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

const ID_SIZE: u8 = size_of::<BaseId>() as u8;

struct SerializeCtx<'a> {
    defs: &'a StructDefs,
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
                self.out.push(ID_SIZE);
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
            Value::Identifier(_) | Value::Fact(_) => return Err(SerializeError::InternalValue),
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
    defs: &'a StructDefs,
    bytes: &'a [u8],
}

impl DeserializeCtx<'_> {
    fn deserialize_struct(&mut self, name: Identifier) -> Result<Struct, DeserializeError> {
        let def = self
            .defs
            .get(&name)
            .ok_or_else(|| DeserializeError::UnknownStruct(name.clone()))?;
        let mut fields = BTreeMap::new();
        for d in def {
            let v = self.deserialize_value(&d.field_type.kind)?;
            fields.insert(d.identifier.name.clone(), v);
        }
        Ok(Struct::new(name, fields))
    }

    fn deserialize_value(&mut self, kind: &TypeKind) -> Result<Value, DeserializeError> {
        use DeserializeError::BadInput as Bad;

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
                if len != ID_SIZE {
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

#[cfg(test)]
mod test {
    use aranya_policy_ast::{Text, Version, ident, text};
    use aranya_policy_compiler::Compiler;
    use aranya_policy_lang::lang::parse_policy_str;
    use aranya_policy_module::ModuleData;

    use super::*;

    #[test]
    fn test_round_trip_with_rust_type() {
        let src = r#"
            enum Answer {
                Yes,
                No,
            }

            struct Complex {
                m_int int,
                m_bool bool,
                m_string string,
                m_id id,
                m_some option[int],
                m_none option[int],
                m_ok result[int, string],
                m_err result[int, string],
                m_enum enum Answer,
                m_struct struct Simple,
            }

            struct Simple {
                m_int int,
            }
        "#;

        #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        enum Answer {
            Yes,
            No,
        }

        #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        struct Complex {
            m_int: i64,
            m_bool: bool,
            m_string: Text,
            m_id: BaseId,
            m_some: Option<i64>,
            m_none: Option<i64>,
            m_ok: Result<i64, Text>,
            m_err: Result<i64, Text>,
            m_enum: Answer,
            m_struct: Simple,
        }

        #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        struct Simple {
            m_int: i64,
        }

        let defs = {
            let policy = parse_policy_str(src, Version::V2).unwrap();
            let ModuleData::V0(m) = Compiler::new(&policy).compile().unwrap().data;
            m.struct_defs
        };

        let id = BaseId::from_bytes(core::array::from_fn(|i| u8::MAX - i as u8));

        let rust_in = Complex {
            m_int: 1,
            m_bool: false,
            m_string: text!("hello"),
            m_id: id,
            m_some: Some(2),
            m_none: None,
            m_ok: Ok(4),
            m_err: Err(text!("uh oh")),
            m_enum: Answer::Yes,
            m_struct: Simple { m_int: 3 },
        };

        let rust_ser = postcard::to_allocvec(&rust_in).unwrap();
        let value_de = deserialize_struct(&defs, ident!("Complex"), &rust_ser).unwrap();
        let value_ser = serialize_struct(&defs, &value_de).unwrap();
        let rust_de: Complex = postcard::from_bytes(&value_ser).unwrap();

        assert_eq!(rust_in, rust_de);
        assert_eq!(rust_ser, value_ser);
    }
}
