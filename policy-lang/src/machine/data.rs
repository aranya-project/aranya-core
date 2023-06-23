extern crate alloc;

use alloc::collections::BTreeMap;
use core::fmt::Display;

use serde::{Deserialize, Serialize};

use crate::lang::ast::VType;
use crate::machine::MachineError;

/// A Fact value
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fact {
    /// The name of the fact
    pub name: String,
    /// The keys of the fact
    pub keys: BTreeMap<String, HashableValue>,
    /// The values of the fact
    pub values: BTreeMap<String, Value>,
}

impl Display for Fact {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}[", self.name)?;
        let mut i = false;
        for (k, v) in &self.keys {
            if i {
                write!(f, ", ")?;
            }
            i = true;
            write!(f, "{}: {}", k, v)?;
        }
        write!(f, "]=>{{")?;
        i = false;
        for (k, v) in &self.values {
            if i {
                write!(f, ", ")?;
            }
            i = true;
            write!(f, "{}: {}", k, v)?;
        }
        write!(f, " }}")
    }
}

pub struct FactIterator<'a> {
    key: &'a [u8],
    q: &'a dyn Fn(&[u8]) -> Option<&'a [u8]>,
}

impl<'a> Iterator for FactIterator<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        (self.q)(self.key)
    }
}

/// A Struct value
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Struct {
    /// The name of the struct
    pub name: String,
    /// the fields of the struct
    pub fields: BTreeMap<String, Value>,
}

impl From<Struct> for (String, Vec<(String, Value)>) {
    fn from(value: Struct) -> Self {
        (value.name, value.fields.into_iter().collect())
    }
}

impl Display for Struct {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}{{", self.name)?;
        let mut i = false;
        for (k, v) in &self.fields {
            if i {
                write!(f, ", ")?;
            }
            i = true;
            write!(f, "{}: {}", k, v)?;
        }
        write!(f, "}}")
    }
}

/// All of the value types allowed in the VM
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Value {
    /// Integer (64-bit signed)
    Int(i64),
    /// Boolean
    Bool(bool),
    /// String (UTF-8)
    String(String),
    /// Struct
    Struct(Struct),
    /// Fact
    Fact(Fact),
    /// Empty optional value
    None,
}

impl Value {
    /// Coerce this value into an i64 or error
    pub fn try_to_int(&self) -> Result<i64, MachineError> {
        if let Value::Int(i) = self {
            return Ok(*i);
        }
        Err(MachineError::InvalidType)
    }

    /// Coerce this value into a bool or error
    pub fn try_to_bool(&self) -> Result<bool, MachineError> {
        if let Value::Bool(b) = self {
            return Ok(*b);
        }
        Err(MachineError::InvalidType)
    }

    /// Coerce this value into an &str or error
    pub fn try_as_str(&self) -> Result<&str, MachineError> {
        if let Value::String(s) = self {
            return Ok(s);
        }
        Err(MachineError::InvalidType)
    }

    /// Convert this value into a String or error
    pub fn try_into_string(self) -> Result<String, MachineError> {
        if let Value::String(s) = self {
            return Ok(s);
        }
        Err(MachineError::InvalidType)
    }

    /// Convert this value into a Struct or error
    pub fn try_into_struct(self) -> Result<Struct, MachineError> {
        if let Value::Struct(s) = self {
            return Ok(s);
        }
        Err(MachineError::InvalidType)
    }

    /// Convert this value into a Fact or error
    pub fn try_into_fact(self) -> Result<Fact, MachineError> {
        if let Value::Fact(f) = self {
            return Ok(f);
        }
        Err(MachineError::InvalidType)
    }

    /// Get the ast:::Vtype if possible
    pub fn vtype(&self) -> Option<VType> {
        match self {
            Value::Int(_) => Some(VType::Int),
            Value::Bool(_) => Some(VType::Bool),
            Value::String(_) => Some(VType::String),
            Value::Struct(_) => None,
            Value::Fact(_) => None,
            Value::None => None,
        }
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Value::Int(i) => write!(f, "{}", i),
            Value::Bool(b) => write!(f, "{}", b),
            Value::String(s) => write!(f, "\"{}\"", s),
            Value::Struct(s) => s.fmt(f),
            Value::Fact(fa) => fa.fmt(f),
            Value::None => write!(f, "None"),
        }
    }
}

impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Value::Int(value)
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Value::Bool(value)
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Value::String(value.to_owned())
    }
}

/// The subset of Values that can be hashed. Only these types of values
/// can be used in the key portion of a Fact.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashableValue {
    Int(i64),
    Bool(bool),
    String(String),
}

impl HashableValue {
    /// Get the ast:::Vtype. Unlike the Value version, this cannot
    /// fail.
    pub fn vtype(&self) -> VType {
        match self {
            HashableValue::Int(_) => VType::Int,
            HashableValue::Bool(_) => VType::Bool,
            HashableValue::String(_) => VType::String,
        }
    }
}

impl TryFrom<Value> for HashableValue {
    type Error = MachineError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Int(v) => Ok(HashableValue::Int(v)),
            Value::Bool(v) => Ok(HashableValue::Bool(v)),
            Value::String(v) => Ok(HashableValue::String(v)),
            _ => Err(MachineError::InvalidType),
        }
    }
}

impl From<HashableValue> for Value {
    fn from(value: HashableValue) -> Self {
        match value {
            HashableValue::Int(v) => Value::Int(v),
            HashableValue::Bool(v) => Value::Bool(v),
            HashableValue::String(v) => Value::String(v),
        }
    }
}

impl Display for HashableValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let real_value: Value = self.to_owned().into();
        write!(f, "{}", real_value)
    }
}
