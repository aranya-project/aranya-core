extern crate alloc;

use alloc::collections::BTreeMap;
use core::fmt;

use serde::{Deserialize, Serialize};

use crate::lang::ast::VType;
use crate::machine::MachineErrorType;

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

pub trait TryAsMut<T: ?Sized> {
    type Error;
    fn try_as_mut(&mut self) -> Result<&mut T, Self::Error>;
}

impl Value {
    /// Get the ast:::Vtype if possible
    pub fn vtype(&self) -> Option<VType> {
        match self {
            Value::Int(_) => Some(VType::Int),
            Value::Bool(_) => Some(VType::Bool),
            Value::String(_) => Some(VType::String),
            _ => None,
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

impl From<Struct> for Value {
    fn from(value: Struct) -> Self {
        Value::Struct(value)
    }
}

impl From<Fact> for Value {
    fn from(value: Fact) -> Self {
        Value::Fact(value)
    }
}

impl TryFrom<Value> for i64 {
    type Error = MachineErrorType;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Int(i) = value {
            return Ok(i);
        }
        Err(MachineErrorType::InvalidType)
    }
}

impl TryFrom<Value> for bool {
    type Error = MachineErrorType;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Bool(b) = value {
            return Ok(b);
        }
        Err(MachineErrorType::InvalidType)
    }
}

impl TryFrom<Value> for String {
    type Error = MachineErrorType;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::String(s) = value {
            return Ok(s);
        }
        Err(MachineErrorType::InvalidType)
    }
}

impl TryFrom<Value> for Struct {
    type Error = MachineErrorType;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Struct(s) = value {
            return Ok(s);
        }
        Err(MachineErrorType::InvalidType)
    }
}

impl TryFrom<Value> for Fact {
    type Error = MachineErrorType;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Fact(f) = value {
            return Ok(f);
        }
        Err(MachineErrorType::InvalidType)
    }
}

impl TryAsMut<i64> for Value {
    type Error = MachineErrorType;
    fn try_as_mut(&mut self) -> Result<&mut i64, Self::Error> {
        if let Self::Int(s) = self {
            return Ok(s);
        }
        Err(MachineErrorType::InvalidType)
    }
}

impl TryAsMut<bool> for Value {
    type Error = MachineErrorType;
    fn try_as_mut(&mut self) -> Result<&mut bool, Self::Error> {
        if let Self::Bool(b) = self {
            return Ok(b);
        }
        Err(MachineErrorType::InvalidType)
    }
}

impl TryAsMut<str> for Value {
    type Error = MachineErrorType;
    fn try_as_mut(&mut self) -> Result<&mut str, Self::Error> {
        if let Self::String(s) = self {
            return Ok(s);
        }
        Err(MachineErrorType::InvalidType)
    }
}

impl TryAsMut<Struct> for Value {
    type Error = MachineErrorType;
    fn try_as_mut(&mut self) -> Result<&mut Struct, Self::Error> {
        if let Self::Struct(s) = self {
            return Ok(s);
        }
        Err(MachineErrorType::InvalidType)
    }
}

impl TryAsMut<Fact> for Value {
    type Error = MachineErrorType;
    fn try_as_mut(&mut self) -> Result<&mut Fact, Self::Error> {
        if let Self::Fact(f) = self {
            return Ok(f);
        }
        Err(MachineErrorType::InvalidType)
    }
}

impl fmt::Display for Value {
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

/// The subset of Values that can be hashed. Only these types of values
/// can be used in the key portion of a Fact.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
    type Error = MachineErrorType;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Int(v) => Ok(HashableValue::Int(v)),
            Value::Bool(v) => Ok(HashableValue::Bool(v)),
            Value::String(v) => Ok(HashableValue::String(v)),
            _ => Err(MachineErrorType::InvalidType),
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

impl fmt::Display for HashableValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let real_value: Value = self.to_owned().into();
        write!(f, "{}", real_value)
    }
}

/// One labeled value in a fact key. A sequence of FactKeys mapped to
/// a sequence of FactValues comprises a Fact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FactKey(String, HashableValue);

impl FactKey {
    pub fn new(key: &str, value: HashableValue) -> FactKey {
        FactKey(key.to_owned(), value)
    }
}

impl fmt::Display for FactKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.0, self.1)
    }
}

/// One labeled value in a fact value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactValue(String, Value);

impl FactValue {
    pub fn new(key: &str, value: Value) -> FactValue {
        FactValue(key.to_owned(), value)
    }
}

impl fmt::Display for FactValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.0, self.1)
    }
}

pub type FactKeyList = Vec<FactKey>;
pub type FactValueList = Vec<FactValue>;

/// A generic key/value pair. Used for Effects and Command fields.
/// Technically identical to a FactValue but separate to distinguish
/// usage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KVPair(String, Value);

impl KVPair {
    pub fn new(key: &str, value: Value) -> KVPair {
        KVPair(key.to_owned(), value)
    }

    pub fn new_int(key: &str, value: i64) -> KVPair {
        KVPair(key.to_owned(), Value::Int(value))
    }
}

impl fmt::Display for KVPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.0, self.1)
    }
}

impl From<&KVPair> for (String, Value) {
    fn from(value: &KVPair) -> Self {
        (value.0.clone(), value.1.clone())
    }
}

impl From<FactKey> for KVPair {
    fn from(value: FactKey) -> Self {
        KVPair(value.0, value.1.into())
    }
}

impl From<FactValue> for KVPair {
    fn from(value: FactValue) -> Self {
        KVPair(value.0, value.1)
    }
}

/// A Fact
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fact {
    /// The name of the fact
    pub name: String,
    /// The keys of the fact
    pub keys: FactKeyList,
    /// The values of the fact
    pub values: FactValueList,
}

impl Fact {
    pub fn new(name: String) -> Fact {
        Fact {
            name,
            keys: vec![],
            values: vec![],
        }
    }
    pub fn set_key<V>(&mut self, name: String, value: V)
    where
        V: Into<HashableValue>,
    {
        match self.keys.iter_mut().find(|e| e.0 == name) {
            None => self.keys.push(FactKey(name, value.into())),
            Some(e) => e.1 = value.into(),
        }
    }

    pub fn set_value<V>(&mut self, name: String, value: V)
    where
        V: Into<Value>,
    {
        match self.values.iter_mut().find(|e| e.0 == name) {
            None => self.values.push(FactValue(name, value.into())),
            Some(e) => e.1 = value.into(),
        }
    }
}

impl fmt::Display for Fact {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}[", self.name)?;
        let mut i = false;
        for FactKey(k, v) in &self.keys {
            if i {
                write!(f, ", ")?;
            }
            i = true;
            write!(f, "{}: {}", k, v)?;
        }
        write!(f, "]=>{{")?;
        i = false;
        for FactValue(k, v) in &self.values {
            if i {
                write!(f, ", ")?;
            }
            i = true;
            write!(f, "{}: {}", k, v)?;
        }
        write!(f, " }}")
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

impl Struct {
    pub fn new(name: &str, fields: &[KVPair]) -> Struct {
        Struct {
            name: name.to_owned(),
            fields: fields.iter().map(|p| p.into()).collect(),
        }
    }
}

impl From<Struct> for (String, Vec<KVPair>) {
    fn from(value: Struct) -> Self {
        (
            value.name,
            value
                .fields
                .into_iter()
                .map(|(k, v)| KVPair(k, v))
                .collect(),
        )
    }
}

impl fmt::Display for Struct {
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
