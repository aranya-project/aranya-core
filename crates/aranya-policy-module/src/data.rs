extern crate alloc;

use alloc::{borrow::ToOwned, collections::BTreeMap, format, string::String, vec, vec::Vec};
use core::fmt::{self, Display};

pub use aranya_crypto::Id;
use aranya_crypto::{DeviceId, EncryptionKeyId};
use aranya_policy_ast::VType;
use serde::{Deserialize, Serialize};

use super::ffi::Type;

#[derive(Debug, thiserror::Error)]
/// Indicates that the Value conversion has failed
pub enum ValueConversionError {
    /// A conversion was attempted to a type that is not compatible with this Value
    #[error("expected type {want}, but got {got}: {msg}")]
    InvalidType {
        /// Expected type name
        want: String,
        /// Received type name
        got: String,
        /// Extra information
        msg: String,
    },
    /// A struct conversion found a field mismatch between types
    #[error("invalid struct member `{0}`")]
    InvalidStructMember(String),
    /// The target type does not have sufficient range to represent this Value
    #[error("value out of range")]
    OutOfRange,
    /// Some internal state is corrupt
    #[error("bad state")]
    BadState,
}

impl ValueConversionError {
    /// Constructs an `InvalidType` error
    pub fn invalid_type(
        want: impl Into<String>,
        got: impl Into<String>,
        msg: impl Into<String>,
    ) -> Self {
        Self::InvalidType {
            want: want.into(),
            got: got.into(),
            msg: msg.into(),
        }
    }
}

/// Allows a type to be used by FFI derive.
// TODO(eric): move this into `super::ffi`?
pub trait Typed {
    /// Indicates the type of the type.
    const TYPE: Type<'static>;
}

macro_rules! impl_typed {
    ($name:ty => $type:ident) => {
        impl Typed for $name {
            const TYPE: Type<'static> = Type::$type;
        }
    };
}

impl_typed!(String => String);
impl_typed!(&str => String);

impl_typed!(Vec<u8> => Bytes);
impl_typed!(&[u8] => Bytes);

impl_typed!(isize => Int);
impl_typed!(i64 => Int);
impl_typed!(i32 => Int);
impl_typed!(i16 => Int);
impl_typed!(i8 => Int);

impl_typed!(usize => Int);
impl_typed!(u64 => Int);
impl_typed!(u32 => Int);
impl_typed!(u16 => Int);
impl_typed!(u8 => Int);

impl_typed!(bool => Bool);

impl_typed!(Id => Id);
impl_typed!(EncryptionKeyId => Id);
impl_typed!(DeviceId => Id);

impl<T: Typed> Typed for Option<T> {
    const TYPE: Type<'static> = Type::Optional(&T::TYPE);
}

/// All of the value types allowed in the VM
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
// Trait bounds required for serialization
#[rkyv(serialize_bounds(
    __S: rkyv::ser::Writer + rkyv::ser::Allocator,
    __S::Error: rkyv::rancor::Source,
))]
// Trait bounds required for deserialization
#[rkyv(deserialize_bounds(__D::Error: rkyv::rancor::Source))]
// Bounds for validation during bytechecking (validating archived data)
#[rkyv(bytecheck(
    bounds(
        __C: rkyv::validation::ArchiveContext,
    )
))]
pub enum Value {
    /// Integer (64-bit signed)
    Int(i64),
    /// Boolean
    Bool(bool),
    /// String (UTF-8)
    String(String),
    /// Bytes
    Bytes(Vec<u8>),
    /// Struct
    Struct(#[rkyv(omit_bounds)] Struct),
    /// Fact
    Fact(Fact),
    /// A unique identifier.
    Id(Id),
    /// Enumeration value
    Enum(String, i64),
    /// Empty optional value
    None,
}

/// Trait for converting from a [`Value`], similar to [`TryFrom<Value>`].
///
/// This trait allows us to add a blanket impl for `Option`, which we cannot
/// do for `TryFrom<Value>` because of overlap and foreign type restrictions.
pub trait TryFromValue: Sized {
    /// Tries to convert a [`Value`] into `Self`.
    fn try_from_value(value: Value) -> Result<Self, ValueConversionError>;
}

impl<T: TryFromValue> TryFromValue for Option<T> {
    fn try_from_value(value: Value) -> Result<Self, ValueConversionError> {
        if matches!(value, Value::None) {
            Ok(None)
        } else {
            T::try_from_value(value).map(Some)
        }
    }
}

impl<T: TryFrom<Value, Error = ValueConversionError>> TryFromValue for T {
    fn try_from_value(value: Value) -> Result<Self, ValueConversionError> {
        Self::try_from(value)
    }
}

/// Like `AsMut`, but fallible.
pub trait TryAsMut<T: ?Sized> {
    /// The error result.
    type Error;

    /// Converts this type into a mutable reference of the
    /// (usually inferred) input type.
    fn try_as_mut(&mut self) -> Result<&mut T, Self::Error>;
}

impl Value {
    /// Get the [`VType`], if possible.
    pub fn vtype(&self) -> Option<VType> {
        match self {
            Value::Int(_) => Some(VType::Int),
            Value::Bool(_) => Some(VType::Bool),
            Value::String(_) => Some(VType::String),
            Value::Bytes(_) => Some(VType::Bytes),
            Value::Id(_) => Some(VType::Id),
            Value::Enum(name, _) => Some(VType::Enum(name.to_owned())),
            Value::Struct(s) => Some(VType::Struct(s.name.clone())),
            _ => None,
        }
    }

    /// Returns a string representing the value's type.
    pub fn type_name(&self) -> String {
        match self {
            Value::Int(_) => String::from("Int"),
            Value::Bool(_) => String::from("Bool"),
            Value::String(_) => String::from("String"),
            Value::Bytes(_) => String::from("Bytes"),
            Value::Struct(s) => format!("Struct {}", s.name),
            Value::Fact(f) => format!("Fact {}", f.name),
            Value::Id(_) => String::from("Id"),
            Value::Enum(name, _) => format!("Enum {}", name),
            Value::None => String::from("None"),
        }
    }

    /// Checks to see if a [`Value`] matches some [`VType`]
    /// ```
    /// use aranya_policy_ast::VType;
    /// use aranya_policy_module::Value;
    ///
    /// let value = Value::Int(1);
    ///
    /// assert!(value.fits_type(&VType::Int));
    /// ```
    pub fn fits_type(&self, expected_type: &VType) -> bool {
        match (self.vtype(), expected_type) {
            (None, VType::Optional(_)) => true,
            (None, _) => false,
            (Some(VType::Optional(_)), _) => unreachable!(),
            (Some(left), VType::Optional(inner)) => left == **inner,
            (Some(left), right) => left == *right,
        }
    }
}

impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(value: Option<T>) -> Self {
        value.map_or(Value::None, Into::into)
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

impl From<String> for Value {
    fn from(value: String) -> Self {
        Value::String(value)
    }
}

impl From<&[u8]> for Value {
    fn from(value: &[u8]) -> Self {
        Value::Bytes(value.to_owned())
    }
}

impl From<Vec<u8>> for Value {
    fn from(value: Vec<u8>) -> Self {
        Value::Bytes(value)
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

impl From<Id> for Value {
    fn from(id: Id) -> Self {
        Value::Id(id)
    }
}

impl From<DeviceId> for Value {
    fn from(id: DeviceId) -> Self {
        Value::Id(id.into())
    }
}

impl From<EncryptionKeyId> for Value {
    fn from(id: EncryptionKeyId) -> Self {
        Value::Id(id.into())
    }
}

impl TryFrom<Value> for i64 {
    type Error = ValueConversionError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Int(i) = value {
            return Ok(i);
        }
        Err(ValueConversionError::invalid_type(
            "Int",
            value.type_name(),
            "Value -> i64",
        ))
    }
}

impl TryFrom<Value> for bool {
    type Error = ValueConversionError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Bool(b) = value {
            return Ok(b);
        }
        Err(ValueConversionError::invalid_type(
            "Bool",
            value.type_name(),
            "Value -> bool",
        ))
    }
}

impl TryFrom<Value> for String {
    type Error = ValueConversionError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::String(s) = value {
            return Ok(s);
        }
        Err(ValueConversionError::invalid_type(
            "String",
            value.type_name(),
            "Value -> String",
        ))
    }
}

impl TryFrom<Value> for Vec<u8> {
    type Error = ValueConversionError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Bytes(v) = value {
            return Ok(v);
        }
        Err(ValueConversionError::invalid_type(
            "Bytes",
            value.type_name(),
            "Value -> Vec<u8>",
        ))
    }
}

impl TryFrom<Value> for Struct {
    type Error = ValueConversionError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Struct(s) = value {
            return Ok(s);
        }
        Err(ValueConversionError::invalid_type(
            "Struct",
            value.type_name(),
            "Value -> Struct",
        ))
    }
}

impl TryFrom<Value> for Fact {
    type Error = ValueConversionError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Fact(f) = value {
            return Ok(f);
        }
        Err(ValueConversionError::invalid_type(
            "Fact",
            value.type_name(),
            "Value -> Fact",
        ))
    }
}

impl TryFrom<Value> for Id {
    type Error = ValueConversionError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Id(id) = value {
            Ok(id)
        } else {
            Err(ValueConversionError::invalid_type(
                "Id",
                value.type_name(),
                "Value -> Id",
            ))
        }
    }
}

impl TryFrom<Value> for DeviceId {
    type Error = ValueConversionError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Id(id) = value {
            Ok(id.into())
        } else {
            Err(ValueConversionError::invalid_type(
                "Id",
                value.type_name(),
                "Value -> DeviceId",
            ))
        }
    }
}

impl TryFrom<Value> for EncryptionKeyId {
    type Error = ValueConversionError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Id(id) = value {
            Ok(id.into())
        } else {
            Err(ValueConversionError::invalid_type(
                "Id",
                value.type_name(),
                "Value -> EncryptionKeyId",
            ))
        }
    }
}

impl TryAsMut<i64> for Value {
    type Error = ValueConversionError;
    fn try_as_mut(&mut self) -> Result<&mut i64, Self::Error> {
        if let Self::Int(s) = self {
            return Ok(s);
        }
        Err(ValueConversionError::invalid_type(
            "i64",
            self.type_name(),
            "Value -> i64",
        ))
    }
}

impl TryAsMut<bool> for Value {
    type Error = ValueConversionError;
    fn try_as_mut(&mut self) -> Result<&mut bool, Self::Error> {
        if let Self::Bool(b) = self {
            return Ok(b);
        }
        Err(ValueConversionError::invalid_type(
            "bool",
            self.type_name(),
            "Value -> bool",
        ))
    }
}

impl TryAsMut<str> for Value {
    type Error = ValueConversionError;
    fn try_as_mut(&mut self) -> Result<&mut str, Self::Error> {
        if let Self::String(s) = self {
            return Ok(s);
        }
        Err(ValueConversionError::invalid_type(
            "String",
            self.type_name(),
            "Value -> String",
        ))
    }
}

impl TryAsMut<[u8]> for Value {
    type Error = ValueConversionError;
    fn try_as_mut(&mut self) -> Result<&mut [u8], Self::Error> {
        if let Self::Bytes(v) = self {
            return Ok(v);
        }
        Err(ValueConversionError::invalid_type(
            "Vec<u8>",
            self.type_name(),
            "Value -> [u8]",
        ))
    }
}

impl TryAsMut<Struct> for Value {
    type Error = ValueConversionError;
    fn try_as_mut(&mut self) -> Result<&mut Struct, Self::Error> {
        if let Self::Struct(s) = self {
            return Ok(s);
        }
        Err(ValueConversionError::invalid_type(
            "Struct",
            self.type_name(),
            "Value -> Struct",
        ))
    }
}

impl TryAsMut<Fact> for Value {
    type Error = ValueConversionError;
    fn try_as_mut(&mut self) -> Result<&mut Fact, Self::Error> {
        if let Self::Fact(f) = self {
            return Ok(f);
        }
        Err(ValueConversionError::invalid_type(
            "Fact",
            self.type_name(),
            "Value -> Fact",
        ))
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Int(i) => write!(f, "{}", i),
            Value::Bool(b) => write!(f, "{}", b),
            Value::String(s) => write!(f, "\"{}\"", s),
            Value::Bytes(v) => {
                write!(f, "b:")?;
                for b in v {
                    write!(f, "{:02X}", b)?;
                }
                Ok(())
            }
            Value::Struct(s) => s.fmt(f),
            Value::Fact(fa) => fa.fmt(f),
            Value::Id(id) => id.fmt(f),
            Value::Enum(name, value) => write!(f, "{name}::{value}"),
            Value::None => write!(f, "None"),
        }
    }
}

/// The subset of Values that can be hashed. Only these types of values
/// can be used in the key portion of a Fact.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[cfg_attr(feature = "proptest", derive(proptest_derive::Arbitrary))]
pub enum HashableValue {
    /// An integer.
    Int(i64),
    /// A bool.
    Bool(bool),
    /// A string.
    String(String),
    /// A unique identifier.
    Id(Id),
    /// Enum
    Enum(String, i64),
}

impl HashableValue {
    /// Get the ast:::Vtype. Unlike the Value version, this cannot
    /// fail.
    pub fn vtype(&self) -> VType {
        match self {
            HashableValue::Int(_) => VType::Int,
            HashableValue::Bool(_) => VType::Bool,
            HashableValue::String(_) => VType::String,
            HashableValue::Id(_) => VType::Id,
            HashableValue::Enum(id, _) => VType::Enum(id.clone()),
        }
    }
}

impl TryFrom<Value> for HashableValue {
    type Error = ValueConversionError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Int(v) => Ok(HashableValue::Int(v)),
            Value::Bool(v) => Ok(HashableValue::Bool(v)),
            Value::String(v) => Ok(HashableValue::String(v)),
            Value::Id(v) => Ok(HashableValue::Id(v)),
            Value::Enum(id, value) => Ok(HashableValue::Enum(id, value)),
            _ => Err(ValueConversionError::invalid_type(
                "Int | Bool | String | Id | Enum",
                value.type_name(),
                "Value -> HashableValue",
            )),
        }
    }
}

impl From<HashableValue> for Value {
    fn from(value: HashableValue) -> Self {
        match value {
            HashableValue::Int(v) => Value::Int(v),
            HashableValue::Bool(v) => Value::Bool(v),
            HashableValue::String(v) => Value::String(v),
            HashableValue::Id(v) => Value::Id(v),
            HashableValue::Enum(id, value) => Value::Enum(id, value),
        }
    }
}

impl Display for HashableValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let real_value: Value = self.to_owned().into();
        write!(f, "{}", real_value)
    }
}

/// One labeled value in a fact key. A sequence of FactKeys mapped to
/// a sequence of FactValues comprises a Fact.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[cfg_attr(feature = "proptest", derive(proptest_derive::Arbitrary))]
pub struct FactKey {
    /// key name
    pub identifier: String,
    /// key value
    pub value: HashableValue,
}

impl FactKey {
    /// Creates a new fact key.
    pub fn new(name: &str, value: HashableValue) -> Self {
        Self {
            identifier: String::from(name),
            value,
        }
    }
}

impl Display for FactKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.identifier, self.value)
    }
}

/// One labeled value in a fact value.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct FactValue {
    /// value name
    pub identifier: String,
    /// value
    pub value: Value,
}

impl FactValue {
    /// Creates a new fact value.
    pub fn new(name: &str, value: Value) -> Self {
        Self {
            identifier: String::from(name),
            value,
        }
    }
}

impl Display for FactValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.identifier, self.value)
    }
}

/// A list of fact keys.
pub type FactKeyList = Vec<FactKey>;

/// A list of fact values.
pub type FactValueList = Vec<FactValue>;

/// A generic key/value pair. Used for Effects and Command fields.
/// Technically identical to a FactValue but separate to distinguish
/// usage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KVPair(String, Value);

impl KVPair {
    /// Creates a key-value pair.
    pub fn new(key: &str, value: Value) -> KVPair {
        KVPair(key.to_owned(), value)
    }

    /// Creates a key-value pair with an integer value.
    pub fn new_int(key: &str, value: i64) -> KVPair {
        KVPair(key.to_owned(), Value::Int(value))
    }

    /// Returns the key half of the key-value pair.
    pub fn key(&self) -> &str {
        &self.0
    }

    /// Returns the value half of the key-value pair.
    pub fn value(&self) -> &Value {
        &self.1
    }
}

impl Display for KVPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.0, self.1)
    }
}

impl From<KVPair> for (String, Value) {
    fn from(kv: KVPair) -> Self {
        (kv.0, kv.1)
    }
}

impl From<&KVPair> for (String, Value) {
    fn from(value: &KVPair) -> Self {
        (value.0.clone(), value.1.clone())
    }
}

impl From<FactKey> for KVPair {
    fn from(value: FactKey) -> Self {
        KVPair(value.identifier, value.value.into())
    }
}

impl From<FactValue> for KVPair {
    fn from(value: FactValue) -> Self {
        KVPair(value.identifier, value.value)
    }
}

/// A Fact
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[rkyv(serialize_bounds(
    __S: rkyv::ser::Writer + rkyv::ser::Allocator,
    __S::Error: rkyv::rancor::Source,
))]
#[rkyv(deserialize_bounds(__D::Error: rkyv::rancor::Source))]
#[rkyv(bytecheck(
    bounds(
        __C: rkyv::validation::ArchiveContext,
    )
))]
pub struct Fact {
    /// The name of the fact
    pub name: String,
    /// The keys of the fact
    #[rkyv(omit_bounds)]
    pub keys: FactKeyList,
    /// The values of the fact
    #[rkyv(omit_bounds)]
    pub values: FactValueList,
}

impl Fact {
    /// Creates a fact.
    pub fn new(name: String) -> Fact {
        Fact {
            name,
            keys: vec![],
            values: vec![],
        }
    }

    /// Sets the fact's key.
    pub fn set_key<V>(&mut self, name: String, value: V)
    where
        V: Into<HashableValue>,
    {
        match self.keys.iter_mut().find(|e| e.identifier == name) {
            None => self.keys.push(FactKey::new(&name, value.into())),
            Some(e) => e.value = value.into(),
        }
    }

    /// Sets the fact's value.
    pub fn set_value<V>(&mut self, name: String, value: V)
    where
        V: Into<Value>,
    {
        match self.values.iter_mut().find(|e| e.identifier == name) {
            None => self.values.push(FactValue {
                identifier: name,
                value: value.into(),
            }),
            Some(e) => e.value = value.into(),
        }
    }
}

impl Display for Fact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}[", self.name)?;
        let mut i = false;
        for FactKey {
            identifier: k,
            value: v,
        } in &self.keys
        {
            if i {
                write!(f, ", ")?;
            }
            i = true;
            write!(f, "{}: {}", k, v)?;
        }
        write!(f, "]=>{{")?;
        i = false;
        for FactValue {
            identifier: k,
            value: v,
        } in &self.values
        {
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
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[rkyv(serialize_bounds(
    __S: rkyv::ser::Writer + rkyv::ser::Allocator,
    __S::Error: rkyv::rancor::Source,
))]
#[rkyv(deserialize_bounds(__D::Error: rkyv::rancor::Source))]
#[rkyv(bytecheck(
    bounds(
        __C: rkyv::validation::ArchiveContext,
    )
))]
pub struct Struct {
    /// The name of the struct
    pub name: String,
    /// the fields of the struct
    #[rkyv(omit_bounds)]
    pub fields: BTreeMap<String, Value>,
}

impl Struct {
    /// Creates a struct.
    pub fn new(name: &str, fields: impl IntoIterator<Item = impl Into<(String, Value)>>) -> Struct {
        Struct {
            name: name.to_owned(),
            fields: fields.into_iter().map(|p| p.into()).collect(),
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

impl Display for Struct {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
