extern crate alloc;

use alloc::{
    borrow::ToOwned as _, boxed::Box, collections::BTreeMap, format, string::String, vec, vec::Vec,
};
use core::fmt::{self, Display};

pub use aranya_id::BaseId;
use aranya_id::{Id, IdTag};
use aranya_policy_ast::{Ident, Identifier, Span, Text, TypeKind, VType};
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
    InvalidStructMember(Identifier),
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

impl_typed!(Text => String);

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

impl<Tag: IdTag> Typed for Id<Tag> {
    const TYPE: Type<'static> = Type::Id;
}

impl<T: Typed> Typed for Option<T> {
    const TYPE: Type<'static> = Type::Optional(const { &T::TYPE });
}

impl<T: Typed, E: Typed> Typed for Result<T, E> {
    const TYPE: Type<'static> = Type::Result(const { &T::TYPE }, const { &E::TYPE });
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
#[rkyv(serialize_bounds(
    __S: rkyv::ser::Writer + rkyv::ser::Allocator,
    __S::Error: rkyv::rancor::Source,
))]
#[rkyv(deserialize_bounds(__D::Error: rkyv::rancor::Source))]
#[rkyv(bytecheck(
    bounds(
        __C: rkyv::validation::ArchiveContext,
        __C::Error: rkyv::rancor::Source,
    )
))]
pub enum Value {
    /// Integer (64-bit signed)
    Int(i64),
    /// Boolean
    Bool(bool),
    /// String (UTF-8)
    String(Text),
    /// Bytes
    Bytes(Vec<u8>),
    /// Struct
    Struct(#[rkyv(omit_bounds)] Struct),
    /// Fact
    Fact(Fact),
    /// A unique identifier.
    Id(BaseId),
    /// Enumeration value
    Enum(Identifier, i64),
    /// Textual Identifier (name)
    Identifier(Identifier),
    /// Optional value
    Option(#[rkyv(omit_bounds)] Option<Box<Self>>),
    /// Result value
    Result(#[rkyv(omit_bounds)] Result<Box<Value>, Box<Value>>),
}

impl Value {
    /// Shorthand for `Self::Option(None)`.
    pub const NONE: Self = Self::Option(None);
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
        let Value::Option(opt) = value else {
            return Err(ValueConversionError::InvalidType {
                want: "Option".into(),
                got: value.type_name(),
                msg: format!("Value -> {}", core::any::type_name::<Self>()),
            });
        };
        opt.map(|v| T::try_from_value(*v)).transpose()
    }
}

impl<T: TryFromValue, E: TryFromValue> TryFromValue for Result<T, E> {
    fn try_from_value(value: Value) -> Result<Self, ValueConversionError> {
        let Value::Result(res) = value else {
            return Err(ValueConversionError::InvalidType {
                want: "Result".into(),
                got: value.type_name(),
                msg: format!("Value -> {}", core::any::type_name::<Self>()),
            });
        };
        match res {
            Ok(v) => T::try_from_value(*v).map(Ok),
            Err(v) => E::try_from_value(*v).map(Err),
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
    /// Get the [`TypeKind`], if possible.
    pub fn vtype(&self) -> Option<TypeKind> {
        match self {
            Self::Int(_) => Some(TypeKind::Int),
            Self::Bool(_) => Some(TypeKind::Bool),
            Self::String(_) => Some(TypeKind::String),
            Self::Bytes(_) => Some(TypeKind::Bytes),
            Self::Id(_) => Some(TypeKind::Id),
            Self::Enum(name, _) => Some(TypeKind::Enum(Ident {
                name: name.to_owned(),
                span: Span::default(),
            })),
            Self::Struct(s) => Some(TypeKind::Struct(Ident {
                name: s.name.clone(),
                span: Span::default(),
            })),
            _ => None,
        }
    }

    /// Returns a string representing the value's type.
    pub fn type_name(&self) -> String {
        match self {
            Self::Int(_) => String::from("Int"),
            Self::Bool(_) => String::from("Bool"),
            Self::String(_) => String::from("String"),
            Self::Bytes(_) => String::from("Bytes"),
            Self::Struct(s) => format!("Struct {}", s.name),
            Self::Fact(f) => format!("Fact {}", f.name),
            Self::Id(_) => String::from("Id"),
            Self::Enum(name, _) => format!("Enum {}", name),
            Self::Identifier(_) => String::from("Identifier"),
            Self::Option(Some(inner)) => format!("Option[{}]", inner.type_name()),
            Self::Option(None) => String::from("Option[_]"),
            Self::Result(Ok(inner)) => format!("Result[_, {}]", inner.type_name()),
            Self::Result(Err(inner)) => format!("Result[{}, _]", inner.type_name()),
        }
    }

    /// Checks to see if a [`Value`] matches some [`VType`]
    /// ```
    /// use aranya_policy_ast::{Span, TypeKind, VType};
    /// use aranya_policy_module::Value;
    ///
    /// let value = Value::Int(1);
    /// let int_type = VType {
    ///     kind: TypeKind::Int,
    ///     span: Span::empty(),
    /// };
    ///
    /// assert!(value.fits_type(&int_type));
    /// ```
    pub fn fits_type(&self, expected_type: &VType) -> bool {
        use aranya_policy_ast::TypeKind;
        match (self, &expected_type.kind) {
            (Self::Int(_), TypeKind::Int) => true,
            (Self::Bool(_), TypeKind::Bool) => true,
            (Self::String(_), TypeKind::String) => true,
            (Self::Bytes(_), TypeKind::Bytes) => true,
            (Self::Struct(s), TypeKind::Struct(ident)) => s.name == ident.name,
            (Self::Id(_), TypeKind::Id) => true,
            (Self::Enum(name, _), TypeKind::Enum(ident)) => *name == ident.name,
            (Self::Option(Some(value)), TypeKind::Optional(ty)) => value.fits_type(ty),
            (Self::Option(None), TypeKind::Optional(_)) => true,
            (Self::Result(Ok(inner)), TypeKind::Result(result_type)) => {
                inner.fits_type(&result_type.ok)
            }
            (Self::Result(Err(inner)), TypeKind::Result(result_type)) => {
                inner.fits_type(&result_type.err)
            }
            _ => false,
        }
    }
}

impl<T: Into<Self>> From<Option<T>> for Value {
    fn from(value: Option<T>) -> Self {
        Self::Option(value.map(Into::into).map(Box::new))
    }
}

impl<T: Into<Self>, E: Into<Self>> From<Result<T, E>> for Value {
    fn from(value: Result<T, E>) -> Self {
        Self::Result(match value {
            Ok(v) => Ok(Box::new(v.into())),
            Err(v) => Err(Box::new(v.into())),
        })
    }
}

impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Self::Int(value)
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<Text> for Value {
    fn from(value: Text) -> Self {
        Self::String(value)
    }
}

impl From<Identifier> for Value {
    fn from(value: Identifier) -> Self {
        Self::Identifier(value)
    }
}

impl From<&[u8]> for Value {
    fn from(value: &[u8]) -> Self {
        Self::Bytes(value.to_owned())
    }
}

impl From<Vec<u8>> for Value {
    fn from(value: Vec<u8>) -> Self {
        Self::Bytes(value)
    }
}

impl From<Struct> for Value {
    fn from(value: Struct) -> Self {
        Self::Struct(value)
    }
}

impl From<Fact> for Value {
    fn from(value: Fact) -> Self {
        Self::Fact(value)
    }
}

impl<Tag: IdTag> From<Id<Tag>> for Value {
    fn from(id: Id<Tag>) -> Self {
        Self::Id(id.as_base())
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

impl TryFrom<Value> for Text {
    type Error = ValueConversionError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::String(s) = value {
            return Ok(s);
        }
        Err(ValueConversionError::invalid_type(
            "String",
            value.type_name(),
            "Value -> Text",
        ))
    }
}

impl TryFrom<Value> for Identifier {
    type Error = ValueConversionError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let Value::Identifier(text) = value else {
            return Err(ValueConversionError::invalid_type(
                "Identifier",
                value.type_name(),
                "Value -> Identifier",
            ));
        };
        Ok(text)
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

impl<Tag: IdTag> TryFrom<Value> for Id<Tag> {
    type Error = ValueConversionError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Id(id) = value {
            Ok(Self::from_base(id))
        } else {
            Err(ValueConversionError::invalid_type(
                "Id",
                value.type_name(),
                "Value -> Id",
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
            Self::Int(i) => write!(f, "{}", i),
            Self::Bool(b) => write!(f, "{}", b),
            Self::String(s) => write!(f, "\"{}\"", s),
            Self::Bytes(v) => {
                write!(f, "b:")?;
                for b in v {
                    write!(f, "{:02X}", b)?;
                }
                Ok(())
            }
            Self::Struct(s) => s.fmt(f),
            Self::Fact(fa) => fa.fmt(f),
            Self::Id(id) => id.fmt(f),
            Self::Enum(name, value) => write!(f, "{name}::{value}"),
            Self::Identifier(name) => write!(f, "{name}"),
            Self::Option(Some(v)) => write!(f, "Some({v})"),
            Self::Option(None) => write!(f, "None"),
            Self::Result(Ok(v)) => write!(f, "Ok({})", v),
            Self::Result(Err(v)) => write!(f, "Err({})", v),
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
    String(Text),
    /// A unique identifier.
    Id(BaseId),
    /// Enum
    Enum(Identifier, i64),
}

impl HashableValue {
    /// Get the [`TypeKind`]. Unlike the Value version, this cannot
    /// fail.
    pub fn vtype(&self) -> TypeKind {
        use aranya_policy_ast::TypeKind;
        match self {
            Self::Int(_) => TypeKind::Int,
            Self::Bool(_) => TypeKind::Bool,
            Self::String(_) => TypeKind::String,
            Self::Id(_) => TypeKind::Id,
            Self::Enum(id, _) => TypeKind::Enum(Ident {
                name: id.clone(),
                span: Span::default(),
            }),
        }
    }
}

impl TryFrom<Value> for HashableValue {
    type Error = ValueConversionError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Int(v) => Ok(Self::Int(v)),
            Value::Bool(v) => Ok(Self::Bool(v)),
            Value::String(v) => Ok(Self::String(v)),
            Value::Id(v) => Ok(Self::Id(v)),
            Value::Enum(id, value) => Ok(Self::Enum(id, value)),
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
            HashableValue::Int(v) => Self::Int(v),
            HashableValue::Bool(v) => Self::Bool(v),
            HashableValue::String(v) => Self::String(v),
            HashableValue::Id(v) => Self::Id(v),
            HashableValue::Enum(id, value) => Self::Enum(id, value),
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
    pub identifier: Identifier,
    /// key value
    pub value: HashableValue,
}

impl FactKey {
    /// Creates a new fact key.
    pub fn new(name: Identifier, value: HashableValue) -> Self {
        Self {
            identifier: name,
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
    pub identifier: Identifier,
    /// value
    pub value: Value,
}

impl FactValue {
    /// Creates a new fact value.
    pub fn new(name: Identifier, value: Value) -> Self {
        Self {
            identifier: name,
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
pub struct KVPair(Identifier, Value);

impl KVPair {
    /// Creates a key-value pair.
    pub fn new(key: Identifier, value: Value) -> Self {
        Self(key, value)
    }

    /// Creates a key-value pair with an integer value.
    pub fn new_int(key: Identifier, value: i64) -> Self {
        Self(key, Value::Int(value))
    }

    /// Returns the key half of the key-value pair.
    pub fn key(&self) -> &Identifier {
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

impl From<KVPair> for (Identifier, Value) {
    fn from(kv: KVPair) -> Self {
        (kv.0, kv.1)
    }
}

impl From<&KVPair> for (Identifier, Value) {
    fn from(value: &KVPair) -> Self {
        (value.0.clone(), value.1.clone())
    }
}

impl From<FactKey> for KVPair {
    fn from(value: FactKey) -> Self {
        Self(value.identifier, value.value.into())
    }
}

impl From<FactValue> for KVPair {
    fn from(value: FactValue) -> Self {
        Self(value.identifier, value.value)
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
        __C::Error: rkyv::rancor::Source,
    )
))]
pub struct Fact {
    /// The name of the fact
    pub name: Identifier,
    /// The keys of the fact
    #[rkyv(omit_bounds)]
    pub keys: FactKeyList,
    /// The values of the fact
    #[rkyv(omit_bounds)]
    pub values: FactValueList,
}

impl Fact {
    /// Creates a fact.
    pub fn new(name: Identifier) -> Self {
        Self {
            name,
            keys: vec![],
            values: vec![],
        }
    }

    /// Sets the fact's key.
    pub fn set_key<V>(&mut self, name: Identifier, value: V)
    where
        V: Into<HashableValue>,
    {
        match self.keys.iter_mut().find(|e| e.identifier == name) {
            None => self.keys.push(FactKey::new(name, value.into())),
            Some(e) => e.value = value.into(),
        }
    }

    /// Sets the fact's value.
    pub fn set_value<V>(&mut self, name: Identifier, value: V)
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
        __C::Error: rkyv::rancor::Source,
    )
))]
pub struct Struct {
    /// The name of the struct
    pub name: Identifier,
    /// the fields of the struct
    #[rkyv(omit_bounds)]
    pub fields: BTreeMap<Identifier, Value>,
}

impl Struct {
    /// Creates a struct.
    pub fn new(
        name: Identifier,
        fields: impl IntoIterator<Item = impl Into<(Identifier, Value)>>,
    ) -> Self {
        Self {
            name,
            fields: fields.into_iter().map(Into::into).collect(),
        }
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

#[cfg(test)]
mod test {
    use crate::{TryFromValue as _, Value};

    #[test]
    fn test_option_error() {
        let err = <Option<i64>>::try_from_value(Value::Bool(true)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "expected type Option, but got Bool: Value -> core::option::Option<i64>"
        );
    }
}
