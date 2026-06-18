extern crate alloc;

use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::fmt;

use aranya_policy_ast::Identifier;
use serde::{Deserialize, Serialize};

use crate::ffi;

/// An error when validating the contract against expectations
#[derive(Debug, thiserror::Error)]
pub struct ContractValidationError(/* TODO(chip): Add detail */ pub String);
trait PrependError {
    fn prepend<C: fmt::Display>(self, s: C) -> Self;
}

impl<T> PrependError for Result<T, ContractValidationError> {
    fn prepend<C: fmt::Display>(self, s: C) -> Self {
        self.map_err(|e| ContractValidationError(format!("{s} {}", e.0)))
    }
}

impl fmt::Display for ContractValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Contract Validation Error: {}", self.0)
    }
}

/// Describes a name and type for an argument or field
///
/// Effectively an owned version of [`ffi::Type`](crate::ffi::Type).
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
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
pub enum TypeContract {
    /// A character (UTF-8) string
    String,
    /// A byte string
    Bytes,
    /// A signed 64-bit integer
    Int,
    /// A boolean
    Bool,
    /// A unique identifier
    Id,
    /// A named struct
    Struct(Identifier),
    /// Named enumeration
    Enum(Identifier),
    /// An optional type of some other type
    Optional(#[rkyv(omit_bounds)] Box<TypeContract>),
    /// Result with value, or error
    Result(#[rkyv(omit_bounds)] Box<(TypeContract, TypeContract)>),
}

impl TypeContract {
    fn validate(&self, other: &ffi::Type<'_>) -> Result<(), ContractValidationError> {
        let other_tc = other.into();
        if self != &other_tc {
            return Err(ContractValidationError(format!(
                "{self:?} but VM expected {other_tc:?}"
            )));
        }
        Ok(())
    }
}

impl From<&ffi::Type<'_>> for TypeContract {
    fn from(value: &ffi::Type<'_>) -> Self {
        match value {
            ffi::Type::String => Self::String,
            ffi::Type::Bytes => Self::Bytes,
            ffi::Type::Int => Self::Int,
            ffi::Type::Bool => Self::Bool,
            ffi::Type::Id => Self::Id,
            ffi::Type::Struct(identifier) => Self::Struct(identifier.clone()),
            ffi::Type::Enum(identifier) => Self::Enum(identifier.clone()),
            ffi::Type::Optional(t) => Self::Optional(Box::new((*t).into())),
            ffi::Type::Result(t_ok, t_err) => {
                Self::Result(Box::new(((*t_ok).into(), (*t_err).into())))
            }
        }
    }
}

/// Describes a name and type for an argument or field
///
/// Effectively an owned version of [`ffi::Arg`](crate::ffi::Arg).
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct ArgContract {
    /// Argument name
    pub name: Identifier,
    /// Argument type
    pub vtype: TypeContract,
}

impl ArgContract {
    fn validate(&self, other: &ffi::Arg<'_>) -> Result<(), ContractValidationError> {
        if self.name != other.name {
            return Err(ContractValidationError(format!(
                "VM expected `{}`",
                other.name
            )));
        }
        self.vtype.validate(&other.vtype).prepend("type")?;
        Ok(())
    }
}

impl From<&ffi::Arg<'_>> for ArgContract {
    fn from(value: &ffi::Arg<'_>) -> Self {
        Self {
            name: value.name.clone(),
            vtype: (&value.vtype).into(),
        }
    }
}

/// Describes function signatures
///
/// Effectively an owned version of [`ffi::Func`](crate::ffi::Func).
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct FunctionContract {
    /// Function name
    pub name: Identifier,
    /// Function arguments
    pub args: Vec<ArgContract>,
    /// Return type
    pub return_type: TypeContract,
}

impl FunctionContract {
    fn validate(&self, other: &ffi::Func<'_>) -> Result<(), ContractValidationError> {
        if self.name != other.name {
            return Err(ContractValidationError(format!(
                "function `{}`, VM expected `{}`",
                self.name, other.name
            )));
        }
        for (a1, a2) in self.args.iter().zip(other.args.iter()) {
            a1.validate(a2)
                .prepend(format!("function `{}` arg `{}`,", self.name, a1.name))?;
        }
        self.return_type
            .validate(&other.return_type)
            .prepend(format!("function `{}` return type", self.name))?;
        Ok(())
    }
}

impl From<&ffi::Func<'_>> for FunctionContract {
    fn from(value: &ffi::Func<'_>) -> Self {
        Self {
            name: value.name.clone(),
            args: value.args.iter().map(ArgContract::from).collect(),
            return_type: (&value.return_type).into(),
        }
    }
}

/// Describes struct signatures
///
/// Effectively an owned version of [`ffi::Struct`](crate::ffi::Struct).
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct StructContract {
    /// Struct name
    pub name: Identifier,
    /// Struct fields
    pub fields: Vec<ArgContract>,
}

impl StructContract {
    fn validate(&self, other: &ffi::Struct<'_>) -> Result<(), ContractValidationError> {
        if self.name != other.name {
            return Err(ContractValidationError(format!(
                "`struct {}`, VM expected `struct {}`",
                self.name, other.name
            )));
        }
        if self.fields.len() != other.fields.len() {
            return Err(ContractValidationError(format!(
                "`struct {}` has {} fields but VM expects {}",
                self.name,
                self.fields.len(),
                other.fields.len()
            )));
        }
        for (f1, f2) in self.fields.iter().zip(other.fields.iter()) {
            f1.validate(f2)
                .prepend(format!("`struct {}` field `{}`,", self.name, f1.name))?;
        }
        Ok(())
    }
}

impl From<&ffi::Struct<'_>> for StructContract {
    fn from(value: &ffi::Struct<'_>) -> Self {
        Self {
            name: value.name.clone(),
            fields: value.fields.iter().map(ArgContract::from).collect(),
        }
    }
}

/// Describes enum signatures
///
/// Effectively an owned version of [`ffi::Enum`](crate::ffi::Enum).
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct EnumContract {
    /// Enum name
    pub name: Identifier,
    /// Enum variants
    pub variants: Vec<Identifier>,
}

impl EnumContract {
    fn validate(&self, other: &ffi::Enum<'_>) -> Result<(), ContractValidationError> {
        if self.name != other.name {
            return Err(ContractValidationError(format!(
                "`enum {}`, VM expected `enum {}`",
                self.name, other.name
            )));
        }
        if self.variants.len() != other.variants.len() {
            return Err(ContractValidationError(format!(
                "`enum {}` has {} variants but VM expects {}",
                self.name,
                self.variants.len(),
                other.variants.len()
            )));
        }
        for (v1, v2) in self.variants.iter().zip(other.variants.iter()) {
            if v1 != v2 {
                return Err(ContractValidationError(format!(
                    "`enum {}` has variant `{}` but VM expected `{}`",
                    self.name, v1, v2
                )));
            }
        }
        Ok(())
    }
}

impl From<&ffi::Enum<'_>> for EnumContract {
    fn from(e: &ffi::Enum<'_>) -> Self {
        Self {
            name: e.name.clone(),
            variants: e.variants.to_vec(),
        }
    }
}

/// Describes the module names and function signatures
///
/// Effectively an owned version of [`ffi::ModuleSchema`](crate::ffi::ModuleSchema).
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct FfiContract {
    /// FFI module name
    pub name: Identifier,
    /// FFI functions
    pub functions: Vec<FunctionContract>,
    /// FFI-defined structs
    pub structs: Vec<StructContract>,
    /// FFI-defined enums
    pub enums: Vec<EnumContract>,
}

impl FfiContract {
    /// Validates a contract against a [`ModuleSchema`](ffi::ModuleSchema).
    pub fn validate(&self, other: &ffi::ModuleSchema<'_>) -> Result<(), ContractValidationError> {
        if self.name != other.name {
            return Err(ContractValidationError(format!(
                "FFI module `{}`, VM expected `{}`",
                self.name, other.name
            )));
        }

        if self.functions.len() != other.functions.len() {
            return Err(ContractValidationError(format!(
                "FFI module `{}` has {} functions but VM expects {}",
                self.name,
                self.functions.len(),
                other.functions.len()
            )));
        }
        for (f1, f2) in self.functions.iter().zip(other.functions.iter()) {
            f1.validate(f2)
                .prepend(format!("FFI module `{}`,", self.name))?;
        }

        if self.structs.len() != other.structs.len() {
            return Err(ContractValidationError(format!(
                "FFI module `{}` has {} structs but VM expects {}",
                self.name,
                self.structs.len(),
                other.structs.len()
            )));
        }
        for (s1, s2) in self.structs.iter().zip(other.structs.iter()) {
            s1.validate(s2)
                .prepend(format!("FFI module `{}`,", self.name))?;
        }

        if self.enums.len() != other.enums.len() {
            return Err(ContractValidationError(format!(
                "FFI module `{}` has {} enums but VM expects {}",
                self.name,
                self.enums.len(),
                other.enums.len()
            )));
        }
        for (e1, e2) in self.enums.iter().zip(other.enums.iter()) {
            e1.validate(e2)
                .prepend(format!("FFI module `{}`,", self.name))?;
        }
        Ok(())
    }
}

impl From<&ffi::ModuleSchema<'_>> for FfiContract {
    fn from(ms: &ffi::ModuleSchema<'_>) -> Self {
        Self {
            name: ms.name.clone(),
            functions: ms.functions.iter().map(FunctionContract::from).collect(),
            structs: ms.structs.iter().map(StructContract::from).collect(),
            enums: ms.enums.iter().map(EnumContract::from).collect(),
        }
    }
}

/// Describes the policy module contract so that this module can be validated against the expected
/// contract.
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct ModuleContract {
    /// FFI module names
    // TODO(chip): extend this to full schema, not just the name
    pub ffis: Vec<FfiContract>,
    // TODO(chip): catalog every other public-facing thing in a module - actions, effects, and
    // exported types
}
