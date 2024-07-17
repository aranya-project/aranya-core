//! Data definitions used by the FFI interface
extern crate alloc;
use alloc::{boxed::Box, string::String};

use policy_ast::VType;

/// The type of a value
#[derive(Debug, Clone, PartialEq)]
pub enum Type<'a> {
    /// A UTF-8 string.
    String,
    /// A byte string
    Bytes,
    /// A signed, 64-bit integer.
    Int,
    /// A boolean.
    Bool,
    /// A unique identifier.
    Id,
    /// A named struct.
    Struct(&'a str),
    /// An optional type of some other type.
    Optional(&'a Type<'a>),
}

impl From<&Type<'_>> for VType {
    fn from(value: &Type<'_>) -> Self {
        match value {
            Type::String => VType::String,
            Type::Bytes => VType::Bytes,
            Type::Int => VType::Int,
            Type::Bool => VType::Bool,
            Type::Id => VType::Id,
            Type::Struct(s) => VType::Struct(String::from(*s)),
            Type::Optional(t) => VType::Optional(Box::new((*t).into())),
        }
    }
}

/// Describes the context in which the function can be called.
#[derive(Clone, Debug)]
pub enum Color<'a> {
    /// Function is valid outside of finish blocks, and returns
    /// a value.
    Pure(Type<'a>),
    /// Function is valid inside finish blocks, and does not
    /// return a value.
    Finish,
}

/// A foreign function.
#[derive(Clone, Debug)]
pub struct Func<'a> {
    /// The function's name.
    pub name: &'a str,
    /// The function's arguments.
    pub args: &'a [Arg<'a>],
    /// The return type of the function.
    pub return_type: Type<'a>,
}

/// An argument to a foreign function.
#[derive(Clone, Debug, PartialEq)]
pub struct Arg<'a> {
    /// The argument's name.
    pub name: &'a str,
    /// The field's type.
    pub vtype: Type<'a>,
}

/// A struct definition
pub struct Struct<'a> {
    /// The name of the struct.
    pub name: &'a str,
    /// The fields of the struct.
    pub fields: &'a [Arg<'a>],
}

/// Shorthand for creating [`Arg`]s.
///
/// # Example
///
/// ```rust
/// use policy_module::{
///     arg,
///     ffi::{Arg, Type},
/// };
///
/// let got = arg!("string", String);
/// let want = Arg { name: "string", vtype: Type::String };
/// assert_eq!(got, want);
///
/// let got = arg!("bytes", Bytes);
/// let want = Arg { name: "bytes", vtype: Type::Bytes };
/// assert_eq!(got, want);
///
/// let got = arg!("int", Int);
/// let want = Arg { name: "int", vtype: Type::Int };
/// assert_eq!(got, want);
///
/// let got = arg!("bool", Bool);
/// let want = Arg { name: "bool", vtype: Type::Bool };
/// assert_eq!(got, want);
///
/// let got = arg!("id", Id);
/// let want = Arg { name: "id", vtype: Type::Id };
/// assert_eq!(got, want);
///
/// let got = arg!("struct", Struct("foo"));
/// let want = Arg { name: "struct", vtype: Type::Struct("foo") };
/// assert_eq!(got, want);
///
/// let got = arg!("optional", Optional(&Type::Struct("bar")));
/// let want = Arg {
///     name: "optional",
///     vtype: Type::Optional(&Type::Struct("bar")),
/// };
/// assert_eq!(got, want);
/// ```
#[macro_export]
macro_rules! arg {
    ($name:literal, String) => {{
        $crate::__arg!($name, String)
    }};
    ($name:literal, Bytes) => {{
        $crate::__arg!($name, Bytes)
    }};
    ($name:literal, Int) => {{
        $crate::__arg!($name, Int)
    }};
    ($name:literal, Bool) => {{
        $crate::__arg!($name, Bool)
    }};
    ($name:literal, Id) => {{
        $crate::__arg!($name, Id)
    }};
    ($name:literal, Struct($struct_name:literal)) => {{
        $crate::__arg!($name, Struct($struct_name))
    }};
    ($name:literal, Optional($(inner:tt)+)) => {{
        $crate::__arg!($name, Optional($(inner)+))
    }};
    ($name:literal, Optional($inner:expr)) => {{
        $crate::__arg!($name, Optional($inner))
    }};
    ($name:literal, $type:ident) => {{
        ::core::compile_error!(::core::concat!(
            "unknown argument type: ",
            ::core::stringify!($type)
        ))
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __arg {
    ($name:literal, $type:ident) => {{
        $crate::ffi::Arg {
            name: $name,
            vtype: $crate::ffi::Type::$type,
        }
    }};
    ($name:literal, Struct($struct_name:literal)) => {{
        $crate::ffi::Arg {
            name: $name,
            vtype: $crate::ffi::Type::Struct($struct_name),
        }
    }};
    ($name:literal, Optional($inner:expr)) => {{
        $crate::ffi::Arg {
            name: $name,
            vtype: $crate::ffi::Type::Optional($inner),
        }
    }};
}

/// Foreign-function module declaration.
pub struct ModuleSchema<'a> {
    /// module name
    pub name: &'a str,
    /// list of functions provided by the module
    pub functions: &'a [Func<'a>],
    /// list of structs defined by the module
    pub structs: &'a [Struct<'a>],
}
