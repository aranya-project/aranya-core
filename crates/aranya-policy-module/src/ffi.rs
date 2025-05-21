//! Data definitions used by the FFI interface
extern crate alloc;
use alloc::{boxed::Box, string::String};

use aranya_policy_ast::VType;

/// The type of a value
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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
    /// A named enum.
    Enum(&'a str),
    /// An optional type of some other type.
    Optional(&'a Type<'a>),
}

impl Type<'_> {
    // Like `==`, but can be used in a const context.
    //
    // Used by `policy-derive`.
    #[doc(hidden)]
    pub const fn const_eq(&self, rhs: &Self) -> bool {
        use Type::*;
        match (self, rhs) {
            (String, String) | (Bytes, Bytes) | (Int, Int) | (Bool, Bool) | (Id, Id) => true,
            (Struct(lhs), Struct(rhs)) => {
                // `lhs == rhs` cannot be used in a const
                // context.
                let lhs = lhs.as_bytes();
                let rhs = rhs.as_bytes();
                if lhs.len() != rhs.len() {
                    return false;
                }
                let mut i = 0;
                while i < lhs.len() && i < rhs.len() {
                    if lhs[i] != rhs[i] {
                        return false;
                    }
                    // Cannot overflow or wrap since `i` is
                    // `usize` and `<[_]>::len()` is at most
                    // `isize::MAX`.
                    #[allow(clippy::arithmetic_side_effects)]
                    {
                        i += 1;
                    }
                }
                true
            }
            (Optional(lhs), Optional(rhs)) => lhs.const_eq(rhs),
            _ => false,
        }
    }
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
            Type::Enum(s) => VType::Enum(String::from(*s)),
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

/// Enumeration
pub struct Enum<'a> {
    /// name of enumeration
    pub name: &'a str,
    /// list of possible values
    pub variants: &'a [&'a str],
}

/// Shorthand for creating [`Arg`]s.
///
/// # Example
///
/// ```rust
/// use aranya_policy_module::{
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
    ($name:literal, Enum($enum_name:literal)) => {{
        $crate::__arg!($name, Enum($enum_name))
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
            vtype: $crate::__type!($type),
        }
    }};
    ($name:literal, Struct($struct_name:literal)) => {{
        $crate::ffi::Arg {
            name: $name,
            vtype: $crate::__type!(Struct($struct_name)),
        }
    }};
    ($name:literal, Enum($enum_name:literal)) => {{
        $crate::ffi::Arg {
            name: $name,
            vtype: $crate::__type!(Enum($enum_name)),
        }
    }};
    ($name:literal, Optional($inner:expr)) => {{
        $crate::ffi::Arg {
            name: $name,
            vtype: $crate::__type!(Optional($inner)),
        }
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __type {
    (@raw $type:ident) => {
        $crate::ffi::Type::$type
    };
    (@raw Struct($struct_name:literal)) => {
        $crate::ffi::Type::Struct($struct_name)
    };
    (@raw Enum($enum_name:literal)) => {
        $crate::ffi::Type::Enum($enum_name)
    };
    (@raw Optional($inner:expr)) => {
        $crate::ffi::Type::Optional($inner)
    };

    (String) => {{ $crate::__type!(@raw String) }};
    (Bytes) => {{ $crate::__type!(@raw Bytes) }};
    (Int) => {{ $crate::__type!(@raw Int) }};
    (Bool) => {{ $crate::__type!(@raw Bool) }};
    (Id) => {{ $crate::__type!(@raw Id) }};
    (Struct($struct_name:literal)) => {{
        $crate::__type!(@raw Struct($struct_name))
    }};
    (Enum($enum_name:literal)) => {{
        $crate::__type!(@raw Enum($enum_name))
    }};
    (Optional($(inner:tt)+)) => {{
        $crate::__type!(@raw Optional($(inner)+))
    }};
    (Optional($inner:expr)) => {{
        $crate::__type!(@raw Optional($inner))
    }};
    ($type:ident) => {{
        ::core::compile_error!(::core::concat!(
            "unknown argument type: ",
            ::core::stringify!($type)
        ))
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
    /// list of enums
    pub enums: &'a [Enum<'a>],
}
