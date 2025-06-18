use std::{
    borrow::Cow,
    collections::{HashMap, hash_map},
    fmt::Display,
};

use aranya_policy_ast::{self as ast, Identifier};
use ast::VType;

use crate::{CompileErrorType, compile::CompileState};

/// Describes the nature of a type error
#[derive(Debug, PartialEq)]
pub struct TypeError(Cow<'static, str>);

impl TypeError {
    pub(super) fn new(msg: &'static str) -> TypeError {
        TypeError(Cow::from(msg))
    }

    pub(super) fn new_owned(msg: String) -> TypeError {
        TypeError(Cow::from(msg))
    }
}

impl Display for TypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Type Error: {}", self.0)
    }
}

impl From<TypeError> for CompileErrorType {
    fn from(value: TypeError) -> Self {
        CompileErrorType::InvalidType(value.0.into_owned())
    }
}

/// Holds a stack of identifier-type mappings. Lookups traverse down the stack. The "current
/// scope" is the one on the top of the stack.
#[derive(Debug, Clone)]
pub struct IdentifierTypeStack {
    globals: HashMap<Identifier, Typeish>,
    locals: Vec<Vec<HashMap<Identifier, Typeish>>>,
}

impl IdentifierTypeStack {
    /// Create a new `IdentifierTypeStack`
    pub fn new() -> Self {
        Self {
            globals: HashMap::new(),
            locals: vec![vec![HashMap::new()]],
        }
    }

    /// Add an identifier-type mapping to the global variables
    pub fn add_global(&mut self, name: Identifier, value: Typeish) -> Result<(), CompileErrorType> {
        match self.globals.entry(name) {
            hash_map::Entry::Occupied(o) => {
                Err(CompileErrorType::AlreadyDefined(o.key().to_string()))
            }
            hash_map::Entry::Vacant(e) => {
                e.insert(value);
                Ok(())
            }
        }
    }

    /// Add an identifier-type mapping to the current scope
    pub fn add(&mut self, ident: Identifier, value: Typeish) -> Result<(), CompileErrorType> {
        if self.globals.contains_key(&ident) {
            return Err(CompileErrorType::AlreadyDefined(ident.to_string()));
        }
        let locals = self.locals.last_mut().expect("no function scope");
        for prev in locals.iter().rev().skip(1) {
            if prev.contains_key(&ident) {
                return Err(CompileErrorType::AlreadyDefined(ident.to_string()));
            }
        }
        let block = locals.last_mut().expect("no block scope");
        match block.entry(ident) {
            hash_map::Entry::Occupied(o) => match (o.get(), &value) {
                (Typeish::Type(ty1), Typeish::Type(ty2)) if ty1 != ty2 => {
                    Err(CompileErrorType::InvalidType(format!(
                        "Definitions of `{}` do not have the same type: {ty1} != {ty2}",
                        o.key()
                    )))
                }
                _ => Ok(()),
            },
            hash_map::Entry::Vacant(e) => {
                e.insert(value);
                Ok(())
            }
        }
    }

    /// Retrieve a type for an identifier. Searches lower stack items if a mapping is not
    /// found in the current scope.
    pub fn get(&self, name: &Identifier) -> Result<Typeish, CompileErrorType> {
        if let Some(locals) = self.locals.last() {
            for scope in locals.iter().rev() {
                if let Some(v) = scope.get(name) {
                    return Ok(v.clone());
                }
            }
        }
        if let Some(v) = self.globals.get(name) {
            return Ok(v.clone());
        }
        Err(CompileErrorType::NotDefined(name.to_string()))
    }

    /// Push a new, empty scope on top of the type stack.
    pub fn enter_function(&mut self) {
        self.locals.push(vec![HashMap::new()]);
    }

    /// Pop the current scope off of the type stack. It is a fatal error to pop an empty
    /// stack, as this indicates a mistake in the compiler.
    pub fn exit_function(&mut self) {
        self.locals.pop().expect("no function scope");
    }

    /// Enter a new block scope.
    pub fn enter_block(&mut self) {
        self.locals
            .last_mut()
            .expect("no function scope")
            .push(HashMap::new());
    }

    /// Exit the current block scope.
    pub fn exit_block(&mut self) {
        self.locals
            .last_mut()
            .expect("no function scope")
            .pop()
            .expect("no block scope");
    }
}

/// This is a calculated type, which may be indeterminate if we don't have all the
/// information we need to calculate it.
///
/// [`PartialEq`] and [`Eq`] are intentionally not derived, as naive equality doesn't make
/// sense here. Use [`is_equal()`](Typeish::is_equal),
/// [`is_indeterminate()`](Typeish::is_indeterminate), and
/// [`is_maybe()`](Typeish::is_indeterminate).
//
// TODO(chip): This _should_
// eventually go away as every expression should be well-defined by the language. But we're
// not there yet.
#[must_use]
#[derive(Debug, Clone)]
pub enum Typeish {
    Type(VType),
    Indeterminate,
}

impl Typeish {
    /// If `self` is `Type(x)`, map `x` to `y` via `f()`
    pub fn map_vtype<F>(self, f: F) -> Typeish
    where
        F: Fn(VType) -> VType,
    {
        match self {
            Self::Type(t) => Self::Type(f(t)),
            x => x,
        }
    }

    /// If `self` is `Type(x)`, map `x` to `y` as a Result via `f()`
    pub fn map_result<F>(self, f: F) -> Result<Typeish, TypeError>
    where
        F: Fn(VType) -> Result<Typeish, TypeError>,
    {
        match self {
            Self::Type(t) => f(t),
            x => Ok(x),
        }
    }

    /// Two Typeish's are equal if they're both definite types and are the same type
    pub fn is_equal(&self, ot: &Typeish) -> bool {
        match (self, ot) {
            (Self::Type(x), Self::Type(y)) => x == y,
            _ => false,
        }
    }

    /// Two Typeish's are maybe equal if either one is indeterminate or they are the same
    /// definite type
    pub fn is_maybe_equal(&self, ot: &Typeish) -> bool {
        match (self, ot) {
            (Self::Type(x), Self::Type(y)) => x == y,
            _ => true,
        }
    }

    /// True if the type is indeterminate
    pub fn is_indeterminate(&self) -> bool {
        matches!(self, Self::Indeterminate)
    }

    /// Is this an instance of this type or an Indeterminate value? Indeterminate types
    /// always match.
    pub fn is_maybe(&self, ot: &VType) -> bool {
        match self {
            Self::Type(t) => t == ot,
            _ => true,
        }
    }

    /// Is this a struct of any kind or indeterminate?
    pub fn is_any_struct(&self) -> bool {
        match self {
            Self::Type(t) => matches!(t, VType::Struct(_)),
            _ => true,
        }
    }

    /// If self is not indeterminate and not the target type, return a [`TypeError`]
    pub fn check_type(&self, target_type: VType, errmsg: &'static str) -> Result<(), TypeError> {
        match self {
            Self::Type(t) => {
                if t != &target_type {
                    Err(TypeError::new(errmsg))
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }
}

impl Display for Typeish {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Typeish::Type(t) => write!(f, "{t}"),
            Typeish::Indeterminate => write!(f, "indeterminate"),
        }
    }
}

impl CompileState<'_> {
    /// Construct a struct's type, or error if the struct is not defined.
    pub(super) fn struct_type(&self, s: &ast::NamedStruct) -> Result<Typeish, TypeError> {
        if self.m.struct_defs.contains_key(&s.identifier) {
            Ok(Typeish::Type(VType::Struct(s.identifier.clone())))
        } else {
            Err(TypeError::new_owned(format!(
                "Struct `{}` not defined",
                s.identifier
            )))
        }
    }

    /// Construct the type of a query based on its fact argument, or error if the fact is
    /// not defined.
    pub(super) fn query_fact_type(&self, f: &ast::FactLiteral) -> Result<Typeish, TypeError> {
        if self.m.fact_defs.contains_key(&f.identifier) {
            Ok(Typeish::Type(VType::Struct(f.identifier.clone())))
        } else {
            Err(TypeError::new_owned(format!(
                "Fact `{}` not defined",
                f.identifier
            )))
        }
    }

    /// If two types are defined, and are the same, the result is that type. If they are
    /// different, it is a type error. If either type is indeterminate, the type is
    /// indeterminate.
    pub(super) fn unify_pair(
        &self,
        left_type: Typeish,
        right_type: Typeish,
    ) -> Result<Typeish, TypeError> {
        if left_type.is_equal(&right_type) {
            Ok(left_type)
        } else if left_type.is_indeterminate() || right_type.is_indeterminate() {
            Ok(Typeish::Indeterminate)
        } else {
            Err(TypeError::new_owned(format!(
                "types do not match: {left_type} and {right_type}"
            )))
        }
    }

    /// Like [`unify_pair`], except additionally the pair is checked against `target_type`
    /// and an error is produced if they don't match.
    pub(super) fn unify_pair_as(
        &self,
        left_type: Typeish,
        right_type: Typeish,
        target_type: VType,
        errmsg: &'static str,
    ) -> Result<(), TypeError> {
        self.unify_pair(left_type, right_type)?
            .check_type(target_type, errmsg)
    }
}
