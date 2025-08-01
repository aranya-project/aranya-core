use std::{
    borrow::Cow,
    collections::{HashMap, hash_map},
    fmt::{self, Display},
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Type Error: {}", self.0)
    }
}

impl From<TypeError> for CompileErrorType {
    fn from(value: TypeError) -> Self {
        CompileErrorType::InvalidType(value.0.into_owned())
    }
}

/// Could not unify a pair of types.
pub struct TypeUnifyError {
    /// The left type which could not be unified
    pub left: NullableVType,
    /// The right type which could not be unified
    pub right: NullableVType,
    /// Context message for the cause of the unify error.
    pub ctx: &'static str,
}

impl Display for TypeUnifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { left, right, ctx } = self;
        write!(f, "{ctx}: {left} != {right}")
    }
}

// TODO: Remove and force callers to make better error.
impl From<TypeUnifyError> for CompileErrorType {
    fn from(err: TypeUnifyError) -> Self {
        CompileErrorType::InvalidType(err.to_string())
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
        for prev in locals.iter().rev() {
            if prev.contains_key(&ident) {
                return Err(CompileErrorType::AlreadyDefined(ident.to_string()));
            }
        }
        let block = locals.last_mut().expect("no block scope");
        match block.entry(ident) {
            hash_map::Entry::Occupied(_) => {
                unreachable!();
            }
            hash_map::Entry::Vacant(e) => {
                e.insert(value);
            }
        }
        Ok(())
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
/// sense here. Use one of the helper methods such as [`Self::unify`] or pattern matching.
//
// TODO(chip): This _should_
// eventually go away as every expression should be well-defined by the language. But we're
// not there yet.
#[must_use]
#[derive(Debug, Clone)]
pub enum Typeish {
    /// A definitely known type.
    Definitely(NullableVType),
    /// A known type unified with unknown type.
    ///
    /// This lets us type check more expressions while indicating that a runtime type check would
    /// be needed before blindly trusting this type.
    Probably(NullableVType),
    /// An unknown type.
    Indeterminate,
}

impl Typeish {
    /// Is this an instance of this type or an Indeterminate value? Indeterminate types
    /// always match.
    pub fn fits_type(&self, ot: &VType) -> bool {
        match self {
            Self::Definitely(t) | Self::Probably(t) => t.fits_type(ot),
            Self::Indeterminate => true,
        }
    }

    /// Checks this [`Typeish`] against an expected [`VType`].
    ///
    /// If `self` is `Indeterminate`, it will be "upgraded" to `Probably`.
    /// Otherwise, it will keep its value if the inner type matches the target,
    /// or error out otherwise.
    pub fn check_type(
        self,
        target_type: VType,
        errmsg: &'static str,
    ) -> Result<Self, TypeUnifyError> {
        match self {
            Self::Definitely(ref ty) | Self::Probably(ref ty) if ty.fits_type(&target_type) => {
                Ok(self)
            }
            Self::Indeterminate => Ok(Self::Probably(NullableVType::Type(target_type))),
            Self::Definitely(ty) | Self::Probably(ty) => Err(TypeUnifyError {
                left: ty,
                right: NullableVType::Type(target_type),
                ctx: errmsg,
            }),
        }
    }

    /// Create a definitely known type.
    pub fn known(vtype: VType) -> Self {
        Self::Definitely(NullableVType::Type(vtype))
    }

    /// Map over a type, preserving indeterminism.
    pub fn map<F>(self, f: F) -> Self
    where
        F: FnOnce(NullableVType) -> NullableVType,
    {
        match self {
            Self::Definitely(t) => Self::Definitely(f(t)),
            Self::Probably(t) => Self::Probably(f(t)),
            Self::Indeterminate => Self::Indeterminate,
        }
    }

    /// Try to map over a type, preserving indeterminism.
    pub fn try_map<F, R>(self, f: F) -> Result<Self, R>
    where
        F: FnOnce(NullableVType) -> Result<NullableVType, R>,
    {
        Ok(match self {
            Self::Definitely(t) => Self::Definitely(f(t)?),
            Self::Probably(t) => Self::Probably(f(t)?),
            Self::Indeterminate => Self::Indeterminate,
        })
    }

    /// Tries to unify two types, propagating uncertainty from either type.
    pub fn unify(self, other: Self) -> Result<Self, TypeUnifyError> {
        Ok(match (self, other) {
            // Two Indeterminate are Indeterminate
            (Self::Indeterminate, Self::Indeterminate) => Self::Indeterminate,

            // Indeterminate downgrades the other type to Probably
            (Self::Indeterminate, Self::Probably(t) | Self::Definitely(t))
            | (Self::Probably(t) | Self::Definitely(t), Self::Indeterminate) => Self::Probably(t),

            // Probably downgrades Definitely to Probably. The types must unify.
            (Self::Probably(left), Self::Probably(right))
            | (Self::Probably(left), Self::Definitely(right))
            | (Self::Definitely(left), Self::Probably(right)) => Self::Probably(left.unify(right)?),

            // The types must unify.
            (Self::Definitely(left), Self::Definitely(right)) => {
                Self::Definitely(left.unify(right)?)
            }
        })
    }
}

impl Display for Typeish {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Typeish::Definitely(t) => t.fmt(f),
            Typeish::Probably(t) => write!(f, "probably {t}"),
            Typeish::Indeterminate => f.write_str("unknown"),
        }
    }
}

#[must_use]
#[derive(Debug, Clone)]
pub enum NullableVType {
    Type(VType),
    Null,
}

impl NullableVType {
    /// Returns whether the type matches. Null will match any optional.
    pub fn fits_type(&self, ot: &VType) -> bool {
        match self {
            Self::Type(vtype) => vtype == ot,
            Self::Null => matches!(ot, VType::Optional(_)),
        }
    }

    /// Equal types will unify, and null will unify with any optional.
    fn unify(self, rhs: NullableVType) -> Result<Self, TypeUnifyError> {
        match (self, rhs) {
            (t @ NullableVType::Type(VType::Optional(_)), NullableVType::Null)
            | (NullableVType::Null, t @ NullableVType::Type(VType::Optional(_))) => Ok(t),
            (NullableVType::Type(left), NullableVType::Type(right)) if left == right => {
                Ok(NullableVType::Type(left))
            }
            (NullableVType::Null, NullableVType::Null) => Ok(NullableVType::Null),
            (left, right) => Err(TypeUnifyError {
                left,
                right,
                ctx: "type mismatch",
            }),
        }
    }
}

impl Display for NullableVType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type(vtype) => vtype.fmt(f),
            Self::Null => f.write_str("null"),
        }
    }
}

impl CompileState<'_> {
    /// Construct a struct's type, or error if the struct is not defined.
    pub(super) fn struct_type(&self, s: &ast::NamedStruct) -> Result<VType, TypeError> {
        if self.m.struct_defs.contains_key(&s.identifier) {
            Ok(VType::Struct(s.identifier.clone()))
        } else {
            Err(TypeError::new_owned(format!(
                "Struct `{}` not defined",
                s.identifier
            )))
        }
    }

    /// Construct the type of a query based on its fact argument, or error if the fact is
    /// not defined.
    pub(super) fn query_fact_type(&self, f: &ast::FactLiteral) -> Result<VType, TypeError> {
        if self.m.fact_defs.contains_key(&f.identifier) {
            Ok(VType::Struct(f.identifier.clone()))
        } else {
            Err(TypeError::new_owned(format!(
                "Fact `{}` not defined",
                f.identifier
            )))
        }
    }

    pub(super) fn unify_pair(
        &self,
        left_type: Typeish,
        right_type: Typeish,
    ) -> Result<Typeish, TypeUnifyError> {
        left_type.unify(right_type)
    }

    /// Like [`unify_pair`], except additionally the pair is checked against `target_type`
    /// and an error is produced if they don't match.
    pub(super) fn unify_pair_as(
        &self,
        left_type: Typeish,
        right_type: Typeish,
        target_type: VType,
        errmsg: &'static str,
    ) -> Result<Typeish, CompileErrorType> {
        Ok(self.unify_pair(
            left_type
                .check_type(target_type.clone(), errmsg)
                .map_err(|_| CompileErrorType::InvalidType(errmsg.into()))?,
            right_type
                .check_type(target_type, errmsg)
                .map_err(|_| CompileErrorType::InvalidType(errmsg.into()))?,
        )?)
    }
}
