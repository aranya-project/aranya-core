use std::{
    borrow::Cow,
    collections::{HashMap, hash_map},
    fmt::{self, Display},
};

use aranya_policy_ast::{FactLiteral, Identifier, NamedStruct, TypeKind, VType};

use crate::{CompileErrorType, compile::CompileState};

/// Describes the nature of a type error
#[derive(Debug, PartialEq, Eq)]
pub struct TypeError(Cow<'static, str>);

impl TypeError {
    pub(super) fn new(msg: &'static str) -> Self {
        Self(Cow::from(msg))
    }

    pub(super) fn new_owned(msg: String) -> Self {
        Self(Cow::from(msg))
    }
}

impl Display for TypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Type Error: {}", self.0)
    }
}

impl From<TypeError> for CompileErrorType {
    fn from(value: TypeError) -> Self {
        Self::InvalidType(value.0.into_owned())
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
        Self::InvalidType(err.to_string())
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

/// A calculated type, which may be `Never`.
///
/// [`PartialEq`] and [`Eq`] are intentionally not derived, as naive equality doesn't make
/// sense here. Use one of the helper methods such as [`Self::unify`] or pattern matching.
#[must_use]
#[derive(Debug, Clone)]
pub enum Typeish {
    /// A known type.
    Known(NullableVType),
    /// The bottom type, which cannot be instantiated.
    ///
    /// This signifies a panic, currently from `todo()` or stubbed FFI.
    Never,
}

impl Typeish {
    /// Is this an instance of this type or a `Never` value?
    pub fn fits_type(&self, ot: &VType) -> bool {
        match self {
            Self::Known(t) => t.fits_type(ot),
            Self::Never => true,
        }
    }

    /// Checks this [`Typeish`] against an expected [`VType`].
    ///
    /// If `self` is `Never`, it will become the expected type.
    /// Otherwise, it will keep its value if the inner type matches the target,
    /// or error out otherwise.
    pub fn check_type(
        self,
        target_type: VType,
        errmsg: &'static str,
    ) -> Result<Self, TypeUnifyError> {
        match self {
            Self::Never => Ok(Self::Known(NullableVType::Type(target_type))),
            Self::Known(ty) => {
                if ty.fits_type(&target_type) {
                    Ok(Self::Known(ty))
                } else {
                    Err(TypeUnifyError {
                        left: ty,
                        right: NullableVType::Type(target_type),
                        ctx: errmsg,
                    })
                }
            }
        }
    }

    /// Create a known type.
    pub fn known(vtype: VType) -> Self {
        Self::Known(NullableVType::Type(vtype))
    }

    /// Map over a type, preserving indeterminism.
    pub fn map<F>(self, f: F) -> Self
    where
        F: FnOnce(NullableVType) -> NullableVType,
    {
        match self {
            Self::Known(t) => Self::Known(f(t)),
            Self::Never => Self::Never,
        }
    }

    /// Try to map over a type, preserving indeterminism.
    pub fn try_map<F, R>(self, f: F) -> Result<Self, R>
    where
        F: FnOnce(NullableVType) -> Result<NullableVType, R>,
    {
        Ok(match self {
            Self::Known(t) => Self::Known(f(t)?),
            Self::Never => Self::Never,
        })
    }

    /// Tries to unify two types.
    pub fn unify(self, other: Self) -> Result<Self, TypeUnifyError> {
        Ok(match (self, other) {
            (Self::Never, Self::Never) => Self::Never,
            (Self::Never, Self::Known(t)) => Self::Known(t),
            (Self::Known(t), Self::Never) => Self::Known(t),
            (Self::Known(left), Self::Known(right)) => Self::Known(left.unify(right)?),
        })
    }
}

impl Display for Typeish {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(t) => t.fmt(f),
            Self::Never => f.write_str("never"),
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
            Self::Type(vtype) => vtype.matches(ot),
            Self::Null => matches!(ot.kind, TypeKind::Optional(_)),
        }
    }

    /// Equal types will unify, and null will unify with any optional.
    fn unify(self, rhs: Self) -> Result<Self, TypeUnifyError> {
        match (self, rhs) {
            (ref t @ Self::Type(ref ty), Self::Null)
                if matches!(ty.kind, TypeKind::Optional(_)) =>
            {
                Ok(t.clone())
            }
            (Self::Null, ref t @ Self::Type(ref ty))
                if matches!(ty.kind, TypeKind::Optional(_)) =>
            {
                Ok(t.clone())
            }
            (Self::Type(left), Self::Type(right)) if left.matches(&right) => Ok(Self::Type(left)),
            (Self::Null, Self::Null) => Ok(Self::Null),
            (left, right) => Err(TypeUnifyError {
                left,
                right,
                ctx: "type mismatch",
            }),
        }
    }
}

// Wrapper type for displaying Type since we can't implement Display for external types
pub struct DisplayType<'a>(pub &'a VType);

impl Display for DisplayType<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0.kind {
            TypeKind::String => f.write_str("string"),
            TypeKind::Bytes => f.write_str("bytes"),
            TypeKind::Int => f.write_str("int"),
            TypeKind::Bool => f.write_str("bool"),
            TypeKind::Id => f.write_str("id"),
            TypeKind::Struct(id) => write!(f, "struct {}", id),
            TypeKind::Enum(id) => write!(f, "enum {}", id),
            TypeKind::Optional(inner) => write!(f, "optional {}", DisplayType(inner)),
        }
    }
}

impl Display for NullableVType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type(vtype) => DisplayType(vtype).fmt(f),
            Self::Null => f.write_str("null"),
        }
    }
}

impl CompileState<'_> {
    /// Construct a struct's type, or error if the struct is not defined.
    pub(super) fn struct_type(&self, s: &NamedStruct) -> Result<VType, TypeError> {
        if self.m.struct_defs.contains_key(&s.identifier.name) {
            Ok(VType {
                kind: TypeKind::Struct(s.identifier.clone()),
                span: s.identifier.span,
            })
        } else {
            Err(TypeError::new_owned(format!(
                "Struct `{}` not defined",
                s.identifier
            )))
        }
    }

    /// Construct the type of a query based on its fact argument, or error if the fact is
    /// not defined.
    pub(super) fn query_fact_type(&self, f: &FactLiteral) -> Result<VType, TypeError> {
        if self.m.fact_defs.contains_key(&f.identifier.name) {
            Ok(VType {
                kind: TypeKind::Struct(f.identifier.clone()),
                span: f.identifier.span,
            })
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
