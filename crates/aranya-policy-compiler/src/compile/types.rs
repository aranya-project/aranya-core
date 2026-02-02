use std::{
    collections::{HashMap, hash_map},
    fmt::{self, Display},
};

use aranya_policy_ast::{self as ast, FactLiteral, Identifier, NamedStruct, TypeKind, VType};

use crate::{CompileError, CompileErrorType, compile::CompileState};

/// Could not unify a pair of types.
pub struct TypeUnifyError {
    /// The left type which could not be unified
    pub left: VType,
    /// The right type which could not be unified
    pub right: VType,
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

pub(crate) enum UserType<'a> {
    Struct(&'a ast::StructDefinition),
    Fact(&'a ast::FactDefinition),
    Effect(&'a ast::EffectDefinition),
    Command(&'a ast::CommandDefinition),
}

/// Holds a stack of identifier-type mappings. Lookups traverse down the stack. The "current
/// scope" is the one on the top of the stack.
#[derive(Debug, Clone)]
pub struct IdentifierTypeStack {
    globals: HashMap<Identifier, VType>,
    locals: Vec<Vec<HashMap<Identifier, VType>>>,
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
    #[allow(clippy::result_large_err)]
    pub fn add_global(&mut self, name: Identifier, value: VType) -> Result<(), CompileErrorType> {
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
    #[allow(clippy::result_large_err)]
    pub fn add(&mut self, ident: Identifier, value: VType) -> Result<(), CompileErrorType> {
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
    #[allow(clippy::result_large_err)]
    pub fn get(&self, name: &Identifier) -> Result<VType, CompileErrorType> {
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

/// Checks this [`VType`] against an expected [`VType`].
///
/// If `self` is `Never`, it will become the expected type.
/// Otherwise, it will keep its value the type kind matches the target,
/// or error out otherwise.
#[allow(clippy::result_large_err)]
pub fn check_type(
    ty: VType,
    target_type: VType,
    errmsg: &'static str,
) -> Result<VType, TypeUnifyError> {
    match ty.kind {
        TypeKind::Never => Ok(target_type),
        _ => {
            if ty.fits_type(&target_type) {
                Ok(ty)
            } else {
                Err(TypeUnifyError {
                    left: ty,
                    right: target_type,
                    ctx: errmsg,
                })
            }
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
            TypeKind::Optional(inner) => write!(f, "option[{}]", DisplayType(inner)),
            TypeKind::Never => write!(f, "never"),
        }
    }
}

impl CompileState<'_> {
    /// Construct a struct's type, or error if the struct is not defined.
    pub(super) fn struct_type(&self, s: &NamedStruct) -> Result<VType, CompileError> {
        if self.m.struct_defs.contains_key(&s.identifier.name) {
            Ok(VType {
                kind: TypeKind::Struct(s.identifier.clone()),
                span: s.identifier.span,
            })
        } else {
            Err(self.err(CompileErrorType::InvalidType(format!(
                "Struct `{}` not defined",
                s.identifier
            ))))
        }
    }

    /// Construct the type of a query based on its fact argument, or error if the fact is
    /// not defined.
    pub(super) fn query_fact_type(&self, f: &FactLiteral) -> Result<VType, CompileError> {
        if self.m.fact_defs.contains_key(&f.identifier.name) {
            Ok(VType {
                kind: TypeKind::Struct(f.identifier.clone()),
                span: f.identifier.span,
            })
        } else {
            Err(self.err(CompileErrorType::InvalidType(format!(
                "Fact `{}` not defined",
                f.identifier
            ))))
        }
    }
}

#[allow(clippy::result_large_err)]
pub(super) fn unify_pair(left: VType, right: VType) -> Result<VType, TypeUnifyError> {
    match (&left.kind, &right.kind) {
        (_, TypeKind::Never) => Ok(left),
        (TypeKind::Never, _) => Ok(right),
        (TypeKind::Optional(left), TypeKind::Optional(right)) => {
            let inner = unify_pair(left.as_ref().clone(), right.as_ref().clone())?;
            Ok(VType {
                kind: TypeKind::Optional(Box::new(inner)),
                span: aranya_policy_ast::Span::empty(), // TODO
            })
        }
        (_, _) => {
            if left.matches(&right) {
                Ok(left)
            } else {
                Err(TypeUnifyError {
                    left,
                    right,
                    ctx: "type mismatch",
                })
            }
        }
    }
}

/// Like [`unify_pair`], except additionally the pair is checked against `target_type`
/// and an error is produced if they don't match.
#[allow(clippy::result_large_err)]
pub(super) fn unify_pair_as(
    left_type: VType,
    right_type: VType,
    target_type: VType,
    errmsg: &'static str,
) -> Result<VType, CompileErrorType> {
    Ok(unify_pair(
        check_type(left_type, target_type.clone(), errmsg)
            .map_err(|_| CompileErrorType::InvalidType(errmsg.into()))?,
        check_type(right_type, target_type, errmsg)
            .map_err(|_| CompileErrorType::InvalidType(errmsg.into()))?,
    )?)
}
