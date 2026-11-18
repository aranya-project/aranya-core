use std::{
    collections::{HashMap, hash_map},
    fmt::{self, Display},
    sync::atomic::{AtomicBool, Ordering},
};

use aranya_policy_ast::{
    self as ast, FactLiteral, Ident, Identifier, NamedStruct, ResultTypeKind, Span, Spanned as _,
    TypeKind, VType,
};
use aranya_policy_module::ffi;
use indexmap::IndexMap;
use tracing::warn;

use crate::{
    CompileError,
    compile::{
        CompileState,
        error::{AlreadyDefined, InvalidType, NotDefined, UnusedVariable, rendering::Error as _},
    },
};

pub(crate) enum UserType<'a> {
    Struct(&'a ast::StructDefinition),
    Fact(&'a ast::FactDefinition),
    Effect(&'a ast::EffectDefinition),
    BaseCommand(&'a ast::BaseCommandDefinition),
    Command(&'a ast::CommandDefinition),
    FFIStruct(&'a ffi::Struct<'a>),
}

/// Holds a stack of identifier-type mappings. Lookups traverse down the stack. The "current
/// scope" is the one on the top of the stack.
#[derive(Debug)]
pub struct IdentifierTypeStack {
    globals: HashMap<Ident, VType>,
    locals: Vec<IndexMap<Ident, Local>>,
    /// When set, don't error on unused vars
    allow_unused: bool,
}

#[derive(Debug)]
struct Local {
    vtype: VType,
    used: AtomicBool,
}

impl IdentifierTypeStack {
    /// Create a new `IdentifierTypeStack`
    pub fn new(allow_unused: bool) -> Self {
        Self {
            globals: HashMap::new(),
            locals: Vec::new(),
            allow_unused,
        }
    }

    /// Add an identifier-type mapping to the global variables
    #[allow(clippy::result_large_err)]
    pub fn add_global(&mut self, name: Ident, value: VType) -> Result<(), AlreadyDefined> {
        match self.globals.entry(name.clone()) {
            hash_map::Entry::Occupied(o) => {
                let existing_global = o.key().clone();
                Err(AlreadyDefined::new(existing_global, name))
            }
            hash_map::Entry::Vacant(e) => {
                e.insert(value);
                Ok(())
            }
        }
    }

    /// Add an identifier-type mapping to the current scope
    #[allow(clippy::result_large_err)]
    pub fn add(&mut self, ident: Ident, vtype: VType) -> Result<(), AlreadyDefined> {
        if let Some((existing_global, _)) = self.globals.get_key_value(&ident) {
            return Err(AlreadyDefined::new(existing_global.clone(), ident));
        }
        for prev in self.locals.iter().rev() {
            if let Some((existing_var, _)) = prev.get_key_value(&ident) {
                return Err(AlreadyDefined::new(ident, existing_var.clone()));
            }
        }
        let block = self.locals.last_mut().expect("no block scope");
        match block.entry(ident) {
            indexmap::map::Entry::Occupied(_) => {
                unreachable!();
            }
            indexmap::map::Entry::Vacant(e) => {
                e.insert(Local {
                    vtype,
                    used: AtomicBool::new(false),
                });
            }
        }
        Ok(())
    }

    /// Retrieve a type for an identifier. Searches lower stack items if a mapping is not
    /// found in the current scope.
    #[allow(clippy::result_large_err)]
    pub fn get(&self, name: &Identifier) -> Result<VType, IdentNotDefined> {
        for scope in self.locals.iter().rev() {
            if let Some(v) = scope.get(name) {
                v.used.store(true, Ordering::Relaxed);
                return Ok(v.vtype.clone());
            }
        }
        if let Some(v) = self.globals.get(name) {
            return Ok(v.clone());
        }
        Err(IdentNotDefined)
    }

    /// Enters a function. This should add a block scope to an empty stack.
    pub fn enter_function(&mut self) {
        assert!(self.locals.is_empty());
        self.enter_block();
    }

    /// Exits a function. This should remove the last scope in the stack.
    pub fn exit_function(&mut self) -> Result<(), UnusedVariable> {
        let unused = self.exit_block();
        assert!(self.locals.is_empty());
        unused
    }

    /// Enter a new block scope.
    pub fn enter_block(&mut self) {
        self.locals.push(IndexMap::new());
    }

    /// Exit the current block scope, reporting any bindings in it that was never
    /// read.
    pub fn exit_block(&mut self) -> Result<(), UnusedVariable> {
        let scope = self.locals.pop().expect("no block scope");

        let unused: Vec<Ident> = scope
            .into_iter()
            .filter(|(_, local)| !local.used.load(Ordering::Relaxed))
            .map(|(name, _)| name)
            // Skip names with a leading underscore
            .filter(|name| !name.as_str().starts_with('_'))
            .collect();

        if !unused.is_empty() {
            let err = UnusedVariable { names: unused };
            if self.allow_unused {
                warn!("{}", err.description());
            } else {
                return Err(err);
            }
        }
        Ok(())
    }
}

pub(crate) struct IdentNotDefined;

impl Display for IdentNotDefined {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("identifier not found")
    }
}

/// Checks this [`VType`] against an expected [`VType`].
///
/// If `self` is `Never`, it will become the expected type.
/// Otherwise, it will keep its value the type kind matches the target,
/// or error out otherwise.
#[allow(clippy::result_large_err)]
pub fn check_type(vtype: VType, target_type: VType) -> Result<VType, InvalidType> {
    match vtype.inner {
        TypeKind::Never => Ok(target_type),
        _ => {
            if vtype.fits_type(&target_type) {
                Ok(vtype)
            } else {
                Err(InvalidType::new(
                    target_type.to_string(),
                    Some(target_type.span()),
                    vtype.to_string(),
                    vtype.span,
                ))
            }
        }
    }
}

impl CompileState<'_> {
    /// Construct a struct's type, or error if the struct is not defined.
    pub(super) fn struct_type(&self, s: &NamedStruct) -> Result<VType, CompileError> {
        if self.m.interface.struct_defs.contains_key(&s.name.inner) {
            Ok(VType {
                inner: TypeKind::Struct(s.name.clone()),
                span: s.name.span,
            })
        } else {
            let note = format!("struct `{}` not defined", s.name);
            Err(self.err(NotDefined(note, s.name.span)))
        }
    }

    /// Construct the type of a query based on its fact argument, or error if the fact is
    /// not defined.
    pub(super) fn query_fact_type(&self, f: &FactLiteral) -> Result<VType, CompileError> {
        if self.m.fact_defs.contains_key(&f.name.inner) {
            Ok(VType {
                inner: TypeKind::Struct(f.name.clone()),
                span: f.name.span,
            })
        } else {
            let note = format!("fact `{}` not defined", f.name);
            Err(self.err(NotDefined(note, f.name.span)))
        }
    }
}

#[allow(clippy::result_large_err)]
pub(super) fn unify_pair(left: VType, right: VType) -> Result<VType, InvalidType> {
    match (&left.inner, &right.inner) {
        (_, TypeKind::Never) => Ok(left),
        (TypeKind::Never, _) => Ok(right),
        (TypeKind::Optional(left), TypeKind::Optional(right)) => {
            let inner = unify_pair(left.as_ref().clone(), right.as_ref().clone())?;
            Ok(VType {
                inner: TypeKind::Optional(Box::new(inner)),
                span: Span::empty(), // TODO
            })
        }
        (TypeKind::Result(left_result), TypeKind::Result(right_result)) => {
            let ok = unify_pair(left_result.ok.clone(), right_result.ok.clone())?;
            let err = unify_pair(left_result.err.clone(), right_result.err.clone())?;
            Ok(VType {
                inner: TypeKind::Result(Box::new(ResultTypeKind { ok, err })),
                span: Span::empty(), // TODO
            })
        }
        (_, _) => {
            if left.matches(&right) {
                Ok(left)
            } else {
                Err(InvalidType::new(
                    left.to_string(),
                    Some(left.span()),
                    right.to_string(),
                    right.span(),
                ))
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
) -> Result<VType, InvalidType> {
    unify_pair(
        check_type(left_type, target_type.clone())?,
        check_type(right_type, target_type)?,
    )
}
