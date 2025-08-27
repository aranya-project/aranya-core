//! Type unification.
//!
//! # Rules
//!
//! ## Never
//!
//! `never` is implicitly converted to any other type.
//!
//! ## None
//!
//! `None` is implicitly converted to any `optional` type.

use std::collections::HashMap;

use super::{
    check::TypeChecker,
    types::{TypeKind, TypeOptional, TypeRef, TypeVar},
};

impl TypeChecker<'_> {
    pub(super) fn unify(&self, t1: TypeRef, t2: TypeRef) -> Option<TypeRef> {
        // Fast path: identical types.
        if t1 == t2 {
            return Some(t1);
        }

        let ty1 = self.ctx.get_type(t1);
        let ty2 = self.ctx.get_type(t2);

        match (ty1, ty2) {
            // Never can be implicitly converted to any other
            // type, so unification yields the other type.
            (TypeKind::Never, _) => Some(t2),
            (_, TypeKind::Never) => Some(t1),

            // Infer can be implicitly converted to any other
            // type, so unification yields the other type.
            (TypeKind::Infer, _) => Some(t2),
            (_, TypeKind::Infer) => Some(t1),

            // None unifies with any optional.
            (TypeKind::Optional(opt1), TypeKind::Optional(opt2)) => {
                self.unify_optionals(opt1, opt2, t1, t2)
            }

            (TypeKind::TypeVar(v), _) => self.bind_type_var(*v, t2),
            (_, TypeKind::TypeVar(v)) => self.bind_type_var(*v, t1),

            // Otherwise: types don't unify
            _ => None,
        }
    }

    fn unify_optionals(
        &self,
        opt1: &TypeOptional,
        opt2: &TypeOptional,
        t1: TypeRef,
        t2: TypeRef,
    ) -> Option<TypeRef> {
        match (opt1.inner, opt2.inner) {
            // None unifies with any optional
            (None, _) => Some(t2),
            (_, None) => Some(t1),
            (Some(inner1), Some(inner2)) => {
                // Recursively unify inner types
                self.unify(inner1, inner2).map(|ty| {
                    if ty != inner1 && ty != inner2 {
                        self.ctx
                            .intern_type(TypeKind::Optional(TypeOptional { inner: Some(ty) }))
                    } else {
                        t1 // or t2, same thing
                    }
                })
            }
        }
    }

    /// Bind a type variable.
    fn bind_type_var(&self, var: TypeVar, ty: TypeRef) -> Option<TypeRef> {
        let mut state = self.state.borrow_mut();
        match state.type_vars.get_mut(&var)? {
            slot @ None => {
                *slot = Some(ty);
                Some(ty)
            }
            Some(existing) => {
                // Already bound, so try to unify.
                let existing = *existing;
                drop(state);
                self.unify(existing, ty)
            }
        }
    }
}

/// Mutable state of the unifier
pub(super) struct UnifierState {
    /// For future: type variable bindings
    type_vars: HashMap<TypeVar, Option<TypeRef>>,
    #[allow(dead_code)]
    next_var_id: u32,
}

impl UnifierState {
    pub fn new() -> Self {
        Self {
            type_vars: HashMap::new(),
            next_var_id: 0,
        }
    }
}
