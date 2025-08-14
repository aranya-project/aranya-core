//! Type unification for type inference.
//!
//! This module implements unification to resolve type variables
//! when we need to infer types (e.g., for let bindings without
//! explicit type annotations).

use std::collections::BTreeMap;

use crate::{
    arena::Arena,
    typecheck::types::{Type, TypeId, TypeKind, TypeVarId},
};

/// Type unification context.
pub(crate) struct Unifier<'a> {
    /// The type arena.
    types: &'a Arena<TypeId, Type>,
    
    /// Substitutions from type variables to concrete types.
    substitutions: BTreeMap<TypeVarId, Type>,
}

impl<'a> Unifier<'a> {
    /// Creates a new unifier.
    pub fn new(types: &'a Arena<TypeId, Type>) -> Self {
        Self {
            types,
            substitutions: BTreeMap::new(),
        }
    }
    
    /// Unifies two types, updating substitutions as needed.
    ///
    /// Returns true if unification succeeded, false otherwise.
    pub fn unify(&mut self, ty1: Type, ty2: Type) -> bool {
        let ty1 = self.resolve(ty1);
        let ty2 = self.resolve(ty2);
        
        match (&ty1.kind, &ty2.kind) {
            // Two type variables
            (TypeKind::TypeVar(v1), TypeKind::TypeVar(v2)) if v1 == v2 => true,
            (TypeKind::TypeVar(v), _) => {
                self.substitutions.insert(*v, ty2);
                true
            }
            (_, TypeKind::TypeVar(v)) => {
                self.substitutions.insert(*v, ty1);
                true
            }
            
            // Error types unify with anything (to avoid cascading errors)
            (TypeKind::Error, _) | (_, TypeKind::Error) => true,
            
            // Unknown types unify with anything
            (TypeKind::Unknown, _) => {
                // ty1 becomes ty2
                true
            }
            (_, TypeKind::Unknown) => {
                // ty2 becomes ty1
                true
            }
            
            // Optional types
            (TypeKind::Optional(inner1), TypeKind::Optional(inner2)) => {
                if let (Some(t1), Some(t2)) = (self.types.get(*inner1), self.types.get(*inner2)) {
                    self.unify(*t1, *t2)
                } else {
                    false
                }
            }
            
            // Primitive types must match exactly
            (TypeKind::String, TypeKind::String) => true,
            (TypeKind::Bytes, TypeKind::Bytes) => true,
            (TypeKind::Int, TypeKind::Int) => true,
            (TypeKind::Bool, TypeKind::Bool) => true,
            (TypeKind::Id, TypeKind::Id) => true,
            
            // Struct types must refer to the same struct
            (TypeKind::Struct(s1), TypeKind::Struct(s2)) => s1 == s2,
            
            // Enum types must refer to the same enum
            (TypeKind::Enum(e1), TypeKind::Enum(e2)) => e1 == e2,
            
            // Different types don't unify
            _ => false,
        }
    }
    
    /// Resolves a type by following substitutions for type variables.
    pub fn resolve(&self, ty: Type) -> Type {
        match ty.kind {
            TypeKind::TypeVar(var) => {
                if let Some(&substituted) = self.substitutions.get(&var) {
                    // Follow the chain of substitutions
                    self.resolve(substituted)
                } else {
                    ty
                }
            }
            TypeKind::Optional(inner_id) => {
                if let Some(inner) = self.types.get(inner_id) {
                    let resolved_inner = self.resolve(*inner);
                    if resolved_inner.id != inner_id {
                        // The inner type was resolved to something different
                        Type::new(ty.id, TypeKind::Optional(resolved_inner.id))
                    } else {
                        ty
                    }
                } else {
                    ty
                }
            }
            _ => ty,
        }
    }
    
    /// Returns the current substitutions.
    pub fn substitutions(&self) -> &BTreeMap<TypeVarId, Type> {
        &self.substitutions
    }
    
    /// Applies the current substitutions to a type environment.
    pub fn apply_substitutions(&self, ty: Type) -> Type {
        self.resolve(ty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_unify_same_type() {
        let mut arena = Arena::new();
        let int_type = Type::new(arena.next_id(), TypeKind::Int);
        arena.insert(int_type);
        
        let mut unifier = Unifier::new(&arena);
        assert!(unifier.unify(int_type, int_type));
    }
    
    #[test]
    fn test_unify_type_var() {
        let mut arena = Arena::new();
        let int_type = Type::new(arena.next_id(), TypeKind::Int);
        let var_type = Type::new(arena.next_id(), TypeKind::TypeVar(TypeVarId(0)));
        arena.insert(int_type);
        arena.insert(var_type);
        
        let mut unifier = Unifier::new(&arena);
        assert!(unifier.unify(var_type, int_type));
        
        // The type variable should now resolve to int
        let resolved = unifier.resolve(var_type);
        assert_eq!(resolved.kind, TypeKind::Int);
    }
    
    #[test]
    fn test_unify_different_types() {
        let mut arena = Arena::new();
        let int_type = Type::new(arena.next_id(), TypeKind::Int);
        let bool_type = Type::new(arena.next_id(), TypeKind::Bool);
        arena.insert(int_type);
        arena.insert(bool_type);
        
        let mut unifier = Unifier::new(&arena);
        assert!(!unifier.unify(int_type, bool_type));
    }
}