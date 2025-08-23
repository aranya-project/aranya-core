use std::{cell::RefCell, collections::HashMap};

use super::types::{Type, TypeCmd, TypeEffect, TypeFact, TypeOptional, TypeRef, TypeStruct};
use crate::{
    ctx::Ctx,
    symtab::{SymbolId, SymbolsView},
};

/// Type unification with internal mutability for state tracking
pub(crate) struct Unifier<'cx> {
    /// Shared context with type arena
    ctx: Ctx<'cx>,

    /// Symbol table for looking up Facts/Commands/Effects
    symbols: SymbolsView<'cx>,

    /// Internal state with RefCell for mutation without &mut
    state: RefCell<UnifierState>,
}

/// Mutable state of the unifier
struct UnifierState {
    /// For future: type variable bindings
    type_vars: HashMap<u32, Option<TypeRef>>,
    next_var_id: u32,

    /// Cache for synthesized struct types from Facts/Commands/Effects
    synthesized_structs: HashMap<SymbolId, TypeRef>,
}

impl<'cx> Unifier<'cx> {
    pub fn new(ctx: Ctx<'cx>, symbols: SymbolsView<'cx>) -> Self {
        Self {
            ctx,
            symbols,
            state: RefCell::new(UnifierState {
                type_vars: HashMap::new(),
                next_var_id: 0,
                synthesized_structs: HashMap::new(),
            }),
        }
    }

    /// Main unification function - returns unified type or None if incompatible
    /// Uses &self (not &mut self) thanks to RefCell
    pub fn unify(&self, t1: TypeRef, t2: TypeRef) -> Option<TypeRef> {
        // Fast path: identical types
        if t1 == t2 {
            return Some(t1);
        }

        let ty1 = self.ctx.get_type(t1);
        let ty2 = self.ctx.get_type(t2);

        match (ty1, ty2) {
            // Never type unifies with anything, yielding the other type
            (Type::Never, _) => Some(t2),
            (_, Type::Never) => Some(t1),

            // Infer type accepts anything (for deserialize)
            (Type::Infer, _) => Some(t2),
            (_, Type::Infer) => Some(t1),

            // None unifies with any Optional
            (Type::Optional(opt1), Type::Optional(opt2)) => {
                self.unify_optionals(opt1, opt2, t1, t2)
            }

            // Struct synthesis for Facts/Commands/Effects
            (Type::Fact(fact), Type::Struct(st)) | (Type::Struct(st), Type::Fact(fact)) => {
                self.unify_fact_as_struct(fact.symbol, st.symbol)
            }

            (Type::Cmd(cmd), Type::Struct(st)) | (Type::Struct(st), Type::Cmd(cmd)) => {
                self.unify_cmd_as_struct(cmd.symbol, st.symbol)
            }

            (Type::Effect(effect), Type::Struct(st)) | (Type::Struct(st), Type::Effect(effect)) => {
                self.unify_effect_as_struct(effect.symbol, st.symbol)
            }

            // Future: Type variables
            (Type::TypeVar(v), _) => self.bind_type_var(*v, t2),
            (_, Type::TypeVar(v)) => self.bind_type_var(*v, t1),

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
            (None, _) => Some(t2), // None unifies with any optional
            (_, None) => Some(t1),
            (Some(inner1), Some(inner2)) => {
                // Recursively unify inner types
                self.unify(inner1, inner2).map(|unified_inner| {
                    // Create new optional with unified inner type
                    if unified_inner == inner1 {
                        t1
                    } else if unified_inner == inner2 {
                        t2
                    } else {
                        // Need to create new optional type
                        self.ctx.intern_type(Type::Optional(TypeOptional {
                            inner: Some(unified_inner),
                        }))
                    }
                })
            }
        }
    }

    /// Check if a Fact can be used as a Struct
    fn unify_fact_as_struct(&self, fact_sym: SymbolId, struct_sym: SymbolId) -> Option<TypeRef> {
        // Facts can be used as structs with the same name
        // The old compiler synthesizes struct definitions for facts
        if self.symbols.get(fact_sym).ident == self.symbols.get(struct_sym).ident {
            // Return the struct type (prefer existing struct over synthesized)
            Some(self.get_or_synthesize_struct_for_fact(fact_sym))
        } else {
            None
        }
    }

    /// Check if a Command can be used as a Struct
    fn unify_cmd_as_struct(&self, cmd_sym: SymbolId, struct_sym: SymbolId) -> Option<TypeRef> {
        if self.symbols.get(cmd_sym).ident == self.symbols.get(struct_sym).ident {
            Some(self.get_or_synthesize_struct_for_cmd(cmd_sym))
        } else {
            None
        }
    }

    /// Check if an Effect can be used as a Struct
    fn unify_effect_as_struct(
        &self,
        effect_sym: SymbolId,
        struct_sym: SymbolId,
    ) -> Option<TypeRef> {
        if self.symbols.get(effect_sym).ident == self.symbols.get(struct_sym).ident {
            Some(self.get_or_synthesize_struct_for_effect(effect_sym))
        } else {
            None
        }
    }

    /// Get or create synthesized struct type for a fact
    pub fn get_or_synthesize_struct_for_fact(&self, fact_sym: SymbolId) -> TypeRef {
        let mut state = self.state.borrow_mut();

        // Check cache first
        if let Some(&ty_ref) = state.synthesized_structs.get(&fact_sym) {
            return ty_ref;
        }

        // Synthesize struct type from fact definition
        let ty_ref = self.synthesize_fact_struct(fact_sym);
        state.synthesized_structs.insert(fact_sym, ty_ref);
        ty_ref
    }

    /// Get or create synthesized struct type for a command
    pub fn get_or_synthesize_struct_for_cmd(&self, cmd_sym: SymbolId) -> TypeRef {
        let mut state = self.state.borrow_mut();

        // Check cache first
        if let Some(&ty_ref) = state.synthesized_structs.get(&cmd_sym) {
            return ty_ref;
        }

        // Synthesize struct type from command definition
        let ty_ref = self.synthesize_cmd_struct(cmd_sym);
        state.synthesized_structs.insert(cmd_sym, ty_ref);
        ty_ref
    }

    /// Get or create synthesized struct type for an effect
    pub fn get_or_synthesize_struct_for_effect(&self, effect_sym: SymbolId) -> TypeRef {
        let mut state = self.state.borrow_mut();

        // Check cache first
        if let Some(&ty_ref) = state.synthesized_structs.get(&effect_sym) {
            return ty_ref;
        }

        // Synthesize struct type from effect definition
        let ty_ref = self.synthesize_effect_struct(effect_sym);
        state.synthesized_structs.insert(effect_sym, ty_ref);
        ty_ref
    }

    fn synthesize_fact_struct(&self, fact_sym: SymbolId) -> TypeRef {
        // For now, create a basic struct - TODO: populate from actual fact definition
        self.ctx.intern_type(Type::Struct(TypeStruct {
            symbol: fact_sym,
            fields: Vec::new(), // TODO: get fields from fact definition
        }))
    }

    fn synthesize_cmd_struct(&self, cmd_sym: SymbolId) -> TypeRef {
        // For now, create a basic struct - TODO: populate from actual command definition
        self.ctx.intern_type(Type::Struct(TypeStruct {
            symbol: cmd_sym,
            fields: Vec::new(), // TODO: get fields from command definition
        }))
    }

    fn synthesize_effect_struct(&self, effect_sym: SymbolId) -> TypeRef {
        // For now, create a basic struct - TODO: populate from actual effect definition
        self.ctx.intern_type(Type::Struct(TypeStruct {
            symbol: effect_sym,
            fields: Vec::new(), // TODO: get fields from effect definition
        }))
    }

    /// Bind a type variable (for future inference support)
    fn bind_type_var(&self, var_id: u32, ty: TypeRef) -> Option<TypeRef> {
        let mut state = self.state.borrow_mut();
        match state.type_vars.get_mut(&var_id) {
            Some(slot @ None) => {
                *slot = Some(ty);
                Some(ty)
            }
            Some(Some(existing)) => {
                // Already bound - try to unify
                let existing = *existing;
                drop(state); // Release borrow before recursive call
                self.unify(existing, ty)
            }
            None => None,
        }
    }
}
