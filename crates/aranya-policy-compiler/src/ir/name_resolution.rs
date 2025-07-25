//! Name resolution and scope tracking for detecting shadowing and undefined names.

use std::collections::HashMap;
use aranya_policy_ast::{Identifier, VType};

#[cfg(test)]
mod tests;

/// Name resolver for tracking scopes and variable bindings.
#[derive(Debug)]
pub struct NameResolver {
    /// Stack of scopes, with the current scope at the end.
    scopes: Vec<Scope>,
    
    /// Global scope (separate from local scopes).
    global_scope: Scope,
    
    /// Language rules for what shadowing is allowed.
    rules: LanguageRules,
}

/// A scope containing variable bindings.
#[derive(Debug)]
struct Scope {
    /// Bindings in this scope.
    bindings: HashMap<Identifier, Binding>,
    
    /// Kind of scope.
    kind: ScopeKind,
}

/// Kind of scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    Global,
    Function,
    Block,
}

/// A variable binding.
#[derive(Debug, Clone)]
pub struct Binding {
    pub name: Identifier,
    pub ty: VType,
    pub kind: BindingKind,
    pub defined_at: usize, // source location
}

/// Kind of binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingKind {
    Global,
    Function,
    Parameter,
    Local,
}

/// Language rules for shadowing.
#[derive(Debug, Clone)]
pub struct LanguageRules {
    pub allow_local_shadows_local: bool,
    pub allow_local_shadows_parameter: bool,
    pub allow_local_shadows_global: bool,
    pub allow_parameter_shadows_global: bool,
}

impl Default for LanguageRules {
    fn default() -> Self {
        // Aranya policy language: no shadowing allowed
        Self {
            allow_local_shadows_local: false,
            allow_local_shadows_parameter: false,
            allow_local_shadows_global: false,
            allow_parameter_shadows_global: false,
        }
    }
}

/// Errors that can occur during name resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    /// Variable already defined in current scope.
    AlreadyDefined {
        name: Identifier,
        location: usize,
    },
    
    /// Local variable shadows a global.
    ShadowsGlobal {
        name: Identifier,
        global_location: usize,
        local_location: usize,
    },
    
    /// Local variable shadows a parameter.
    ShadowsParameter {
        name: Identifier,
        param_location: usize,
        local_location: usize,
    },
    
    /// Local variable shadows another local.
    ShadowsLocal {
        name: Identifier,
        outer_location: usize,
        inner_location: usize,
    },
    
    /// Variable not defined.
    NotDefined {
        name: Identifier,
        location: usize,
    },
}

impl NameResolver {
    /// Create a new name resolver with default rules.
    pub fn new() -> Self {
        Self {
            scopes: vec![],
            global_scope: Scope {
                bindings: HashMap::new(),
                kind: ScopeKind::Global,
            },
            rules: LanguageRules::default(),
        }
    }
    
    /// Create a new name resolver with custom rules.
    pub fn with_rules(rules: LanguageRules) -> Self {
        Self {
            scopes: vec![],
            global_scope: Scope {
                bindings: HashMap::new(),
                kind: ScopeKind::Global,
            },
            rules,
        }
    }
    
    /// Define a variable in the current scope.
    pub fn define(&mut self, name: Identifier, binding: Binding) -> Result<(), NameError> {
        // Check for duplicate in current scope
        let current_scope_has_name = self.current_scope_mut().bindings.contains_key(&name);
        if current_scope_has_name {
            return Err(NameError::AlreadyDefined {
                name,
                location: binding.defined_at,
            });
        }
        
        // Check for shadowing
        if let Some(outer_binding) = self.lookup_in_outer_scopes(&name) {
            let outer_kind = outer_binding.kind;
            let outer_location = outer_binding.defined_at;
            
            match (outer_kind, binding.kind) {
                (BindingKind::Global, BindingKind::Local) if !self.rules.allow_local_shadows_global => {
                    return Err(NameError::ShadowsGlobal {
                        name,
                        global_location: outer_location,
                        local_location: binding.defined_at,
                    });
                }
                (BindingKind::Global, BindingKind::Parameter) if !self.rules.allow_parameter_shadows_global => {
                    return Err(NameError::ShadowsGlobal {
                        name,
                        global_location: outer_location,
                        local_location: binding.defined_at,
                    });
                }
                (BindingKind::Parameter, BindingKind::Local) if !self.rules.allow_local_shadows_parameter => {
                    return Err(NameError::ShadowsParameter {
                        name,
                        param_location: outer_location,
                        local_location: binding.defined_at,
                    });
                }
                (BindingKind::Local, BindingKind::Local) if !self.rules.allow_local_shadows_local => {
                    return Err(NameError::ShadowsLocal {
                        name,
                        outer_location: outer_location,
                        inner_location: binding.defined_at,
                    });
                }
                _ => {} // Allowed
            }
        }
        
        self.current_scope_mut().bindings.insert(name, binding);
        Ok(())
    }
    
    /// Define a global variable.
    pub fn define_global(&mut self, name: Identifier, binding: Binding) -> Result<(), NameError> {
        if self.global_scope.bindings.contains_key(&name) {
            return Err(NameError::AlreadyDefined {
                name,
                location: binding.defined_at,
            });
        }
        
        self.global_scope.bindings.insert(name, binding);
        Ok(())
    }
    
    /// Look up a variable in all scopes.
    pub fn lookup(&self, name: &Identifier) -> Option<&Binding> {
        // Search from innermost to outermost scope
        for scope in self.scopes.iter().rev() {
            if let Some(binding) = scope.bindings.get(name) {
                return Some(binding);
            }
        }
        
        // Finally check global scope
        self.global_scope.bindings.get(name)
    }
    
    /// Look up a variable in outer scopes only (not current).
    fn lookup_in_outer_scopes(&self, name: &Identifier) -> Option<&Binding> {
        // Skip the current scope
        let outer_scopes = if self.scopes.len() > 1 {
            &self.scopes[..self.scopes.len() - 1]
        } else {
            &[]
        };
        
        // Search outer scopes
        for scope in outer_scopes.iter().rev() {
            if let Some(binding) = scope.bindings.get(name) {
                return Some(binding);
            }
        }
        
        // Check global scope
        self.global_scope.bindings.get(name)
    }
    
    /// Enter a new scope.
    pub fn enter_scope(&mut self) {
        self.scopes.push(Scope {
            bindings: HashMap::new(),
            kind: ScopeKind::Block,
        });
    }
    
    /// Enter a function scope.
    pub fn enter_function_scope(&mut self) {
        self.scopes.push(Scope {
            bindings: HashMap::new(),
            kind: ScopeKind::Function,
        });
    }
    
    /// Exit the current scope.
    pub fn exit_scope(&mut self) {
        self.scopes.pop();
    }
    
    /// Get the current scope for mutation.
    fn current_scope_mut(&mut self) -> &mut Scope {
        self.scopes.last_mut()
            .unwrap_or(&mut self.global_scope)
    }
    
    /// Check if we're in global scope.
    pub fn is_global_scope(&self) -> bool {
        self.scopes.is_empty()
    }
}