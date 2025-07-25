//! Tests for name resolution and scope tracking.

use super::*;
use aranya_policy_ast::{ident, VType};

// ===== Basic Scope Tests =====

#[test]
fn test_basic_scope_management() {
    let mut resolver = NameResolver::new();
    
    // Define a variable in the current scope
    let binding = Binding {
        name: ident!("x"),
        ty: VType::Int,
        kind: BindingKind::Local,
        defined_at: 10,
    };
    
    resolver.define(ident!("x"), binding.clone()).expect("Should define x");
    
    // Look it up
    let found = resolver.lookup(&ident!("x")).expect("Should find x");
    assert_eq!(found.name, ident!("x"));
    assert_eq!(found.ty, VType::Int);
}

#[test]
fn test_nested_scopes() {
    let mut resolver = NameResolver::new();
    
    // Define in outer scope
    resolver.define(ident!("outer"), Binding {
        name: ident!("outer"),
        ty: VType::Int,
        kind: BindingKind::Local,
        defined_at: 10,
    }).unwrap();
    
    // Enter inner scope
    resolver.enter_scope();
    
    // Define in inner scope
    resolver.define(ident!("inner"), Binding {
        name: ident!("inner"),
        ty: VType::Bool,
        kind: BindingKind::Local,
        defined_at: 20,
    }).unwrap();
    
    // Both should be visible
    assert!(resolver.lookup(&ident!("outer")).is_some());
    assert!(resolver.lookup(&ident!("inner")).is_some());
    
    // Exit inner scope
    resolver.exit_scope();
    
    // Only outer should be visible
    assert!(resolver.lookup(&ident!("outer")).is_some());
    assert!(resolver.lookup(&ident!("inner")).is_none());
}

#[test]
fn test_already_defined_error() {
    let mut resolver = NameResolver::new();
    
    // Define once
    resolver.define(ident!("x"), Binding {
        name: ident!("x"),
        ty: VType::Int,
        kind: BindingKind::Local,
        defined_at: 10,
    }).unwrap();
    
    // Try to define again in same scope
    let result = resolver.define(ident!("x"), Binding {
        name: ident!("x"),
        ty: VType::Bool,
        kind: BindingKind::Local,
        defined_at: 20,
    });
    
    match result {
        Err(NameError::AlreadyDefined { name, location }) => {
            assert_eq!(name, ident!("x"));
            assert_eq!(location, 20);
        }
        _ => panic!("Expected AlreadyDefined error"),
    }
}

// ===== Global Variable Tests =====

#[test]
fn test_global_definition() {
    let mut resolver = NameResolver::new();
    
    // Define global
    resolver.define_global(ident!("CONFIG"), VType::Int, 10).unwrap();
    
    // Should be visible
    let binding = resolver.lookup(&ident!("CONFIG")).expect("Should find global");
    assert_eq!(binding.kind, BindingKind::Global);
}

#[test]
fn test_global_visible_in_function() {
    let mut resolver = NameResolver::new();
    
    // Define global
    resolver.define_global(ident!("MAX_SIZE"), VType::Int, 10).unwrap();
    
    // Enter function scope
    resolver.enter_scope();
    
    // Global should still be visible
    let binding = resolver.lookup(&ident!("MAX_SIZE")).expect("Should find global");
    assert_eq!(binding.kind, BindingKind::Global);
    
    resolver.exit_scope();
}

// ===== Shadowing Tests =====

#[test]
fn test_local_shadows_global() {
    let mut resolver = NameResolver::new();
    
    // Define global
    resolver.define_global(ident!("x"), VType::Int, 10).unwrap();
    
    // Enter function scope
    resolver.enter_scope();
    
    // Try to define local with same name
    let result = resolver.define(ident!("x"), Binding {
        name: ident!("x"),
        ty: VType::Int,
        kind: BindingKind::Local,
        defined_at: 20,
    });
    
    match result {
        Err(NameError::ShadowsGlobal { name, global_location, local_location }) => {
            assert_eq!(name, ident!("x"));
            assert_eq!(global_location, 10);
            assert_eq!(local_location, 20);
        }
        _ => panic!("Expected ShadowsGlobal error"),
    }
}

#[test]
fn test_parameter_shadows_global() {
    let mut resolver = NameResolver::new();
    
    // Define global
    resolver.define_global(ident!("size"), VType::Int, 10).unwrap();
    
    // Enter function scope
    resolver.enter_scope();
    
    // Try to define parameter with same name
    let result = resolver.define(ident!("size"), Binding {
        name: ident!("size"),
        ty: VType::Int,
        kind: BindingKind::Parameter,
        defined_at: 20,
    });
    
    match result {
        Err(NameError::ShadowsGlobal { name, global_location, local_location }) => {
            assert_eq!(name, ident!("size"));
            assert_eq!(global_location, 10);
            assert_eq!(local_location, 20);
        }
        _ => panic!("Expected ShadowsGlobal error"),
    }
}

#[test]
fn test_local_shadows_parameter() {
    let mut resolver = NameResolver::new();
    
    // Enter function scope
    resolver.enter_scope();
    
    // Define parameter
    resolver.define(ident!("x"), Binding {
        name: ident!("x"),
        ty: VType::Int,
        kind: BindingKind::Parameter,
        defined_at: 10,
    }).unwrap();
    
    // Try to define local with same name
    let result = resolver.define(ident!("x"), Binding {
        name: ident!("x"),
        ty: VType::Bool,
        kind: BindingKind::Local,
        defined_at: 20,
    });
    
    match result {
        Err(NameError::ShadowsParameter { name, param_location, local_location }) => {
            assert_eq!(name, ident!("x"));
            assert_eq!(param_location, 10);
            assert_eq!(local_location, 20);
        }
        _ => panic!("Expected ShadowsParameter error"),
    }
}

#[test]
fn test_nested_scope_shadowing() {
    let mut resolver = NameResolver::new();
    
    // Define in outer scope
    resolver.define(ident!("x"), Binding {
        name: ident!("x"),
        ty: VType::Int,
        kind: BindingKind::Local,
        defined_at: 10,
    }).unwrap();
    
    // Enter inner scope
    resolver.enter_scope();
    
    // Should NOT be able to shadow in inner scope (violates uniqueness rule)
    let result = resolver.define(ident!("x"), Binding {
        name: ident!("x"),
        ty: VType::Bool,
        kind: BindingKind::Local,
        defined_at: 20,
    });
    
    // Should fail with specific error about shadowing
    match result {
        Err(NameError::AlreadyDefined { name, location }) => {
            assert_eq!(name, ident!("x"));
            assert_eq!(location, 20);
        }
        Err(other) => panic!("Expected AlreadyDefined error, got {:?}", other),
        Ok(_) => panic!("Should not allow shadowing in nested scope"),
    }
}

// ===== Language Rules Tests =====

#[test]
fn test_language_rules_configuration() {
    let rules = LanguageRules {
        allow_global_shadowing: false,
        allow_parameter_shadowing: false,
        allow_outer_scope_shadowing: true,
    };
    
    let mut resolver = NameResolver::with_rules(rules);
    
    // Test that rules are applied
    resolver.define_global(ident!("test"), VType::Int, 10).unwrap();
    resolver.enter_scope();
    
    let result = resolver.define(ident!("test"), Binding {
        name: ident!("test"),
        ty: VType::Int,
        kind: BindingKind::Local,
        defined_at: 20,
    });
    
    // Should fail because allow_global_shadowing is false
    assert!(result.is_err());
}

// ===== Lookup Tests =====

#[test]
fn test_lookup_nonexistent() {
    let resolver = NameResolver::new();
    assert!(resolver.lookup(&ident!("nonexistent")).is_none());
}

#[test]
fn test_lookup_priority() {
    let mut resolver = NameResolver::new();
    
    // Define global
    resolver.define_global(ident!("x"), VType::Int, 10).unwrap();
    
    // Enter scope and define local (if rules allow)
    resolver.enter_scope();
    
    // Since we can't shadow globals, the lookup should find the global
    let binding = resolver.lookup(&ident!("x")).expect("Should find x");
    assert_eq!(binding.kind, BindingKind::Global);
}

// ===== Complex Scenarios =====

#[test]
fn test_multiple_nested_scopes() {
    let mut resolver = NameResolver::new();
    
    // Level 0
    resolver.define(ident!("a"), Binding {
        name: ident!("a"),
        ty: VType::Int,
        kind: BindingKind::Local,
        defined_at: 10,
    }).unwrap();
    
    // Level 1
    resolver.enter_scope();
    resolver.define(ident!("b"), Binding {
        name: ident!("b"),
        ty: VType::Bool,
        kind: BindingKind::Local,
        defined_at: 20,
    }).unwrap();
    
    // Level 2
    resolver.enter_scope();
    resolver.define(ident!("c"), Binding {
        name: ident!("c"),
        ty: VType::String,
        kind: BindingKind::Local,
        defined_at: 30,
    }).unwrap();
    
    // All should be visible
    assert!(resolver.lookup(&ident!("a")).is_some());
    assert!(resolver.lookup(&ident!("b")).is_some());
    assert!(resolver.lookup(&ident!("c")).is_some());
    
    // Exit level 2
    resolver.exit_scope();
    assert!(resolver.lookup(&ident!("a")).is_some());
    assert!(resolver.lookup(&ident!("b")).is_some());
    assert!(resolver.lookup(&ident!("c")).is_none());
    
    // Exit level 1
    resolver.exit_scope();
    assert!(resolver.lookup(&ident!("a")).is_some());
    assert!(resolver.lookup(&ident!("b")).is_none());
    assert!(resolver.lookup(&ident!("c")).is_none());
}

#[test]
fn test_function_with_parameters_and_locals() {
    let mut resolver = NameResolver::new();
    
    // Define some globals
    resolver.define_global(ident!("MAX"), VType::Int, 10).unwrap();
    
    // Enter function scope
    resolver.enter_scope();
    
    // Define parameters
    resolver.define(ident!("x"), Binding {
        name: ident!("x"),
        ty: VType::Int,
        kind: BindingKind::Parameter,
        defined_at: 20,
    }).unwrap();
    
    resolver.define(ident!("y"), Binding {
        name: ident!("y"),
        ty: VType::Int,
        kind: BindingKind::Parameter,
        defined_at: 30,
    }).unwrap();
    
    // Define locals
    resolver.define(ident!("sum"), Binding {
        name: ident!("sum"),
        ty: VType::Int,
        kind: BindingKind::Local,
        defined_at: 40,
    }).unwrap();
    
    // All should be accessible
    assert_eq!(resolver.lookup(&ident!("MAX")).unwrap().kind, BindingKind::Global);
    assert_eq!(resolver.lookup(&ident!("x")).unwrap().kind, BindingKind::Parameter);
    assert_eq!(resolver.lookup(&ident!("y")).unwrap().kind, BindingKind::Parameter);
    assert_eq!(resolver.lookup(&ident!("sum")).unwrap().kind, BindingKind::Local);
    
    // Exit function
    resolver.exit_scope();
    
    // Only global should remain
    assert!(resolver.lookup(&ident!("MAX")).is_some());
    assert!(resolver.lookup(&ident!("x")).is_none());
    assert!(resolver.lookup(&ident!("y")).is_none());
    assert!(resolver.lookup(&ident!("sum")).is_none());
}