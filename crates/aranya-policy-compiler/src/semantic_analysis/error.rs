//! Error types for semantic analysis.

use aranya_policy_ast::{Identifier, VType};
use std::fmt;

/// Errors that can occur during semantic analysis.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{kind}")]
pub struct SemanticAnalysisError {
    pub kind: SemanticAnalysisErrorKind,
    pub location: Option<usize>,
}

impl SemanticAnalysisError {
    /// Create a new semantic analysis error.
    pub fn new(kind: SemanticAnalysisErrorKind, location: Option<usize>) -> Self {
        Self { kind, location }
    }

    /// Create a type mismatch error.
    pub fn type_mismatch(expected: VType, actual: VType, location: usize) -> Self {
        Self::new(
            SemanticAnalysisErrorKind::TypeMismatch { expected, actual },
            Some(location),
        )
    }

    /// Create a circular dependency error.
    pub fn circular_dependency(cycle: Vec<Identifier>) -> Self {
        Self::new(
            SemanticAnalysisErrorKind::CircularDependency { cycle },
            None,
        )
    }

    /// Create an invalid type error.
    pub fn invalid_type(message: String, location: usize) -> Self {
        Self::new(
            SemanticAnalysisErrorKind::InvalidType { message },
            Some(location),
        )
    }

    /// Create a context violation error.
    pub fn context_violation(message: String, location: usize) -> Self {
        Self::new(
            SemanticAnalysisErrorKind::ContextViolation { message },
            Some(location),
        )
    }

    /// Create a recursive definition error.
    pub fn recursive_definition(name: Identifier, location: usize) -> Self {
        Self::new(
            SemanticAnalysisErrorKind::RecursiveDefinition { name },
            Some(location),
        )
    }
}

/// Kinds of semantic analysis errors.
#[derive(Debug, Clone)]
pub enum SemanticAnalysisErrorKind {
    /// Type mismatch between expected and actual types.
    TypeMismatch {
        expected: VType,
        actual: VType,
    },

    /// Circular dependency detected in declarations.
    CircularDependency {
        cycle: Vec<Identifier>,
    },

    /// Invalid type usage.
    InvalidType {
        message: String,
    },

    /// Statement used in invalid context.
    ContextViolation {
        message: String,
    },

    /// Recursive definition detected.
    RecursiveDefinition {
        name: Identifier,
    },

    /// Function called recursively.
    RecursiveFunction {
        name: Identifier,
        call_chain: Vec<Identifier>,
    },

    /// Invalid field access.
    InvalidFieldAccess {
        struct_type: VType,
        field_name: Identifier,
    },

    /// Invalid array access.
    InvalidArrayAccess {
        array_type: VType,
        index_type: VType,
    },

    /// Invalid function call.
    InvalidFunctionCall {
        function_name: Identifier,
        expected_args: usize,
        actual_args: usize,
    },

    /// Invalid argument type in function call.
    InvalidArgumentType {
        function_name: Identifier,
        param_index: usize,
        expected: VType,
        actual: VType,
    },

    /// Invalid return type.
    InvalidReturnType {
        function_name: Identifier,
        expected: VType,
        actual: VType,
    },

    /// Invalid fact key field (must be hashable).
    InvalidFactKeyField {
        fact_name: Identifier,
        field_name: Identifier,
        field_type: VType,
    },

    /// Internal error (should not happen).
    InternalError(String),
}

impl fmt::Display for SemanticAnalysisErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SemanticAnalysisErrorKind::TypeMismatch { expected, actual } => {
                write!(f, "type mismatch: expected {}, found {}", expected, actual)
            }
            SemanticAnalysisErrorKind::CircularDependency { cycle } => {
                write!(f, "circular dependency detected: ")?;
                for (i, name) in cycle.iter().enumerate() {
                    if i > 0 {
                        write!(f, " -> ")?;
                    }
                    write!(f, "{}", name)?;
                }
                Ok(())
            }
            SemanticAnalysisErrorKind::InvalidType { message } => {
                write!(f, "invalid type: {}", message)
            }
            SemanticAnalysisErrorKind::ContextViolation { message } => {
                write!(f, "context violation: {}", message)
            }
            SemanticAnalysisErrorKind::RecursiveDefinition { name } => {
                write!(f, "recursive definition: {}", name)
            }
            SemanticAnalysisErrorKind::RecursiveFunction { name, call_chain } => {
                write!(f, "recursive function call: {}", name)?;
                if !call_chain.is_empty() {
                    write!(f, " (call chain: ")?;
                    for (i, caller) in call_chain.iter().enumerate() {
                        if i > 0 {
                            write!(f, " -> ")?;
                        }
                        write!(f, "{}", caller)?;
                    }
                    write!(f, ")")?;
                }
                Ok(())
            }
            SemanticAnalysisErrorKind::InvalidFieldAccess { struct_type, field_name } => {
                write!(f, "invalid field access: {} does not have field '{}'", struct_type, field_name)
            }
            SemanticAnalysisErrorKind::InvalidArrayAccess { array_type, index_type } => {
                write!(f, "invalid array access: cannot index {} with {}", array_type, index_type)
            }
            SemanticAnalysisErrorKind::InvalidFunctionCall { function_name, expected_args, actual_args } => {
                write!(f, "invalid function call: {}() expects {} arguments, got {}", 
                       function_name, expected_args, actual_args)
            }
            SemanticAnalysisErrorKind::InvalidArgumentType { function_name, param_index, expected, actual } => {
                write!(f, "invalid argument type in {}(): parameter {} expects {}, got {}", 
                       function_name, param_index + 1, expected, actual)
            }
            SemanticAnalysisErrorKind::InvalidReturnType { function_name, expected, actual } => {
                write!(f, "invalid return type in {}(): expected {}, got {}", 
                       function_name, expected, actual)
            }
            SemanticAnalysisErrorKind::InvalidFactKeyField { fact_name, field_name, field_type } => {
                write!(f, "invalid fact key field: {}.{} has type {} which is not hashable", 
                       fact_name, field_name, field_type)
            }
            SemanticAnalysisErrorKind::InternalError(message) => {
                write!(f, "internal error: {}", message)
            }
        }
    }
}