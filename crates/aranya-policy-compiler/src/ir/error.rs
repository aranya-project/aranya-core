//! Structured error types for the IR module.

use aranya_policy_ast::{Identifier, VType};
use crate::ir::name_resolution::NameError;
use std::fmt;

/// Errors that can occur during IR building.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IRBuildError {
    /// A name was not defined in the current scope.
    NotDefined {
        /// The undefined name.
        name: Identifier,
        /// Where the name was referenced.
        location: usize,
    },
    
    /// Type mismatch in expression or statement.
    TypeMismatch {
        /// Expected type.
        expected: VType,
        /// Found type.
        found: VType,
        /// Where the mismatch occurred.
        location: usize,
    },
    
    /// A local variable shadows a global.
    ShadowsGlobal {
        /// The name being shadowed.
        name: Identifier,
        /// Where the global was defined.
        global_location: usize,
        /// Where the local shadows it.
        local_location: usize,
    },
    
    /// A parameter shadows a global.
    ParameterShadowsGlobal {
        /// The name being shadowed.
        name: Identifier,
        /// Where the global was defined.
        global_location: usize,
        /// Where the parameter shadows it.
        param_location: usize,
    },
    
    /// Variable already defined in current scope.
    AlreadyDefined {
        /// The name already defined.
        name: Identifier,
        /// Where it was first defined.
        first_location: usize,
        /// Where it was defined again.
        second_location: usize,
    },
    
    /// Unknown function referenced.
    UnknownFunction {
        /// The function name.
        name: Identifier,
        /// Where it was referenced.
        location: usize,
    },
    
    /// Unknown global referenced.
    UnknownGlobal {
        /// The global name.
        name: Identifier,
        /// Where it was referenced.
        location: usize,
    },
    
    /// Unsupported feature.
    UnsupportedFeature(String),
    
    /// Invalid AST structure.
    InvalidAst(String),
    
    /// Type error.
    TypeError(String),
    
    /// Name resolution error.
    NameError(NameError),
    
    /// Parse error.
    ParseError(String),
    
    /// Multiple errors occurred.
    Multiple(Vec<IRBuildError>),
}

impl fmt::Display for IRBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotDefined { name, location } => {
                write!(f, "undefined variable '{}' at position {}", name, location)
            }
            
            Self::TypeMismatch { expected, found, location } => {
                write!(f, "type mismatch at position {}: expected {:?}, found {:?}", 
                    location, expected, found)
            }
            
            Self::ShadowsGlobal { name, global_location, local_location } => {
                write!(f, "local variable '{}' at position {} shadows global defined at position {}", 
                    name, local_location, global_location)
            }
            
            Self::ParameterShadowsGlobal { name, global_location, param_location } => {
                write!(f, "parameter '{}' at position {} shadows global defined at position {}", 
                    name, param_location, global_location)
            }
            
            Self::AlreadyDefined { name, first_location, second_location } => {
                write!(f, "variable '{}' already defined at position {}, redefined at position {}", 
                    name, first_location, second_location)
            }
            
            Self::UnknownFunction { name, location } => {
                write!(f, "unknown function '{}' at position {}", name, location)
            }
            
            Self::UnknownGlobal { name, location } => {
                write!(f, "unknown global '{}' at position {}", name, location)
            }
            
            Self::UnsupportedFeature(feature) => {
                write!(f, "unsupported feature: {}", feature)
            }
            
            Self::InvalidAst(msg) => {
                write!(f, "invalid AST: {}", msg)
            }
            
            Self::TypeError(msg) => {
                write!(f, "type error: {}", msg)
            }
            
            Self::NameError(e) => {
                write!(f, "name error: {:?}", e)
            }
            
            Self::ParseError(msg) => {
                write!(f, "parse error: {}", msg)
            }
            
            Self::Multiple(errors) => {
                write!(f, "multiple errors:")?;
                for error in errors {
                    write!(f, "\n  - {}", error)?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for IRBuildError {}

impl From<NameError> for IRBuildError {
    fn from(error: NameError) -> Self {
        Self::NameError(error)
    }
}

/// Errors that can occur during dependency analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyError {
    /// Direct recursion detected.
    DirectRecursion {
        /// The recursive function.
        function: Identifier,
        /// Where the function is defined.
        location: usize,
    },
    
    /// Mutual recursion detected.
    MutualRecursion {
        /// The functions in the recursive cycle.
        cycle: Vec<Identifier>,
        /// Location information for each function.
        locations: Vec<usize>,
    },
    
    /// Circular dependency in globals.
    CircularGlobals {
        /// The globals in the cycle.
        cycle: Vec<Identifier>,
        /// Location information for each global.
        locations: Vec<usize>,
    },
    
    /// Complex cycle involving both functions and globals.
    ComplexCycle {
        /// The items in the cycle.
        cycle: Vec<DependencyNode>,
        /// Location information for each item.
        locations: Vec<usize>,
    },
}

/// A node in the dependency graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyNode {
    /// A function.
    Function(Identifier),
    /// A global variable.
    Global(Identifier),
}

impl fmt::Display for DependencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectRecursion { function, location } => {
                write!(f, "function '{}' at position {} is directly recursive", function, location)
            }
            
            Self::MutualRecursion { cycle, .. } => {
                write!(f, "mutual recursion detected between functions: {}", 
                    cycle.iter().map(|id| id.as_str()).collect::<Vec<_>>().join(" -> "))
            }
            
            Self::CircularGlobals { cycle, .. } => {
                write!(f, "circular dependency detected between globals: {}", 
                    cycle.iter().map(|id| id.as_str()).collect::<Vec<_>>().join(" -> "))
            }
            
            Self::ComplexCycle { cycle, .. } => {
                write!(f, "complex dependency cycle detected: {}", 
                    cycle.iter().map(|node| match node {
                        DependencyNode::Function(id) => format!("function({})", id),
                        DependencyNode::Global(id) => format!("global({})", id),
                    }).collect::<Vec<_>>().join(" -> "))
            }
        }
    }
}

impl std::error::Error for DependencyError {}

/// Errors that can occur during code generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodegenError {
    /// Function not found.
    FunctionNotFound(Identifier),
    
    /// Basic block not found.
    BlockNotFound(super::BlockId),
    
    /// Type mismatch.
    TypeMismatch(String),
    
    /// Unsupported feature.
    UnsupportedFeature(String),
    
    /// Invalid IR.
    InvalidIR(String),
}

impl fmt::Display for CodegenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FunctionNotFound(name) => write!(f, "function '{}' not found", name),
            Self::BlockNotFound(id) => write!(f, "basic block {} not found", id.0),
            Self::TypeMismatch(msg) => write!(f, "type mismatch: {}", msg),
            Self::UnsupportedFeature(feature) => write!(f, "unsupported feature: {}", feature),
            Self::InvalidIR(msg) => write!(f, "invalid IR: {}", msg),
        }
    }
}

impl std::error::Error for CodegenError {}

/// Errors that can occur during name resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverError {
    /// Name not defined.
    NotDefined {
        /// The undefined name.
        name: Identifier,
        /// Where it was referenced.
        location: usize,
    },
    
    /// Name already defined in scope.
    AlreadyDefined {
        /// The name.
        name: Identifier,
        /// Where it was first defined.
        first_location: usize,
        /// Where it was defined again.
        second_location: usize,
    },
    
    /// Local shadows global.
    ShadowsGlobal {
        /// The name.
        name: Identifier,
        /// Where the global was defined.
        global_location: usize,
        /// Where the local shadows it.
        local_location: usize,
    },
}

impl fmt::Display for ResolverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotDefined { name, location } => {
                write!(f, "name '{}' not defined at position {}", name, location)
            }
            
            Self::AlreadyDefined { name, first_location, second_location } => {
                write!(f, "name '{}' already defined at position {}, redefined at position {}", 
                    name, first_location, second_location)
            }
            
            Self::ShadowsGlobal { name, global_location, local_location } => {
                write!(f, "local '{}' at position {} shadows global at position {}", 
                    name, local_location, global_location)
            }
        }
    }
}

impl std::error::Error for ResolverError {}