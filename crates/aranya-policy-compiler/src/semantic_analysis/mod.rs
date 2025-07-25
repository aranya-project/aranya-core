//! Semantic analysis stage for the policy compiler.
//!
//! This stage performs type checking, cycle detection, and semantic validation
//! on a resolved AST. It takes the output from symbol resolution and produces
//! a fully type-checked and validated AST with topological ordering.

mod cycle_detector;
mod error;
mod type_checker;
mod validator;

#[cfg(test)]
mod tests;

pub use error::{SemanticAnalysisError, SemanticAnalysisErrorKind};

use aranya_policy_ast::{Identifier, VType, Expression, Statement, AstNode, StructItem, EffectFieldDefinition};
use crate::{
    dependency_graph::{DependencyGraph, NodeIdx},
    symbol_resolution::{ResolvedAst, SymbolTable, ResolutionResult, FieldLike},
};
use std::collections::HashMap;

/// Entry point for semantic analysis.
pub fn analyze(
    resolution_result: ResolutionResult,
) -> Result<SemanticAnalysisResult, SemanticAnalysisError> {
    let mut analyzer = SemanticAnalyzer::new(resolution_result);
    analyzer.analyze()
}

/// Result of semantic analysis.
#[derive(Debug, Clone)]
pub struct SemanticAnalysisResult {
    /// The type-checked AST.
    pub type_checked_ast: TypeCheckedAST,
    /// Symbol table (unchanged from resolution).
    pub symbol_table: SymbolTable,
    /// Topologically sorted declaration order.
    pub sorted_declarations: Vec<Identifier>,
}

/// AST wrapper that contains type information for all expressions.
#[derive(Debug, Clone)]
pub struct TypeCheckedAST {
    /// The resolved AST.
    pub resolved_ast: ResolvedAst,
    /// Map from expression locations to their inferred types.
    pub expression_types: HashMap<usize, VType>,
}

impl TypeCheckedAST {
    /// Create a new type-checked AST.
    pub fn new(resolved_ast: ResolvedAst) -> Self {
        Self {
            resolved_ast,
            expression_types: HashMap::new(),
        }
    }

    /// Add type information for an expression.
    pub fn add_expression_type(&mut self, location: usize, vtype: VType) {
        self.expression_types.insert(location, vtype);
    }

    /// Get the type of an expression at a given location.
    pub fn get_expression_type(&self, location: usize) -> Option<&VType> {
        self.expression_types.get(&location)
    }
}

/// Main semantic analyzer.
struct SemanticAnalyzer {
    /// The resolved AST being analyzed.
    resolved_ast: ResolvedAst,
    /// Symbol table from resolution.
    symbol_table: SymbolTable,
    /// Dependency graph from resolution.
    dependency_graph: DependencyGraph<Identifier>,
    /// Type-checked AST being built.
    type_checked_ast: TypeCheckedAST,
}

impl SemanticAnalyzer {
    /// Create a new semantic analyzer.
    fn new(resolution_result: ResolutionResult) -> Self {
        let type_checked_ast = TypeCheckedAST::new(resolution_result.resolved_ast.clone());

        Self {
            resolved_ast: resolution_result.resolved_ast,
            symbol_table: resolution_result.symbol_table,
            dependency_graph: DependencyGraph::new(),
            type_checked_ast,
        }
    }

    /// Perform semantic analysis.
    fn analyze(mut self) -> Result<SemanticAnalysisResult, SemanticAnalysisError> {
        // Step 1: Build dependency graph from resolved AST
        self.build_dependency_graph()?;

        // Step 2: Detect cycles in the dependency graph
        let sorted_nodes = cycle_detector::detect_cycles(&self.dependency_graph)?;

        // Step 3: Convert node indices to identifiers
        let sorted_declarations = self.nodes_to_identifiers(sorted_nodes)?;

        // Step 4: Type check all declarations in dependency order
        type_checker::type_check_declarations(
            &sorted_declarations,
            &mut self.type_checked_ast,
            &self.symbol_table,
        )?;

        // Step 5: Additional semantic validation
        validator::validate_semantics(&self.type_checked_ast, &self.symbol_table)?;

        Ok(SemanticAnalysisResult {
            type_checked_ast: self.type_checked_ast,
            symbol_table: self.symbol_table,
            sorted_declarations,
        })
    }

    /// Build dependency graph from resolved AST and symbol table.
    fn build_dependency_graph(&mut self) -> Result<(), SemanticAnalysisError> {
        // Add all declarations as nodes
        for (identifier, _) in self.symbol_table.symbols() {
            self.dependency_graph.add_node(identifier.clone());
        }

        // Build dependency edges by analyzing AST
        let ast = self.resolved_ast.ast.clone();

        // Global variables depend on their values
        for global_let in &ast.global_lets {
            let global_name = &global_let.inner.identifier;
            self.analyze_expression_dependencies(global_name, &global_let.inner.expression)?;
        }

        // Facts depend on their field types
        for fact in &ast.facts {
            let fact_name = &fact.inner.identifier;
            for field in &fact.inner.key {
                self.analyze_type_dependencies(fact_name, &field.field_type)?;
            }
            for field in &fact.inner.value {
                self.analyze_type_dependencies(fact_name, &field.field_type)?;
            }
        }

        // Actions depend on their parameter types and statement dependencies
        for action in &ast.actions {
            let action_name = &action.inner.identifier;
            for param in &action.inner.arguments {
                self.analyze_type_dependencies(action_name, &param.field_type)?;
            }
            for statement in &action.inner.statements {
                self.analyze_statement_dependencies(action_name, statement)?;
            }
        }

        // Effects depend on their field types
        for effect in &ast.effects {
            let effect_name = &effect.inner.identifier;
            for item in &effect.inner.items {
                self.analyze_struct_item_dependencies(effect_name, item)?;
            }
        }

        // Structs depend on their field types
        for struct_def in &ast.structs {
            let struct_name = &struct_def.inner.identifier;
            for item in &struct_def.inner.items {
                self.analyze_struct_item_dependencies(struct_name, item)?;
            }
        }

        // Commands depend on their field types
        for command in &ast.commands {
            let command_name = &command.inner.identifier;
            for item in &command.inner.fields {
                self.analyze_struct_item_dependencies(command_name, item)?;
            }
        }

        // Functions depend on their parameter types, return types, and statement dependencies
        for function in &ast.functions {
            let function_name = &function.inner.identifier;
            for param in &function.inner.arguments {
                self.analyze_type_dependencies(function_name, &param.field_type)?;
            }
            self.analyze_type_dependencies(function_name, &function.inner.return_type)?;
            for statement in &function.inner.statements {
                self.analyze_statement_dependencies(function_name, statement)?;
            }
        }

        // Finish functions depend on their parameter types and statement dependencies
        for finish_function in &ast.finish_functions {
            let function_name = &finish_function.inner.identifier;
            for param in &finish_function.inner.arguments {
                self.analyze_type_dependencies(function_name, &param.field_type)?;
            }
            for statement in &finish_function.inner.statements {
                self.analyze_statement_dependencies(function_name, statement)?;
            }
        }

        Ok(())
    }

    /// Convert node indices to identifiers.
    fn nodes_to_identifiers(&self, nodes: Vec<NodeIdx>) -> Result<Vec<Identifier>, SemanticAnalysisError> {
        let mut identifiers = Vec::new();

        for node in nodes {
            if let Some(identifier) = self.dependency_graph.get(node) {
                identifiers.push(identifier.clone());
            } else {
                return Err(SemanticAnalysisError::new(
                    SemanticAnalysisErrorKind::InternalError(
                        "Invalid node index in dependency graph".to_string()
                    ),
                    None,
                ));
            }
        }

        Ok(identifiers)
    }

    /// Analyze type dependencies and add edges to dependency graph.
    fn analyze_type_dependencies(&mut self, from: &Identifier, vtype: &VType) -> Result<(), SemanticAnalysisError> {
        use crate::dependency_graph::DependencyKind;

        match vtype {
            VType::Struct(struct_name) => {
                if self.symbol_table.contains(struct_name) {
                    self.dependency_graph.add_dependency(from.clone(), struct_name.clone(), DependencyKind::Type);
                }
            }
            VType::Enum(enum_name) => {
                if self.symbol_table.contains(enum_name) {
                    self.dependency_graph.add_dependency(from.clone(), enum_name.clone(), DependencyKind::EnumReference);
                }
            }
            VType::Optional(inner_type) => {
                self.analyze_type_dependencies(from, inner_type)?;
            }
            // Built-in types don't create dependencies
            VType::Int | VType::Bool | VType::String | VType::Id | VType::Bytes => {}
        }
        Ok(())
    }

    /// Analyze expression dependencies and add edges to dependency graph.
    fn analyze_expression_dependencies(&mut self, from: &Identifier, expression: &Expression) -> Result<(), SemanticAnalysisError> {
        use crate::dependency_graph::DependencyKind;

        match expression {
            Expression::Identifier(name) => {
                if self.symbol_table.contains(name) {
                    self.dependency_graph.add_dependency(from.clone(), name.clone(), DependencyKind::Global);
                }
            }
            Expression::FunctionCall(function_call) => {
                if self.symbol_table.contains(&function_call.identifier) {
                    self.dependency_graph.add_dependency(from.clone(), function_call.identifier.clone(), DependencyKind::FunctionCall);
                }
                for arg in &function_call.arguments {
                    self.analyze_expression_dependencies(from, arg)?;
                }
            }
            Expression::NamedStruct(named_struct) => {
                if self.symbol_table.contains(&named_struct.identifier) {
                    self.dependency_graph.add_dependency(from.clone(), named_struct.identifier.clone(), DependencyKind::Type);
                }
                for (_, field_expr) in &named_struct.fields {
                    self.analyze_expression_dependencies(from, field_expr)?;
                }
            }
            Expression::Dot(object, _field) => {
                self.analyze_expression_dependencies(from, object)?;
            }
            Expression::Add(left, right) => {
                self.analyze_expression_dependencies(from, left)?;
                self.analyze_expression_dependencies(from, right)?;
            }
            Expression::Subtract(left, right) => {
                self.analyze_expression_dependencies(from, left)?;
                self.analyze_expression_dependencies(from, right)?;
            }
            Expression::And(left, right) => {
                self.analyze_expression_dependencies(from, left)?;
                self.analyze_expression_dependencies(from, right)?;
            }
            Expression::Or(left, right) => {
                self.analyze_expression_dependencies(from, left)?;
                self.analyze_expression_dependencies(from, right)?;
            }
            Expression::EnumReference(enum_ref) => {
                if self.symbol_table.contains(&enum_ref.identifier) {
                    self.dependency_graph.add_dependency(from.clone(), enum_ref.identifier.clone(), DependencyKind::EnumReference);
                }
            }
            // Literals and other expressions don't create dependencies
            Expression::Int(_) |
            Expression::String(_) |
            Expression::Bool(_) |
            Expression::Optional(_) |
            Expression::InternalFunction(_) |
            Expression::ForeignFunctionCall(_) => {}
            _ => {
                // TODO: Handle other expression types as needed
            }
        }
        Ok(())
    }

    /// Analyze statement dependencies and add edges to dependency graph.
    fn analyze_statement_dependencies(&mut self, from: &Identifier, statement: &AstNode<Statement>) -> Result<(), SemanticAnalysisError> {
        use crate::dependency_graph::DependencyKind;

        match &statement.inner {
            Statement::Let(let_stmt) => {
                self.analyze_expression_dependencies(from, &let_stmt.expression)?;
            }
            Statement::Check(check_stmt) => {
                self.analyze_expression_dependencies(from, &check_stmt.expression)?;
            }
            Statement::Return(return_stmt) => {
                self.analyze_expression_dependencies(from, &return_stmt.expression)?;
            }
            Statement::ActionCall(action_call) => {
                if self.symbol_table.contains(&action_call.identifier) {
                    self.dependency_graph.add_dependency(from.clone(), action_call.identifier.clone(), DependencyKind::ActionCall);
                }
                for arg in &action_call.arguments {
                    self.analyze_expression_dependencies(from, arg)?;
                }
            }
            Statement::FunctionCall(func_call) => {
                if self.symbol_table.contains(&func_call.identifier) {
                    self.dependency_graph.add_dependency(from.clone(), func_call.identifier.clone(), DependencyKind::FunctionCall);
                }
                for arg in &func_call.arguments {
                    self.analyze_expression_dependencies(from, arg)?;
                }
            }
            Statement::Publish(expr) => {
                self.analyze_expression_dependencies(from, expr)?;
            }
            Statement::Emit(expr) => {
                self.analyze_expression_dependencies(from, expr)?;
            }
            Statement::DebugAssert(expr) => {
                self.analyze_expression_dependencies(from, expr)?;
            }
            Statement::Match(match_stmt) => {
                self.analyze_expression_dependencies(from, &match_stmt.expression)?;
                for arm in &match_stmt.arms {
                    for statement in &arm.statements {
                        self.analyze_statement_dependencies(from, statement)?;
                    }
                }
            }
            Statement::If(if_stmt) => {
                for (condition, branch_statements) in &if_stmt.branches {
                    self.analyze_expression_dependencies(from, condition)?;
                    for statement in branch_statements {
                        self.analyze_statement_dependencies(from, statement)?;
                    }
                }
                if let Some(else_statements) = &if_stmt.fallback {
                    for statement in else_statements {
                        self.analyze_statement_dependencies(from, statement)?;
                    }
                }
            }
            Statement::Finish(statements) => {
                for statement in statements {
                    self.analyze_statement_dependencies(from, statement)?;
                }
            }
            Statement::Map(map_stmt) => {
                for statement in &map_stmt.statements {
                    self.analyze_statement_dependencies(from, statement)?;
                }
            }
            Statement::Delete(_) | Statement::Create(_) | Statement::Update(_) => {
                // TODO: Handle fact literal dependencies
            }
        }
        Ok(())
    }

    /// Analyze struct item dependencies and add edges to dependency graph.
    fn analyze_struct_item_dependencies<T>(&mut self, from: &Identifier, item: &StructItem<T>) -> Result<(), SemanticAnalysisError>
    where
        T: FieldLike,
    {
        use crate::dependency_graph::DependencyKind;

        match item {
            StructItem::Field(field) => {
                self.analyze_type_dependencies(from, field.get_field_type())?;
            }
            StructItem::StructRef(struct_name) => {
                if self.symbol_table.contains(struct_name) {
                    self.dependency_graph.add_dependency(from.clone(), struct_name.clone(), DependencyKind::StructComposition);
                }
            }
        }
        Ok(())
    }
}
