//! Main symbol resolver implementation.

use std::{
    collections::{HashMap, HashSet},
    ops::DerefMut,
    rc::Rc,
};

use aranya_policy_ast::{
    ident, ActionDefinition, AstNode, CheckStatement, CommandDefinition, EffectDefinition,
    EffectFieldDefinition, EnumDefinition, EnumReference, Expression, FactDefinition,
    FieldDefinition, FinishFunctionDefinition, FunctionCall, FunctionDefinition,
    GlobalLetStatement, Identifier, IfStatement, LetStatement, MapStatement, MatchStatement,
    Policy, ReturnStatement, Statement, StructDefinition, StructItem, VType,
};
use aranya_policy_module::ffi::{self, ModuleSchema};
use buggy::{bug, BugExt};

use super::{
    error::SymbolResolutionError,
    scope::{InsertError, ScopeId, Scopes},
    symbols::{
        Status, SymAction, SymCommand, SymEffect, SymEnum, SymFact, SymFfiModule,
        SymFinishFunction, SymFunction, SymGlobalVar, SymLocalVar, SymStruct, SymType, Symbol,
        SymbolId, SymbolKind, Symbols,
    },
    ResolvedAst,
};

/// Symbol resolver that walks the AST and builds symbol table.
pub(super) struct Resolver<'a> {
    /// The policy being resolved.
    policy: &'a Policy,
    /// FFI modules.
    ffi_modules: &'a [ModuleSchema<'a>],
    /// Reserved identifiers that cannot be redefined.
    reserved_idents: HashSet<Identifier>,
    scopes: Scopes,
    symbols: Symbols,
    /// Map from identifier usage locations to their resolved
    /// symbols.
    resolved_idents: HashMap<usize, SymbolId>,
}

impl<'a> Resolver<'a> {
    /// Create a new resolver.
    pub fn new(policy: &'a Policy, ffi: &'a [ModuleSchema<'a>]) -> Self {
        Self {
            policy,
            ffi_modules: ffi,
            reserved_idents: HashSet::new(),
            scopes: Scopes::new(),
            symbols: Symbols::new(),
            resolved_idents: HashMap::new(),
        }
    }

    /// Perform symbol resolution.
    pub fn resolve(mut self) -> Result<ResolvedAst<'a>, SymbolResolutionError> {
        self.add_reserved_idents();
        self.add_ffi_modules()?;

        // First pass: collect all top-level declarations
        self.collect_declarations()?;

        // Second pass: resolve all identifier references
        self.resolve_references()?;

        Ok(ResolvedAst {
            ast: self.policy,
            identifier_resolutions: self.resolved_idents,
            symbol_table: self.scopes,
        })
    }

    fn add_reserved_idents(&mut self) {
        self.reserved_idents.insert(ident!("this"));
        self.reserved_idents.insert(ident!("envelope"));
        self.reserved_idents.insert(ident!("id"));
    }

    fn add_ffi_modules(&mut self) -> Result<(), SymbolResolutionError> {
        // for schema in self.ffi_modules {
        //     self.globals.insert(
        //         schema.name.clone(),
        //         Symbol::FfiModule(SymFfiModule {
        //             ident: schema.name,
        //             // TODO
        //             symbols: Rc::new(SymbolTable::new()),
        //         }),
        //     )?;
        // }
        // Ok(())
        todo!()
    }
}

impl<'a> Resolver<'a> {
    /// Adds a symbol to the global symbol table.
    fn add_global_def(
        &mut self,
        ident: Identifier,
        kind: SymbolKind,
        location: Option<usize>,
    ) -> Result<(), SymbolResolutionError> {
        let sym = Symbol {
            ident,
            kind,
            scope: ScopeId::GLOBAL,
            location,
        };
        if self.reserved_idents.contains(&sym.ident) {
            return Err(SymbolResolutionError::ReservedIdentifier {
                sym,
                reserved_for: "language built-ins",
            });
        }
        let ident = sym.ident.clone();
        let sym_id = self.symbols.insert(sym);
        match self.scopes.insert(ScopeId::GLOBAL, ident, sym_id) {
            Ok(()) => Ok(()),
            Err(InsertError::Duplicate(err)) => Err(SymbolResolutionError::Duplicate(err)),
            Err(InsertError::InvalidScopeId(_)) => bug!("global scope should always be valid"),
        }
    }

    fn collect_declarations(&mut self) -> Result<(), SymbolResolutionError> {
        for global in &self.policy.global_lets {
            self.collect_global_let(global)?;
        }
        for fact in &self.policy.facts {
            self.collect_fact(fact)?;
        }
        for action in &self.policy.actions {
            self.collect_action(action)?;
        }
        for effect in &self.policy.effects {
            self.collect_effect(effect)?;
        }
        for def in &self.policy.structs {
            self.collect_struct(def)?;
        }
        for def in &self.policy.enums {
            self.collect_enum(def)?;
        }
        for cmd in &self.policy.commands {
            self.collect_command(cmd)?;
        }
        for func in &self.policy.functions {
            self.collect_function(func)?;
        }
        for func in &self.policy.finish_functions {
            self.collect_finish_function(func)?;
        }
        Ok(())
    }

    /// Collect a global let statement.
    fn collect_global_let(
        &mut self,
        node: &AstNode<GlobalLetStatement>,
    ) -> Result<(), SymbolResolutionError> {
        let kind = SymbolKind::GlobalVar(SymGlobalVar {
            vtype: SymType::Unresolved,
            scope: self
                .scopes
                .create_child_scope(ScopeId::GLOBAL)
                .assume("global should always be valid")?,
        });
        self.add_global_def(node.identifier.clone(), kind, Some(node.locator))
    }

    /// Collect a fact definition.
    fn collect_fact(
        &mut self,
        node: &AstNode<FactDefinition>,
    ) -> Result<(), SymbolResolutionError> {
        let kind = SymbolKind::Fact(SymFact {
            keys: node
                .key
                .iter()
                .map(|f| (f.identifier.clone(), SymType::from(&f.field_type)))
                .collect(),
            values: node
                .value
                .iter()
                .map(|f| (f.identifier.clone(), SymType::from(&f.field_type)))
                .collect(),
        });
        self.add_global_def(node.identifier.clone(), kind, Some(node.locator))
    }

    /// Collect an action definition.
    fn collect_action(
        &mut self,
        node: &AstNode<ActionDefinition>,
    ) -> Result<(), SymbolResolutionError> {
        let kind = SymbolKind::Action(SymAction {
            params: node
                .arguments
                .iter()
                .map(|arg| (arg.identifier.clone(), SymType::from(&arg.field_type)))
                .collect(),
            scope: self
                .scopes
                .create_child_scope(ScopeId::GLOBAL)
                .assume("global should always be valid")?,
        });
        self.add_global_def(node.identifier.clone(), kind, Some(node.locator))
    }

    /// Collect an effect definition.
    fn collect_effect(
        &mut self,
        node: &AstNode<EffectDefinition>,
    ) -> Result<(), SymbolResolutionError> {
        let kind = SymbolKind::Effect(SymEffect {
            fields: Status::Unresolved,
        });
        self.add_global_def(node.identifier.clone(), kind, Some(node.locator))
    }

    /// Collect a struct definition.
    fn collect_struct(
        &mut self,
        node: &AstNode<StructDefinition>,
    ) -> Result<(), SymbolResolutionError> {
        let kind = SymbolKind::Struct(SymStruct {
            fields: Status::Unresolved,
        });
        self.add_global_def(node.identifier.clone(), kind, Some(node.locator))
    }

    /// Collect an enum definition.
    fn collect_enum(
        &mut self,
        node: &AstNode<EnumDefinition>,
    ) -> Result<(), SymbolResolutionError> {
        let kind = SymbolKind::Enum(SymEnum {
            variants: node.variants.clone(),
        });
        self.add_global_def(node.identifier.clone(), kind, Some(node.locator))
    }

    /// Collect a command definition.
    fn collect_command(
        &mut self,
        node: &AstNode<CommandDefinition>,
    ) -> Result<(), SymbolResolutionError> {
        let kind = SymbolKind::Command(SymCommand {
            // TODO(eric): Since we don't use `+Type` syntax for
            // command fields I think we can resolve builtins
            // like we do for function/action params.
            fields: Status::Unresolved,
            policy: Status::Unresolved,
            finish: Status::Unresolved,
            recall: Status::Unresolved,
        });
        self.add_global_def(node.identifier.clone(), kind, Some(node.locator))
    }

    /// Collect a function definition.
    fn collect_function(
        &mut self,
        node: &AstNode<FunctionDefinition>,
    ) -> Result<(), SymbolResolutionError> {
        let kind = SymbolKind::Function(SymFunction {
            params: node
                .arguments
                .iter()
                .map(|arg| (arg.identifier.clone(), SymType::from(&arg.field_type)))
                .collect(),
            result: SymType::from(&node.inner.return_type),
            scope: self
                .scopes
                .create_child_scope(ScopeId::GLOBAL)
                .assume("global should always be valid")?,
        });
        self.add_global_def(node.identifier.clone(), kind, Some(node.locator))
    }

    /// Collect a finish function definition.
    fn collect_finish_function(
        &mut self,
        node: &AstNode<FinishFunctionDefinition>,
    ) -> Result<(), SymbolResolutionError> {
        let kind = SymbolKind::FinishFunction(SymFinishFunction {
            params: node
                .arguments
                .iter()
                .map(|arg| (arg.identifier.clone(), SymType::from(&arg.field_type)))
                .collect(),
            scope: self
                .scopes
                .create_child_scope(ScopeId::GLOBAL)
                .assume("global should always be valid")?,
        });
        self.add_global_def(node.identifier.clone(), kind, Some(node.locator))
    }
}

impl<'a> Resolver<'a> {
    fn get_symbol_id(&self, ident: &Identifier) -> Result<SymbolId, SymbolResolutionError> {
        let sym_id = self
            .scopes
            .get(ScopeId::GLOBAL, ident)
            .assume("global scope should always be valid")?
            .ok_or_else(|| {
                SymbolResolutionError::Undefined {
                    ident: ident.clone(),
                    location: 0, // TODO: Use actual location
                }
            })?;
        Ok(sym_id)
    }

    fn get_global(&self, ident: &Identifier) -> Result<&Symbol, SymbolResolutionError> {
        let sym_id = self.get_symbol_id(ident)?;
        let sym = self
            .symbols
            .get(sym_id)
            .assume("symbol ID should be valid")?;
        Ok(sym)
    }

    fn get_global_mut(&mut self, ident: &Identifier) -> Result<&mut Symbol, SymbolResolutionError> {
        let sym_id = self.get_symbol_id(ident)?;
        let sym = self
            .symbols
            .get_mut(sym_id)
            .assume("symbol ID should be valid")?;
        Ok(sym)
    }

    fn get_symbol_scope(&self, ident: &Identifier) -> Result<ScopeId, SymbolResolutionError> {
        self.get_global(ident).map(|sym| sym.scope)
    }

    /// Second pass: resolve all identifier references.
    fn resolve_references(&mut self) -> Result<(), SymbolResolutionError> {
        for global in &self.policy.global_lets {
            self.resolve_global_let_references(global)?;
        }
        for action in &self.policy.actions {
            self.resolve_action_references(action)?;
        }
        for func in &self.policy.functions {
            self.resolve_function_references(func)?;
        }
        for func in &self.policy.finish_functions {
            self.resolve_finish_function_references(func)?;
        }
        Ok(())
    }

    /// Resolve references within a global let statement.
    fn resolve_global_let_references(
        &mut self,
        node: &'a AstNode<GlobalLetStatement>,
    ) -> Result<(), SymbolResolutionError> {
        let scope = self.get_symbol_scope(&node.identifier)?;
        self.resolve_expr(scope, &node.expression)
    }

    /// Resolve references within an action.
    fn resolve_action_references(
        &mut self,
        node: &'a AstNode<ActionDefinition>,
    ) -> Result<(), SymbolResolutionError> {
        // self.scope_manager.enter_scope(ScopeKind::Function);
        let scope = self.get_symbol_scope(&node.identifier)?;

        // Add parameters to local scope
        for param in &node.inner.arguments {
            self.add_parameter(&param.identifier, &param.field_type, node.locator)?;
        }

        // Resolve action body
        for stmt in &node.inner.statements {
            self.resolve_statement(scope, stmt)?;
        }

        Ok(())
    }

    /// Resolve references within a function.
    fn resolve_function_references(
        &mut self,
        function: &'a AstNode<FunctionDefinition>,
    ) -> Result<(), SymbolResolutionError> {
        self.scope_manager.enter_scope(ScopeKind::Function);

        // Add parameters to local scope
        for param in &function.inner.arguments {
            self.add_parameter(&param.identifier, &param.field_type, function.locator)?;
        }

        // Resolve return type
        self.resolve_type_reference(&function.inner.return_type, function.locator)?;

        // Resolve function body
        for statement in &function.inner.statements {
            self.resolve_statement(statement)?;
        }

        self.scope_manager.exit_scope();
        Ok(())
    }

    /// Resolve references within a finish function.
    fn resolve_finish_function_references(
        &mut self,
        finish_function: &'a AstNode<FinishFunctionDefinition>,
    ) -> Result<(), SymbolResolutionError> {
        self.scope_manager.enter_scope(ScopeKind::Function);

        // Add parameters to local scope
        for param in &finish_function.inner.arguments {
            self.add_parameter(
                &param.identifier,
                &param.field_type,
                finish_function.locator,
            )?;
        }

        // Resolve function body
        for statement in &finish_function.inner.statements {
            self.resolve_statement(statement)?;
        }

        self.scope_manager.exit_scope();
        Ok(())
    }

    /// Add a parameter to the current scope.
    fn add_parameter(
        &mut self,
        name: &Identifier,
        param_type: &VType,
        location: usize,
    ) -> Result<(), SymbolResolutionError> {
        // Resolve the parameter type
        self.resolve_type_reference(param_type, location)?;

        // Add to local scope
        if let Err((name, original_location)) =
            self.scope_manager.add_local_binding(name.clone(), location)
        {
            todo!("duplicate")
        }

        Ok(())
    }

    /// Resolve references in a statement.
    fn resolve_statement(
        &mut self,
        scope: ScopeId,
        statement: &'a AstNode<Statement>,
    ) -> Result<(), SymbolResolutionError> {
        match &statement.inner {
            Statement::Let(v) => {
                // Resolve the value expression first
                self.resolve_expr(scope, &v.expression)?;

                // Add to local scope (shadowing check)
                if let Err((name, original_location)) = self
                    .scope_manager
                    .add_local_binding(v.identifier.clone(), statement.locator)
                {
                    todo!("shadowing")
                }
            }
            Statement::Check(v) => {
                self.resolve_expr(scope, &v.expression)?;
            }
            Statement::Match(v) => {
                self.resolve_expr(scope, &v.expression)?;
                for arm in &v.arms {
                    // self.scope_manager.enter_scope(ScopeKind::Block);
                    let scope = self
                        .scopes
                        .create_child_scope(scope)
                        .assume("statement scope should always be valid")?;
                    // TODO: Handle pattern bindings in match arms
                    for stmt in &arm.statements {
                        self.resolve_statement(scope, stmt)?;
                    }
                }
            }
            Statement::If(v) => {
                // Resolve all branch conditions and statements
                for (cond, stmts) in &v.branches {
                    self.resolve_expr(scope, cond)?;

                    // self.scope_manager.enter_scope(ScopeKind::Block);
                    let scope = self
                        .scopes
                        .create_child_scope(scope)
                        .assume("statement scope should always be valid")?;
                    for stmt in stmts {
                        self.resolve_statement(scope, stmt)?;
                    }
                }

                // Resolve fallback (else) branch
                if let Some(stmts) = &v.fallback {
                    // self.scope_manager.enter_scope(ScopeKind::Block);
                    let scope = self
                        .scopes
                        .create_child_scope(scope)
                        .assume("statement scope should always be valid")?;
                    for stmt in stmts {
                        self.resolve_statement(scope, stmt)?;
                    }
                }
            }
            Statement::Finish(stmts) => {
                // self.scope_manager.enter_scope(ScopeKind::Block);
                let scope = self
                    .scopes
                    .create_child_scope(scope)
                    .assume("statement scope should always be valid")?;
                for stmt in stmts {
                    self.resolve_statement(scope, stmt)?;
                }
            }
            Statement::Map(v) => {
                // TODO: Resolve fact literal references in map_stmt.fact
                // self.scope_manager.enter_scope(ScopeKind::Block);
                let scope = self
                    .scopes
                    .create_child_scope(scope)
                    .assume("statement scope should always be valid")?;
                for stmt in &v.statements {
                    self.resolve_statement(scope, stmt)?;
                }
                self.scope_manager.exit_scope();
            }
            Statement::Return(v) => {
                self.resolve_expr(scope, &v.expression)?;
            }
            Statement::ActionCall(v) => {
                // TODO: Resolve action call directly without
                // creating temporary expression
                self.resolve_ident_ref(scope, &v.identifier, 0)?;
                for arg in &v.arguments {
                    self.resolve_expr(scope, arg)?;
                }
            }
            Statement::Publish(expr) => {
                self.resolve_expr(scope, expr)?;
            }
            Statement::Delete(v) => {
                todo!()
            }
            Statement::Create(v) => {
                todo!()
            }
            Statement::Update(update_stmt) => {
                todo!()
            }
            Statement::Emit(expr) => {
                self.resolve_expr(scope, expr)?;
            }
            Statement::FunctionCall(v) => {
                // TODO: Resolve function call directly without
                // creating temporary expression
                self.resolve_ident_ref(&v.identifier, 0)?;

                for arg in &v.arguments {
                    self.resolve_expr(scope, arg)?;
                }
            }
            Statement::DebugAssert(expr) => {
                self.resolve_expr(scope, expr)?;
            }
        }
        Ok(())
    }

    /// Resolve references in an expression.
    fn resolve_expr(
        &mut self,
        scope: ScopeId,
        expr: &'a Expression,
    ) -> Result<(), SymbolResolutionError> {
        match expr {
            // Literals do not have any references to resolve.
            Expression::Int(_) | Expression::String(_) | Expression::Bool(_) => {}
            Expression::Optional(v) => match v {
                Some(expr) => {
                    self.resolve_expr(scope, expr)?;
                }
                None => {}
            },
            Expression::NamedStruct(v) => {
                self.resolve_ident_ref(&v.identifier, 0)?;
                for (_, expr) in &v.fields {
                    self.resolve_expr(scope, expr)?;
                }
            }
            Expression::InternalFunction(_) => {
                todo!()
            }
            Expression::FunctionCall(v) => {
                self.resolve_ident_ref(&v.identifier, 0)?;
                for arg in &v.arguments {
                    self.resolve_expr(scope, arg)?;
                }
            }
            Expression::ForeignFunctionCall(_) => {
                todo!()
            }
            Expression::Identifier(name) => {
                // TODO: Get actual location
                self.resolve_ident_ref(name, 0)?;
            }
            Expression::EnumReference(v) => {
                self.resolve_ident_ref(&v.identifier, 0)?;
            }
            Expression::Dot(expr, _) => {
                self.resolve_expr(scope, expr)?;
            }
            Expression::Add(left, right)
            | Expression::Subtract(left, right)
            | Expression::And(left, right)
            | Expression::Or(left, right)
            | Expression::Equal(left, right)
            | Expression::NotEqual(left, right)
            | Expression::GreaterThan(left, right)
            | Expression::LessThan(left, right)
            | Expression::GreaterThanOrEqual(left, right)
            | Expression::LessThanOrEqual(left, right) => {
                self.resolve_expr(scope, left)?;
                self.resolve_expr(scope, right)?;
            }
            Expression::Negative(expr)
            | Expression::Not(expr)
            | Expression::Unwrap(expr)
            | Expression::CheckUnwrap(expr) => {
                self.resolve_expr(scope, expr)?;
            }
            Expression::Is(expr, _) => {
                self.resolve_expr(scope, expr)?;
            }
            Expression::Block(stmts, expr) => {
                // self.scope_manager.enter_scope(ScopeKind::Block);
                let scope = self
                    .scopes
                    .create_child_scope(scope)
                    .assume("block scope should always be valid")?;
                for stmt in stmts {
                    self.resolve_statement(scope, stmt)?;
                }
                self.resolve_expr(scope, expr)?;
            }
            Expression::Substruct(expr, identifier) => {
                self.resolve_expr(scope, expr)?;
                self.resolve_ident_ref(identifier, 0)?;
            }
            Expression::Match(_expr) => {
                todo!()
            }
        }
        Ok(())
    }

    /// Resolve an identifier reference.
    fn resolve_ident_ref(
        &mut self,
        scope: ScopeId,
        ident: &Identifier,
        location: usize,
    ) -> Result<(), SymbolResolutionError> {
        let sym_id = self
            .scopes
            .get(scope, ident)
            .assume("scope should always be valid")?
            .ok_or_else(|| SymbolResolutionError::Undefined {
                ident: ident.clone(),
                location,
            })?;
        self.resolved_idents.insert(location, sym_id);
        Ok(())
    }

    /// Resolve type references within a type.
    fn resolve_type_reference(
        &mut self,
        vtype: &VType,
        location: usize,
    ) -> Result<(), SymbolResolutionError> {
        match vtype {
            VType::Struct(name) => {
                self.resolve_ident_ref(name, location)?;
            }
            VType::Enum(name) => {
                self.resolve_ident_ref(name, location)?;
            }
            VType::Optional(inner_type) => {
                self.resolve_type_reference(inner_type, location)?;
            }
            // Built-in types don't need resolution
            VType::Int | VType::Bool | VType::String | VType::Id | VType::Bytes => {}
        }
        Ok(())
    }

    /// Extract fields from StructItem collections, handling both Field and StructRef variants.
    fn extract_struct_fields<T>(&self, items: &[StructItem<T>]) -> Vec<(Identifier, VType)>
    where
        T: FieldLike,
    {
        let mut fields = Vec::new();

        for item in items {
            match item {
                StructItem::Field(field) => {
                    fields.push((
                        field.get_identifier().clone(),
                        field.get_field_type().clone(),
                    ));
                }
                StructItem::StructRef(struct_name) => {
                    // Look up the referenced struct and add its fields
                    if let Some(symbol) = self.scopes.get(struct_name) {
                        if let SymbolKind::Struct {
                            fields: struct_fields,
                        } = &symbol.kind
                        {
                            fields.extend(struct_fields.clone());
                        }
                    }
                    // Note: We don't error here if the struct isn't found, as it might be defined later
                    // The semantic analysis stage will catch undefined references
                }
            }
        }

        fields
    }
}

/// Trait for types that can be used as struct fields.
pub trait FieldLike {
    fn get_identifier(&self) -> &Identifier;
    fn get_field_type(&self) -> &VType;
}

impl FieldLike for FieldDefinition {
    fn get_identifier(&self) -> &Identifier {
        &self.identifier
    }

    fn get_field_type(&self) -> &VType {
        &self.field_type
    }
}

impl FieldLike for EffectFieldDefinition {
    fn get_identifier(&self) -> &Identifier {
        &self.identifier
    }

    fn get_field_type(&self) -> &VType {
        &self.field_type
    }
}
