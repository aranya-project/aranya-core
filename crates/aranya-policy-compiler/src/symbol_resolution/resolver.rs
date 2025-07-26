//! Main symbol resolver implementation.

use std::collections::{HashMap, HashSet};

use aranya_policy_ast;
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
    ResolvedHir,
};
use crate::hir::{
    arena::AstNodes,
    hir::{
        ActionDef, ActionId, BlockId, CmdDef, CmdId, EffectDef, EffectId, EnumDef, EnumId, ExprId,
        ExprKind, FactDef, FactField, FactId, FactLiteral, FinishFuncDef, FinishFuncId, FuncDef,
        FuncId, GlobalId, GlobalLetDef, Hir, IdentId, InternalFunction, StmtId, StmtKind,
        StructDef, StructId, VTypeId, VTypeKind,
    },
};

/// A hint for finding source locations in AST nodes.
#[derive(Copy, Clone, Debug)]
enum LocationHint {
    Expr(ExprId),
    Stmt(StmtId),
    None,
}

/// Symbol resolver that walks the HIR and builds symbol table.
pub(super) struct Resolver<'a> {
    /// The HIR being resolved.
    hir: &'a Hir,
    /// AST nodes for error location lookup.
    ast_nodes: &'a AstNodes<'a>,
    /// FFI modules.
    ffi_modules: &'a [ModuleSchema<'a>],
    /// Reserved identifiers that cannot be redefined.
    reserved_idents: HashSet<IdentId>,
    scopes: Scopes,
    symbols: Symbols,
    /// Map from identifier usage locations to their resolved symbols.
    resolved_idents: HashMap<IdentId, SymbolId>,
}

impl<'a> Resolver<'a> {
    /// Perform symbol resolution.
    pub fn resolve(mut self) -> Result<ResolvedAst<'a>, SymbolResolutionError> {
        self.add_reserved_idents();
        self.add_ffi_modules()?;

        // First pass: collect all top-level declarations
        self.collect_declarations()?;

        // Second pass: resolve all identifier references
        self.resolve_references()?;

        Ok(ResolvedHir {
            hir: self.hir,
            ast_nodes: self.ast_nodes,
            identifier_resolutions: self.resolved_idents,
            scopes: self.scopes,
            symbols: self.symbols,
        })
    }

    fn add_reserved_idents(&mut self) {
        // TODO: Need to find or create IdentIds for reserved identifiers
        // For now, we'll check reserved names during symbol creation
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
    /// Find the IdentId for an identifier by searching through HIR idents.
    fn find_or_create_ident_id(&self, ident: &aranya_policy_ast::Identifier) -> IdentId {
        // Search through all identifiers in HIR to find matching one
        for (id, hir_ident) in &self.hir.idents {
            if &hir_ident.ident == ident {
                return id;
            }
        }
        // This shouldn't happen if HIR was properly constructed
        bug!("identifier not found in HIR: {:?}", ident)
    }

    /// Get the source location from a location hint.
    fn get_location_from_hint(&self, hint: LocationHint) -> usize {
        match hint {
            LocationHint::Expr(expr_id) => {
                // Try to find a parent statement that contains this expression
                // For now, we don't have direct location info for expressions
                // TODO: This could be improved by tracking expression locations during lowering
                0
            }
            LocationHint::Stmt(stmt_id) => self
                .ast_nodes
                .stmts
                .get(stmt_id)
                .map(|ast_stmt| ast_stmt.locator)
                .unwrap_or(0),
            LocationHint::None => 0,
        }
    }

    /// Adds a symbol to the global symbol table.
    fn add_global_def(
        &mut self,
        ident: IdentId,
        kind: SymbolKind,
        location: Option<usize>,
    ) -> Result<(), SymbolResolutionError> {
        // Check if this is a reserved identifier
        if let Some(ident_node) = self.hir.idents.get(ident) {
            let name = &ident_node.ident;
            if name.as_str() == "this" || name.as_str() == "envelope" || name.as_str() == "id" {
                let sym = Symbol {
                    ident,
                    kind,
                    scope: ScopeId::GLOBAL,
                    location,
                };
                return Err(SymbolResolutionError::ReservedIdentifier {
                    sym,
                    reserved_for: "language built-ins",
                });
            }
        }

        let sym = Symbol {
            ident,
            kind,
            scope: ScopeId::GLOBAL,
            location,
        };
        let sym_id = self.symbols.insert(sym);
        match self.scopes.insert(ScopeId::GLOBAL, ident, sym_id) {
            Ok(()) => Ok(()),
            Err(InsertError::Duplicate(err)) => Err(SymbolResolutionError::Duplicate(err)),
            Err(InsertError::InvalidScopeId(_)) => bug!("global scope should always be valid"),
        }
    }

    fn collect_declarations(&mut self) -> Result<(), SymbolResolutionError> {
        // Collect global lets
        for (id, global) in &self.hir.global_lets {
            self.collect_global_let(id, global)?;
        }
        // Collect facts
        for (id, fact) in &self.hir.facts {
            self.collect_fact(id, fact)?;
        }
        // Collect actions
        for (id, action) in &self.hir.actions {
            self.collect_action(id, action)?;
        }
        // Collect effects
        for (id, effect) in &self.hir.effects {
            self.collect_effect(id, effect)?;
        }
        // Collect structs
        for (id, struct_def) in &self.hir.structs {
            self.collect_struct(id, struct_def)?;
        }
        // Collect enums
        for (id, enum_def) in &self.hir.enums {
            self.collect_enum(id, enum_def)?;
        }
        // Collect commands
        for (id, cmd) in &self.hir.cmds {
            self.collect_command(id, cmd)?;
        }
        // Collect functions
        for (id, func) in &self.hir.funcs {
            self.collect_function(id, func)?;
        }
        // Collect finish functions
        for (id, func) in &self.hir.finish_funcs {
            self.collect_finish_function(id, func)?;
        }
        Ok(())
    }

    /// Collect a global let statement.
    fn collect_global_let(
        &mut self,
        id: GlobalId,
        global: &GlobalLetDef,
    ) -> Result<(), SymbolResolutionError> {
        // Get the AST node to find the identifier
        let ast_node = self
            .ast_nodes
            .global_lets
            .get(id)
            .assume("global let should have AST node")?;

        // Find the IdentId for this identifier
        let ident_id = self.find_or_create_ident_id(&ast_node.identifier);

        let kind = SymbolKind::GlobalVar(SymGlobalVar {
            vtype: SymType::Unresolved,
            scope: self
                .scopes
                .create_child_scope(ScopeId::GLOBAL)
                .assume("global should always be valid")?,
        });

        self.add_global_def(ident_id, kind, Some(ast_node.locator))
    }

    /// Collect a fact definition.
    fn collect_fact(&mut self, id: FactId, fact: &FactDef) -> Result<(), SymbolResolutionError> {
        // Get the AST node to find the identifier
        let ast_node = self
            .ast_nodes
            .facts
            .get(id)
            .assume("fact should have AST node")?;

        // Find the IdentId for this identifier
        let ident_id = self.find_or_create_ident_id(&ast_node.identifier);

        // Collect keys
        let mut keys = Vec::new();
        for key_id in &fact.keys {
            let key_ast = self
                .ast_nodes
                .fact_keys
                .get(*key_id)
                .assume("fact key should have AST node")?;
            let key_ident_id = self.find_or_create_ident_id(&key_ast.identifier);
            keys.push((key_ident_id, SymType::Unresolved));
        }

        // Collect values
        let mut values = Vec::new();
        for val_id in &fact.vals {
            let val_ast = self
                .ast_nodes
                .fact_vals
                .get(*val_id)
                .assume("fact val should have AST node")?;
            let val_ident_id = self.find_or_create_ident_id(&val_ast.identifier);
            values.push((val_ident_id, SymType::Unresolved));
        }

        let kind = SymbolKind::Fact(SymFact { keys, values });
        self.add_global_def(ident_id, kind, Some(ast_node.locator))
    }

    /// Collect an action definition.
    fn collect_action(
        &mut self,
        id: ActionId,
        action: &ActionDef,
    ) -> Result<(), SymbolResolutionError> {
        // Get the AST node to find the identifier
        let ast_node = self
            .ast_nodes
            .actions
            .get(id)
            .assume("action should have AST node")?;

        // Find the IdentId for this identifier
        let ident_id = self.find_or_create_ident_id(&ast_node.identifier);

        // Collect parameters
        let mut params = Vec::new();
        for arg_id in &action.args {
            let arg_ast = self
                .ast_nodes
                .action_args
                .get(*arg_id)
                .assume("action arg should have AST node")?;
            let arg_ident_id = self.find_or_create_ident_id(&arg_ast.identifier);
            params.push((arg_ident_id, SymType::Unresolved));
        }

        let kind = SymbolKind::Action(SymAction {
            params,
            scope: self
                .scopes
                .create_child_scope(ScopeId::GLOBAL)
                .assume("global should always be valid")?,
        });

        self.add_global_def(ident_id, kind, Some(ast_node.locator))
    }

    /// Collect an effect definition.
    fn collect_effect(
        &mut self,
        id: EffectId,
        effect: &EffectDef,
    ) -> Result<(), SymbolResolutionError> {
        // Get the AST node to find the identifier
        let ast_node = self
            .ast_nodes
            .effects
            .get(id)
            .assume("effect should have AST node")?;

        // Find the IdentId for this identifier
        let ident_id = self.find_or_create_ident_id(&ast_node.identifier);

        let kind = SymbolKind::Effect(SymEffect {
            fields: Status::Unresolved,
        });

        self.add_global_def(ident_id, kind, Some(ast_node.locator))
    }

    /// Collect a struct definition.
    fn collect_struct(
        &mut self,
        id: StructId,
        struct_def: &StructDef,
    ) -> Result<(), SymbolResolutionError> {
        // Get the AST node to find the identifier
        let ast_node = self
            .ast_nodes
            .structs
            .get(id)
            .assume("struct should have AST node")?;

        // Find the IdentId for this identifier
        let ident_id = self.find_or_create_ident_id(&ast_node.identifier);

        let kind = SymbolKind::Struct(SymStruct {
            fields: Status::Unresolved,
        });

        self.add_global_def(ident_id, kind, Some(ast_node.locator))
    }

    /// Collect an enum definition.
    fn collect_enum(
        &mut self,
        id: EnumId,
        enum_def: &EnumDef,
    ) -> Result<(), SymbolResolutionError> {
        // Get the AST node to find the identifier
        let ast_node = self
            .ast_nodes
            .enums
            .get(id)
            .assume("enum should have AST node")?;

        // Find the IdentId for this identifier
        let ident_id = self.find_or_create_ident_id(&ast_node.identifier);

        // Collect variant IdentIds
        let mut variants = Vec::new();
        for variant in &ast_node.variants {
            let variant_ident_id = self.find_or_create_ident_id(variant);
            variants.push(variant_ident_id);
        }

        let kind = SymbolKind::Enum(SymEnum { variants });

        self.add_global_def(ident_id, kind, Some(ast_node.locator))
    }

    /// Collect a command definition.
    fn collect_command(&mut self, id: CmdId, cmd: &CmdDef) -> Result<(), SymbolResolutionError> {
        // Get the AST node to find the identifier
        let ast_node = self
            .ast_nodes
            .cmds
            .get(id)
            .assume("command should have AST node")?;

        // Find the IdentId for this identifier
        let ident_id = self.find_or_create_ident_id(&ast_node.identifier);

        let kind = SymbolKind::Command(SymCommand {
            fields: Status::Unresolved,
            policy: Status::Unresolved,
            finish: Status::Unresolved,
            recall: Status::Unresolved,
        });

        self.add_global_def(ident_id, kind, Some(ast_node.locator))
    }

    /// Collect a function definition.
    fn collect_function(
        &mut self,
        id: FuncId,
        func: &FuncDef,
    ) -> Result<(), SymbolResolutionError> {
        // Get the AST node to find the identifier
        let ast_node = self
            .ast_nodes
            .funcs
            .get(id)
            .assume("function should have AST node")?;

        // Find the IdentId for this identifier
        let ident_id = self.find_or_create_ident_id(&ast_node.identifier);

        // Collect parameters
        let mut params = Vec::new();
        for arg_id in &func.args {
            let arg_ast = self
                .ast_nodes
                .func_args
                .get(*arg_id)
                .assume("func arg should have AST node")?;
            let arg_ident_id = self.find_or_create_ident_id(&arg_ast.identifier);
            params.push((arg_ident_id, SymType::Unresolved));
        }

        let kind = SymbolKind::Function(SymFunction {
            params,
            result: SymType::Unresolved,
            scope: self
                .scopes
                .create_child_scope(ScopeId::GLOBAL)
                .assume("global should always be valid")?,
        });

        self.add_global_def(ident_id, kind, Some(ast_node.locator))
    }

    /// Collect a finish function definition.
    fn collect_finish_function(
        &mut self,
        id: FinishFuncId,
        func: &FinishFuncDef,
    ) -> Result<(), SymbolResolutionError> {
        // Get the AST node to find the identifier
        let ast_node = self
            .ast_nodes
            .finish_funcs
            .get(id)
            .assume("finish function should have AST node")?;

        // Find the IdentId for this identifier
        let ident_id = self.find_or_create_ident_id(&ast_node.identifier);

        // Collect parameters
        let mut params = Vec::new();
        for arg_id in &func.args {
            let arg_ast = self
                .ast_nodes
                .finish_func_args
                .get(*arg_id)
                .assume("finish func arg should have AST node")?;
            let arg_ident_id = self.find_or_create_ident_id(&arg_ast.identifier);
            params.push((arg_ident_id, SymType::Unresolved));
        }

        let kind = SymbolKind::FinishFunction(SymFinishFunction {
            params,
            scope: self
                .scopes
                .create_child_scope(ScopeId::GLOBAL)
                .assume("global should always be valid")?,
        });

        self.add_global_def(ident_id, kind, Some(ast_node.locator))
    }
}

impl<'a> Resolver<'a> {
    fn get_symbol_id(&self, ident: IdentId) -> Result<SymbolId, SymbolResolutionError> {
        let sym_id = self
            .scopes
            .get(ScopeId::GLOBAL, &ident)
            .assume("global scope should always be valid")?
            .ok_or_else(|| {
                SymbolResolutionError::Undefined {
                    ident,
                    location: 0, // TODO: Use actual location from AstNodes
                }
            })?;
        Ok(sym_id)
    }

    fn get_global(&self, ident: IdentId) -> Result<&Symbol, SymbolResolutionError> {
        let sym_id = self.get_symbol_id(ident)?;
        let sym = self
            .symbols
            .get(sym_id)
            .assume("symbol ID should be valid")?;
        Ok(sym)
    }

    fn get_global_mut(&mut self, ident: IdentId) -> Result<&mut Symbol, SymbolResolutionError> {
        let sym_id = self.get_symbol_id(ident)?;
        let sym = self
            .symbols
            .get_mut(sym_id)
            .assume("symbol ID should be valid")?;
        Ok(sym)
    }

    fn get_symbol_scope(&self, ident: IdentId) -> Result<ScopeId, SymbolResolutionError> {
        self.get_global(ident).map(|sym| sym.scope)
    }

    /// Second pass: resolve all identifier references.
    fn resolve_references(&mut self) -> Result<(), SymbolResolutionError> {
        // Resolve global lets
        for (id, global) in &self.hir.global_lets {
            self.resolve_global_let_references(id, global)?;
        }
        // Resolve actions
        for (id, action) in &self.hir.actions {
            self.resolve_action_references(id, action)?;
        }
        // Resolve functions
        for (id, func) in &self.hir.funcs {
            self.resolve_function_references(id, func)?;
        }
        // Resolve finish functions
        for (id, func) in &self.hir.finish_funcs {
            self.resolve_finish_function_references(id, func)?;
        }
        Ok(())
    }

    /// Resolve references within a global let statement.
    fn resolve_global_let_references(
        &mut self,
        id: GlobalId,
        global: &GlobalLetDef,
    ) -> Result<(), SymbolResolutionError> {
        // Get the AST node to find the identifier
        let ast_node = self
            .ast_nodes
            .global_lets
            .get(id)
            .assume("global let should have AST node")?;

        // Find the IdentId for this global let
        let ident_id = self.find_or_create_ident_id(&ast_node.identifier);

        // Get the scope for this global let
        let scope = self.get_symbol_scope(ident_id)?;

        // Resolve the expression
        self.resolve_expr(scope, global.expr)
    }

    /// Resolve references within an action.
    fn resolve_action_references(
        &mut self,
        id: ActionId,
        action: &ActionDef,
    ) -> Result<(), SymbolResolutionError> {
        // Get the AST node to find the identifier
        let ast_node = self
            .ast_nodes
            .actions
            .get(id)
            .assume("action should have AST node")?;

        // Find the IdentId for this action
        let ident_id = self.find_or_create_ident_id(&ast_node.identifier);

        // Get the scope for this action
        let scope = self.get_symbol_scope(ident_id)?;

        // Add parameters to local scope
        for arg_id in &action.args {
            let arg_ast = self
                .ast_nodes
                .action_args
                .get(*arg_id)
                .assume("action arg should have AST node")?;
            let arg_ident_id = self.find_or_create_ident_id(&arg_ast.identifier);
            self.add_parameter(scope, arg_ident_id, ast_node.locator)?;
        }

        // Resolve action body
        let block = self
            .hir
            .blocks
            .get(action.block)
            .assume("action block should exist")?;
        for stmt_id in &block.stmts {
            self.resolve_statement(scope, *stmt_id)?;
        }

        Ok(())
    }

    /// Resolve references within a function.
    fn resolve_function_references(
        &mut self,
        id: FuncId,
        func: &FuncDef,
    ) -> Result<(), SymbolResolutionError> {
        // Get the AST node to find the identifier
        let ast_node = self
            .ast_nodes
            .funcs
            .get(id)
            .assume("function should have AST node")?;

        // Find the IdentId for this function
        let ident_id = self.find_or_create_ident_id(&ast_node.identifier);

        // Get the scope for this function
        let scope = self.get_symbol_scope(ident_id)?;

        // Add parameters to local scope
        for arg_id in &func.args {
            let arg_ast = self
                .ast_nodes
                .func_args
                .get(*arg_id)
                .assume("func arg should have AST node")?;
            let arg_ident_id = self.find_or_create_ident_id(&arg_ast.identifier);
            self.add_parameter(scope, arg_ident_id, ast_node.locator)?;
        }

        // Resolve return type
        self.resolve_type_reference(func.result)?;

        // Resolve function body
        for stmt_id in &func.stmts {
            self.resolve_statement(scope, *stmt_id)?;
        }

        Ok(())
    }

    /// Resolve references within a finish function.
    fn resolve_finish_function_references(
        &mut self,
        id: FinishFuncId,
        func: &FinishFuncDef,
    ) -> Result<(), SymbolResolutionError> {
        // Get the AST node to find the identifier
        let ast_node = self
            .ast_nodes
            .finish_funcs
            .get(id)
            .assume("finish function should have AST node")?;

        // Find the IdentId for this finish function
        let ident_id = self.find_or_create_ident_id(&ast_node.identifier);

        // Get the scope for this finish function
        let scope = self.get_symbol_scope(ident_id)?;

        // Add parameters to local scope
        for arg_id in &func.args {
            let arg_ast = self
                .ast_nodes
                .finish_func_args
                .get(*arg_id)
                .assume("finish func arg should have AST node")?;
            let arg_ident_id = self.find_or_create_ident_id(&arg_ast.identifier);
            self.add_parameter(scope, arg_ident_id, ast_node.locator)?;
        }

        // Resolve function body
        for stmt_id in &func.stmts {
            self.resolve_statement(scope, *stmt_id)?;
        }

        Ok(())
    }

    /// Add a parameter to the current scope.
    fn add_parameter(
        &mut self,
        scope: ScopeId,
        param_ident: IdentId,
        location: usize,
    ) -> Result<(), SymbolResolutionError> {
        // Create a local variable symbol for the parameter
        let sym = Symbol {
            ident: param_ident,
            kind: SymbolKind::LocalVar(SymLocalVar {
                vtype: SymType::Unresolved,
                scope,
            }),
            scope,
            location: Some(location),
        };

        let sym_id = self.symbols.insert(sym);

        // Add to scope
        match self.scopes.insert(scope, param_ident, sym_id) {
            Ok(()) => Ok(()),
            Err(InsertError::Duplicate(err)) => {
                // TODO: Better error handling for duplicate parameters
                Err(SymbolResolutionError::Duplicate(err))
            }
            Err(InsertError::InvalidScopeId(_)) => {
                bug!("parameter scope should be valid")
            }
        }
    }

    /// Resolve references in a statement.
    fn resolve_statement(
        &mut self,
        scope: ScopeId,
        stmt_id: StmtId,
    ) -> Result<(), SymbolResolutionError> {
        let stmt = self
            .hir
            .stmts
            .get(stmt_id)
            .assume("statement should exist in HIR")?;
        match &stmt.kind {
            StmtKind::Let(v) => {
                // Resolve the value expression first
                self.resolve_expr(scope, v.expr)?;

                // Add to local scope
                let sym = Symbol {
                    ident: v.ident,
                    kind: SymbolKind::LocalVar(SymLocalVar {
                        vtype: SymType::Unresolved,
                        scope,
                    }),
                    scope,
                    location: self.ast_nodes.stmts.get(stmt_id).map(|ast| ast.locator),
                };

                let sym_id = self.symbols.insert(sym);
                match self.scopes.insert(scope, v.ident, sym_id) {
                    Ok(()) => {}
                    Err(InsertError::Duplicate(_)) => {
                        // TODO: Handle shadowing
                    }
                    Err(InsertError::InvalidScopeId(_)) => {
                        bug!("statement scope should be valid")
                    }
                }
            }
            StmtKind::Check(v) => {
                self.resolve_expr(scope, v.expr)?;
            }
            StmtKind::Match(v) => {
                self.resolve_expr(scope, v.expr)?;
                for arm in &v.arms {
                    let arm_scope = self
                        .scopes
                        .create_child_scope(scope)
                        .assume("statement scope should always be valid")?;
                    // TODO: Handle pattern bindings in match arms
                    for stmt in &arm.stmts {
                        self.resolve_statement(arm_scope, *stmt)?;
                    }
                }
            }
            StmtKind::If(v) => {
                // Resolve all branch conditions and statements
                for branch in &v.branches {
                    self.resolve_expr(scope, branch.expr)?;

                    let branch_scope = self
                        .scopes
                        .create_child_scope(scope)
                        .assume("statement scope should always be valid")?;
                    for stmt in &branch.stmts {
                        self.resolve_statement(branch_scope, *stmt)?;
                    }
                }

                // Resolve else branch
                if let Some(else_block) = v.else_block {
                    let else_scope = self
                        .scopes
                        .create_child_scope(scope)
                        .assume("statement scope should always be valid")?;
                    let block = self
                        .hir
                        .blocks
                        .get(else_block)
                        .assume("else block should exist")?;
                    for stmt in &block.stmts {
                        self.resolve_statement(else_scope, *stmt)?;
                    }
                }
            }
            StmtKind::Finish(block_id) => {
                let finish_scope = self
                    .scopes
                    .create_child_scope(scope)
                    .assume("statement scope should always be valid")?;
                let block = self
                    .hir
                    .blocks
                    .get(*block_id)
                    .assume("finish block should exist")?;
                for stmt in &block.stmts {
                    self.resolve_statement(finish_scope, *stmt)?;
                }
            }
            StmtKind::Map(v) => {
                // Resolve fact literal
                self.resolve_fact_literal(scope, &v.fact, LocationHint::Stmt(stmt_id))?;

                // Create scope for map body with the binding
                let map_scope = self
                    .scopes
                    .create_child_scope(scope)
                    .assume("statement scope should always be valid")?;

                // Add the map binding to scope
                let sym = Symbol {
                    ident: v.ident,
                    kind: SymbolKind::LocalVar(SymLocalVar {
                        vtype: SymType::Unresolved,
                        scope: map_scope,
                    }),
                    scope: map_scope,
                    location: self.ast_nodes.stmts.get(stmt_id).map(|ast| ast.locator),
                };
                let sym_id = self.symbols.insert(sym);
                self.scopes
                    .insert(map_scope, v.ident, sym_id)
                    .assume("map scope should be valid")?;

                for stmt in &v.stmts {
                    self.resolve_statement(map_scope, *stmt)?;
                }
            }
            StmtKind::Return(v) => {
                self.resolve_expr(scope, v.expr)?;
            }
            StmtKind::ActionCall(v) => {
                self.resolve_ident_ref(scope, v.ident, LocationHint::Stmt(stmt_id))?;
                for arg in &v.args {
                    self.resolve_expr(scope, *arg)?;
                }
            }
            StmtKind::Publish(v) => {
                self.resolve_expr(scope, v.exor)?;
            }
            StmtKind::Delete(v) => {
                self.resolve_fact_literal(scope, &v.fact, LocationHint::Stmt(stmt_id))?;
            }
            StmtKind::Create(v) => {
                self.resolve_fact_literal(scope, &v.fact, LocationHint::Stmt(stmt_id))?;
            }
            StmtKind::Update(v) => {
                self.resolve_fact_literal(scope, &v.fact, LocationHint::Stmt(stmt_id))?;
                // Resolve expressions in the update fields
                for (_, field) in &v.to {
                    if let FactField::Expr(expr) = field {
                        self.resolve_expr(scope, *expr)?;
                    }
                }
            }
            StmtKind::Emit(v) => {
                self.resolve_expr(scope, v.expr)?;
            }
            StmtKind::FunctionCall(v) => {
                self.resolve_ident_ref(scope, v.ident, LocationHint::Stmt(stmt_id))?;
                for arg in &v.args {
                    self.resolve_expr(scope, *arg)?;
                }
            }
            StmtKind::DebugAssert(v) => {
                self.resolve_expr(scope, v.expr)?;
            }
        }
        Ok(())
    }

    /// Resolve references in an expression.
    fn resolve_expr(
        &mut self,
        scope: ScopeId,
        expr_id: ExprId,
    ) -> Result<(), SymbolResolutionError> {
        let expr = self
            .hir
            .exprs
            .get(expr_id)
            .assume("expression should exist in HIR")?;
        match &expr.kind {
            // Literals do not have any references to resolve.
            ExprKind::Int | ExprKind::String | ExprKind::Bool => {}
            ExprKind::Optional(v) => {
                if let Some(expr) = v {
                    self.resolve_expr(scope, *expr)?;
                }
            }
            ExprKind::NamedStruct(v) => {
                self.resolve_ident_ref(scope, v.ident, LocationHint::Expr(expr_id))?;
                for (_, expr) in &v.fields {
                    self.resolve_expr(scope, *expr)?;
                }
            }
            ExprKind::InternalFunction(func) => match func {
                InternalFunction::Query(fact) | InternalFunction::Exists(fact) => {
                    self.resolve_fact_literal(scope, fact, LocationHint::Expr(expr_id))?;
                }
                InternalFunction::FactCount(_, _, fact) => {
                    self.resolve_fact_literal(scope, fact, LocationHint::Expr(expr_id))?;
                }
                InternalFunction::If(cond, then_expr, else_expr) => {
                    self.resolve_expr(scope, *cond)?;
                    self.resolve_expr(scope, *then_expr)?;
                    self.resolve_expr(scope, *else_expr)?;
                }
                InternalFunction::Serialize(expr) | InternalFunction::Deserialize(expr) => {
                    self.resolve_expr(scope, *expr)?;
                }
            },
            ExprKind::FunctionCall(v) => {
                self.resolve_ident_ref(scope, v.ident, LocationHint::Expr(expr_id))?;
                for arg in &v.args {
                    self.resolve_expr(scope, *arg)?;
                }
            }
            ExprKind::ForeignFunctionCall(v) => {
                // TODO: Resolve FFI module and function
                self.resolve_ident_ref(scope, v.module, LocationHint::Expr(expr_id))?;
                for arg in &v.args {
                    self.resolve_expr(scope, *arg)?;
                }
            }
            ExprKind::Identifier(ident) => {
                self.resolve_ident_ref(scope, *ident, LocationHint::Expr(expr_id))?;
            }
            ExprKind::EnumReference(v) => {
                self.resolve_ident_ref(scope, v.ident, LocationHint::Expr(expr_id))?;
            }
            ExprKind::Dot(expr, _field) => {
                self.resolve_expr(scope, *expr)?;
                // Field access is resolved during type checking
            }
            ExprKind::Add(left, right)
            | ExprKind::Sub(left, right)
            | ExprKind::And(left, right)
            | ExprKind::Or(left, right)
            | ExprKind::Equal(left, right)
            | ExprKind::NotEqual(left, right)
            | ExprKind::GreaterThan(left, right)
            | ExprKind::LessThan(left, right)
            | ExprKind::GreaterThanOrEqual(left, right)
            | ExprKind::LessThanOrEqual(left, right) => {
                self.resolve_expr(scope, *left)?;
                self.resolve_expr(scope, *right)?;
            }
            ExprKind::Negative(expr)
            | ExprKind::Not(expr)
            | ExprKind::Unwrap(expr)
            | ExprKind::CheckUnwrap(expr) => {
                self.resolve_expr(scope, *expr)?;
            }
            ExprKind::Is(expr, _) => {
                self.resolve_expr(scope, *expr)?;
            }
            ExprKind::Block(block_id, expr) => {
                let block = self
                    .hir
                    .blocks
                    .get(*block_id)
                    .assume("block should exist in HIR")?;
                let block_scope = self
                    .scopes
                    .create_child_scope(scope)
                    .assume("block scope should always be valid")?;
                for stmt in &block.stmts {
                    self.resolve_statement(block_scope, *stmt)?;
                }
                self.resolve_expr(block_scope, *expr)?;
            }
            ExprKind::Substruct(expr, struct_ident) => {
                self.resolve_expr(scope, *expr)?;
                self.resolve_ident_ref(scope, *struct_ident, LocationHint::Expr(expr_id))?;
            }
            ExprKind::Match(expr) => {
                self.resolve_expr(scope, *expr)?;
                // Match arms are handled in statement resolution
            }
        }
        Ok(())
    }

    /// Resolve references in a fact literal.
    fn resolve_fact_literal(
        &mut self,
        scope: ScopeId,
        fact: &FactLiteral,
        location_hint: LocationHint,
    ) -> Result<(), SymbolResolutionError> {
        // Resolve the fact identifier
        self.resolve_ident_ref(scope, fact.ident, location_hint)?;

        // Resolve key fields
        for (_, field) in &fact.keys {
            if let FactField::Expr(expr) = field {
                self.resolve_expr(scope, *expr)?;
            }
        }

        // Resolve value fields
        for (_, field) in &fact.vals {
            if let FactField::Expr(expr) = field {
                self.resolve_expr(scope, *expr)?;
            }
        }

        Ok(())
    }

    /// Resolve an identifier reference.
    fn resolve_ident_ref(
        &mut self,
        scope: ScopeId,
        ident: IdentId,
        location_hint: LocationHint,
    ) -> Result<(), SymbolResolutionError> {
        let sym_id = self
            .scopes
            .get(scope, &ident)
            .assume("scope should always be valid")?
            .ok_or_else(|| {
                let location = self.get_location_from_hint(location_hint);
                SymbolResolutionError::Undefined { ident, location }
            })?;
        self.resolved_idents.insert(ident, sym_id);
        Ok(())
    }

    /// Resolve type references within a type.
    fn resolve_type_reference(&mut self, vtype_id: VTypeId) -> Result<(), SymbolResolutionError> {
        let vtype = self
            .hir
            .types
            .get(vtype_id)
            .assume("type should exist in HIR")?;

        match &vtype.kind {
            VTypeKind::Struct(name) => {
                // For now, we'll use a default scope - types are typically resolved in global scope
                self.resolve_ident_ref(ScopeId::GLOBAL, *name, LocationHint::None)?;
            }
            VTypeKind::Enum(name) => {
                self.resolve_ident_ref(ScopeId::GLOBAL, *name, LocationHint::None)?;
            }
            VTypeKind::Optional(inner_type) => {
                self.resolve_type_reference(*inner_type)?;
            }
            // Built-in types don't need resolution
            VTypeKind::Int
            | VTypeKind::Bool
            | VTypeKind::String
            | VTypeKind::Id
            | VTypeKind::Bytes => {}
        }
        Ok(())
    }
}
