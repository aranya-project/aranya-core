//! Main symbol resolver implementation.

use std::collections::{HashMap, HashSet};

use aranya_policy_ast::ident;
use aranya_policy_module::ffi::ModuleSchema;
use buggy::{bug, BugExt};

use crate::{
    hir::{
        ActionDef, ActionId, AstNodes, CmdDef, CmdId, EffectDef, EffectId, EnumDef, EnumId, ExprId,
        ExprKind, FactDef, FactField, FactId, FactLiteral, FinishFuncDef, FinishFuncId, FuncDef,
        FuncId, GlobalId, GlobalLetDef, Hir, IdentId, Intrinsic, Span, StmtId, StmtKind, StructDef,
        StructId, VTypeId, VTypeKind,
    },
    symbol_resolution::{
        error::SymbolResolutionError,
        scope::{InsertError, ScopeId, Scopes},
        symbols::{
            Status, SymAction, SymCommand, SymEffect, SymEnum, SymFact, SymFfiModule,
            SymFinishFunction, SymFunction, SymGlobalVar, SymLocalVar, SymStruct, SymType, Symbol,
            SymbolId, SymbolKind, Symbols,
        },
        ResolvedHir,
    },
};

type Result<T, E = SymbolResolutionError> = std::result::Result<T, E>;

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
    /// Reserved identifiers that cannot be redefined.
    reserved_idents: HashSet<aranya_policy_ast::Identifier>,
    scopes: Scopes,
    symbols: Symbols,
    /// Map from identifier usage locations to their resolved symbols.
    resolved_idents: HashMap<IdentId, SymbolId>,
}

impl<'a> Resolver<'a> {
    /// Create a new resolver.
    pub fn new(hir: &'a Hir) -> Result<Self> {
        Ok(Self {
            hir,
            reserved_idents: HashSet::new(),
            scopes: Scopes::new(),
            symbols: Symbols::new(),
            resolved_idents: HashMap::new(),
        })
    }

    /// Perform symbol resolution.
    pub fn resolve(mut self) -> Result<ResolvedHir<'a>> {
        self.add_reserved_idents();
        self.add_ffi_modules()?;

        // First pass: collect all top-level declarations
        self.collect_decls()?;

        // Second pass: resolve all identifier references
        self.resolve_references()?;

        Ok(ResolvedHir {
            hir: self.hir,
            resolutions: self.resolved_idents,
            scopes: self.scopes,
            symbols: self.symbols,
        })
    }

    fn add_reserved_idents(&mut self) {
        self.reserved_idents.insert(ident!("this"));
        self.reserved_idents.insert(ident!("envelope"));
        self.reserved_idents.insert(ident!("id"));
    }

    /// Check if an identifier is reserved.
    fn is_reserved(&self, id: IdentId) -> bool {
        let ident = &self.hir.idents[id].ident;
        self.reserved_idents.contains(ident)
    }

    /// Check if an identifier is reserved and return an error if
    /// it is.
    fn check_reserved(&self, ident: IdentId, span: Option<Span>) -> Result<()> {
        if self.is_reserved(ident) {
            Err(SymbolResolutionError::ReservedIdentifier {
                ident,
                span,
                reserved_for: "language built-ins",
            })
        } else {
            Ok(())
        }
    }

    fn add_ffi_modules(&mut self) -> Result<()> {
        // Process FFI imports from the policy to check they
        // reference valid modules
        for def in self.hir.ffi_imports.values() {
            // Check if the imported module exists in the HIR FFI
            // modules
            let module_found = self
                .hir
                .ffi_modules
                .values()
                .any(|module| module.name == def.module);

            if !module_found {
                // Get the module name for error reporting
                if let Some(_ident) = self.hir.idents.get(def.module) {
                    return Err(SymbolResolutionError::Undefined {
                        ident: def.module,
                        // TODO: Get span from AST node
                        span: Span::dummy(),
                    });
                }
            }
        }

        // Add FFI modules to the symbol table
        for def in self.hir.ffi_modules.values() {
            // Create a scope for the module
            let module_scope = self
                .scopes
                .create_child_scope(ScopeId::GLOBAL)
                .assume("global scope should always be valid")?;

            // Add the module symbol
            let kind = SymbolKind::FfiModule(SymFfiModule {
                scope: module_scope,
            });
            let sym_id = self.symbols.insert(Symbol {
                ident: def.name,
                kind,
                scope: ScopeId::GLOBAL,
                span: None,
            });

            // Register the module in global scope
            match self.scopes.insert(ScopeId::GLOBAL, def.name, sym_id) {
                Ok(()) => {}
                Err(InsertError::Duplicate(err)) => {
                    return Err(SymbolResolutionError::Duplicate(err));
                }
                Err(InsertError::InvalidScopeId(_)) => bug!("global scope should always be valid"),
            }

            // Add FFI functions to the module scope
            for &id in &def.functions {
                if let Some(func) = self.hir.ffi_funcs.get(id) {
                    let func_sym = Symbol {
                        ident: func.name,
                        kind: SymbolKind::Function(SymFunction {
                            // FFI functions params are resolved
                            // later.
                            params: vec![],
                            result: SymType::Unresolved,
                            scope: module_scope,
                        }),
                        scope: module_scope,
                        span: None,
                    };
                    let func_sym_id = self.symbols.insert(func_sym);
                    self.scopes
                        .insert(module_scope, func.name, func_sym_id)
                        .assume("module scope should be valid")?;
                }
            }

            // Add FFI structs to global scope (FFI structs are
            // globally accessible)
            for &id in &def.structs {
                if let Some(ffi_struct) = self.hir.ffi_structs.get(id) {
                    let struct_sym = Symbol {
                        ident: ffi_struct.name,
                        kind: SymbolKind::Struct(SymStruct {
                            fields: Status::Unresolved,
                        }),
                        scope: ScopeId::GLOBAL,
                        span: None,
                    };
                    let struct_sym_id = self.symbols.insert(struct_sym);
                    match self
                        .scopes
                        .insert(ScopeId::GLOBAL, ffi_struct.name, struct_sym_id)
                    {
                        Ok(()) => {}
                        Err(InsertError::Duplicate(err)) => {
                            return Err(SymbolResolutionError::Duplicate(err));
                        }
                        Err(InsertError::InvalidScopeId(_)) => {
                            bug!("global scope should always be valid")
                        }
                    }
                }
            }

            // Add FFI enums to global scope (FFI enums are
            // globally accessible)
            for &id in &def.enums {
                if let Some(ffi_enum) = self.hir.ffi_enums.get(id) {
                    let enum_sym = Symbol {
                        ident: ffi_enum.name,
                        kind: SymbolKind::Enum(SymEnum {
                            variants: ffi_enum.variants.clone(),
                        }),
                        scope: ScopeId::GLOBAL,
                        span: None,
                    };
                    let enum_sym_id = self.symbols.insert(enum_sym);
                    match self
                        .scopes
                        .insert(ScopeId::GLOBAL, ffi_enum.name, enum_sym_id)
                    {
                        Ok(()) => {}
                        Err(InsertError::Duplicate(err)) => {
                            return Err(SymbolResolutionError::Duplicate(err));
                        }
                        Err(InsertError::InvalidScopeId(_)) => {
                            bug!("global scope should always be valid")
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Get the source span from a location hint.
    fn get_span_from_hint(&self, hint: LocationHint) -> Span {
        match hint {
            LocationHint::Expr(expr_id) => {
                // Get span from HIR expression
                self.hir
                    .exprs
                    .get(expr_id)
                    .map(|expr| expr.span)
                    .unwrap_or_else(Span::dummy)
            }
            LocationHint::Stmt(stmt_id) => {
                // Get span from HIR statement
                self.hir
                    .stmts
                    .get(stmt_id)
                    .map(|stmt| stmt.span)
                    .unwrap_or_else(Span::dummy)
            }
            LocationHint::None => Span::dummy(),
        }
    }

    /// Adds a symbol to the global symbol table.
    fn add_global_def(
        &mut self,
        ident: IdentId,
        kind: SymbolKind,
        span: Option<Span>,
    ) -> Result<()> {
        // Check if this is a reserved identifier
        self.check_reserved(ident, span)?;

        let sym = Symbol {
            ident,
            kind,
            scope: ScopeId::GLOBAL,
            span,
        };
        let sym_id = self.symbols.insert(sym);
        match self.scopes.insert(ScopeId::GLOBAL, ident, sym_id) {
            Ok(()) => Ok(()),
            Err(InsertError::Duplicate(err)) => Err(SymbolResolutionError::Duplicate(err)),
            Err(InsertError::InvalidScopeId(_)) => bug!("global scope should always be valid"),
        }
    }

    fn collect_decls(&mut self) -> Result<()> {
        for global in self.hir.global_lets.values() {
            self.collect_global_let(global)?;
        }
        for fact in self.hir.facts.values() {
            self.collect_fact(fact)?;
        }
        for action in self.hir.actions.values() {
            self.collect_action(action)?;
        }
        for effect in self.hir.effects.values() {
            self.collect_effect(effect)?;
        }
        for struct_def in self.hir.structs.values() {
            self.collect_struct(struct_def)?;
        }
        for enum_def in self.hir.enums.values() {
            self.collect_enum(enum_def)?;
        }
        for cmd in self.hir.cmds.values() {
            self.collect_command(cmd)?;
        }
        for func in self.hir.funcs.values() {
            self.collect_function(func)?;
        }
        for func in self.hir.finish_funcs.values() {
            self.collect_finish_function(func)?;
        }
        Ok(())
    }

    /// Collect a global let statement.
    fn collect_global_let(&mut self, global: &GlobalLetDef) -> Result<()> {
        let kind = SymbolKind::GlobalVar(SymGlobalVar {
            vtype: SymType::Unresolved,
            scope: self
                .scopes
                .create_child_scope(ScopeId::GLOBAL)
                .assume("global should always be valid")?,
        });
        self.add_global_def(global.ident, kind, Some(global.span))
    }

    /// Collect a fact definition.
    fn collect_fact(&mut self, fact: &FactDef) -> Result<()> {
        let mut keys = Vec::new();
        for key_id in &fact.keys {
            let key = self
                .hir
                .fact_keys
                .get(*key_id)
                .assume("fact key should exist in HIR")?;
            keys.push((key.ident, SymType::Unresolved));
        }

        let mut values = Vec::new();
        for val_id in &fact.vals {
            let val = self
                .hir
                .fact_vals
                .get(*val_id)
                .assume("fact val should exist in HIR")?;
            values.push((val.ident, SymType::Unresolved));
        }

        let kind = SymbolKind::Fact(SymFact { keys, values });
        self.add_global_def(fact.ident, kind, Some(fact.span))
    }

    /// Collect an action definition.
    fn collect_action(&mut self, action: &ActionDef) -> Result<()> {
        // Collect parameters
        let mut params = Vec::new();
        for arg_id in &action.args {
            let arg = self
                .hir
                .action_args
                .get(*arg_id)
                .assume("action arg should exist in HIR")?;
            params.push((arg.ident, SymType::Unresolved));
        }

        let kind = SymbolKind::Action(SymAction {
            params,
            scope: self
                .scopes
                .create_child_scope(ScopeId::GLOBAL)
                .assume("global should always be valid")?,
        });
        self.add_global_def(action.ident, kind, Some(action.span))
    }

    /// Collect an effect definition.
    fn collect_effect(&mut self, effect: &EffectDef) -> Result<()> {
        let kind = SymbolKind::Effect(SymEffect {
            fields: Status::Unresolved,
        });
        self.add_global_def(effect.ident, kind, Some(effect.span))
    }

    /// Collect a struct definition.
    fn collect_struct(&mut self, struct_def: &StructDef) -> Result<()> {
        let kind = SymbolKind::Struct(SymStruct {
            fields: Status::Unresolved,
        });
        self.add_global_def(struct_def.ident, kind, Some(struct_def.span))
    }

    /// Collect an enum definition.
    fn collect_enum(&mut self, enum_def: &EnumDef) -> Result<()> {
        let kind = SymbolKind::Enum(SymEnum {
            variants: enum_def.variants.clone(),
        });
        self.add_global_def(enum_def.ident, kind, Some(enum_def.span))
    }

    /// Collect a command definition.
    fn collect_command(&mut self, cmd: &CmdDef) -> Result<()> {
        let kind = SymbolKind::Command(SymCommand {
            fields: Status::Unresolved,
            policy: Status::Unresolved,
            finish: Status::Unresolved,
            recall: Status::Unresolved,
        });
        self.add_global_def(cmd.ident, kind, Some(cmd.span))
    }

    /// Collect a function definition.
    fn collect_function(&mut self, func: &FuncDef) -> Result<()> {
        // Collect parameters
        let mut params = Vec::new();
        for arg_id in &func.args {
            let arg = self
                .hir
                .func_args
                .get(*arg_id)
                .assume("func arg should exist in HIR")?;
            params.push((arg.ident, SymType::Unresolved));
        }

        let kind = SymbolKind::Function(SymFunction {
            params,
            result: SymType::Unresolved,
            scope: self
                .scopes
                .create_child_scope(ScopeId::GLOBAL)
                .assume("global should always be valid")?,
        });

        self.add_global_def(func.ident, kind, Some(func.span))
    }

    /// Collect a finish function definition.
    fn collect_finish_function(&mut self, func: &FinishFuncDef) -> Result<()> {
        // Collect parameters
        let mut params = Vec::new();
        for id in &func.args {
            let arg = self
                .hir
                .finish_func_args
                .get(*id)
                .assume("finish func arg should exist in HIR")?;
            params.push((arg.ident, SymType::Unresolved));
        }

        let kind = SymbolKind::FinishFunction(SymFinishFunction {
            params,
            scope: self
                .scopes
                .create_child_scope(ScopeId::GLOBAL)
                .assume("global should always be valid")?,
        });
        self.add_global_def(func.ident, kind, Some(func.span))
    }
}

impl Resolver<'_> {
    fn get_symbol_id(&self, ident: IdentId) -> Result<SymbolId, SymbolResolutionError> {
        let sym_id = self
            .scopes
            .get(ScopeId::GLOBAL, &ident)
            .assume("global scope should always be valid")?
            .ok_or(SymbolResolutionError::Undefined {
                ident,
                span: Span::dummy(), // TODO: Use actual span from HIR nodes
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
    fn resolve_references(&mut self) -> Result<()> {
        for global in self.hir.global_lets.values() {
            self.resolve_global_let_references(global)?;
        }
        for action in self.hir.actions.values() {
            self.resolve_action_references(action)?;
        }
        for func in self.hir.funcs.values() {
            self.resolve_function_references(func)?;
        }
        for func in self.hir.finish_funcs.values() {
            self.resolve_finish_function_references(func)?;
        }
        Ok(())
    }

    /// Resolve references within a global let statement.
    fn resolve_global_let_references(&mut self, global: &GlobalLetDef) -> Result<()> {
        // Get the scope for this global let
        let scope = self.get_symbol_scope(global.ident)?;

        // Resolve the expression
        self.resolve_expr(scope, global.expr)
    }

    /// Resolve references within an action.
    fn resolve_action_references(&mut self, action: &ActionDef) -> Result<()> {
        // Get the scope for this action
        let scope = self.get_symbol_scope(action.ident)?;

        // Add parameters to local scope
        for arg_id in &action.args {
            let arg = self
                .hir
                .action_args
                .get(*arg_id)
                .assume("action arg should exist in HIR")?;
            self.add_parameter(scope, arg.ident, action.span)?;
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
    fn resolve_function_references(&mut self, func: &FuncDef) -> Result<()> {
        // Get the scope for this function
        let scope = self.get_symbol_scope(func.ident)?;

        // Add parameters to local scope
        for arg_id in &func.args {
            let arg = self
                .hir
                .func_args
                .get(*arg_id)
                .assume("func arg should exist in HIR")?;
            self.add_parameter(scope, arg.ident, func.span)?;
        }

        // Resolve return type
        self.resolve_type_ref(func.result)?;

        // Resolve function body
        let block = self
            .hir
            .blocks
            .get(func.block)
            .assume("function block should exist")?;
        for stmt_id in &block.stmts {
            self.resolve_statement(scope, *stmt_id)?;
        }

        Ok(())
    }

    /// Resolve references within a finish function.
    fn resolve_finish_function_references(&mut self, func: &FinishFuncDef) -> Result<()> {
        // Get the scope for this finish function
        let scope = self.get_symbol_scope(func.ident)?;

        // Add parameters to local scope
        for arg_id in &func.args {
            let arg = self
                .hir
                .finish_func_args
                .get(*arg_id)
                .assume("finish func arg should exist in HIR")?;
            self.add_parameter(scope, arg.ident, func.span)?;
        }

        // Resolve function body
        let block = self
            .hir
            .blocks
            .get(func.block)
            .assume("finish function block should exist")?;
        for stmt_id in &block.stmts {
            self.resolve_statement(scope, *stmt_id)?;
        }

        Ok(())
    }

    /// Add a parameter to the current scope.
    fn add_parameter(&mut self, scope: ScopeId, param_ident: IdentId, span: Span) -> Result<()> {
        // Check if this is a reserved identifier
        self.check_reserved(param_ident, Some(span))?;

        // Create a local variable symbol for the parameter
        let sym = Symbol {
            ident: param_ident,
            kind: SymbolKind::LocalVar(SymLocalVar {
                vtype: SymType::Unresolved,
                scope,
            }),
            scope,
            span: Some(span),
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
    fn resolve_statement(&mut self, scope: ScopeId, stmt_id: StmtId) -> Result<()> {
        let stmt = self
            .hir
            .stmts
            .get(stmt_id)
            .assume("statement should exist in HIR")?;
        match &stmt.kind {
            StmtKind::Let(v) => {
                // Resolve the value expression first
                self.resolve_expr(scope, v.expr)?;

                // Check if this is a reserved identifier
                let span = self.hir.stmts.get(stmt_id).map(|stmt| stmt.span);
                self.check_reserved(v.ident, span)?;

                // Add to local scope
                let sym = Symbol {
                    ident: v.ident,
                    kind: SymbolKind::LocalVar(SymLocalVar {
                        vtype: SymType::Unresolved,
                        scope,
                    }),
                    scope,
                    span,
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
                    let block = self
                        .hir
                        .blocks
                        .get(arm.block)
                        .assume("match arm block should exist")?;
                    for stmt in &block.stmts {
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
                    let block = self
                        .hir
                        .blocks
                        .get(branch.block)
                        .assume("if branch block should exist")?;
                    for stmt in &block.stmts {
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

                // Check if the map binding is a reserved identifier
                let span = self.hir.stmts.get(stmt_id).map(|stmt| stmt.span);
                self.check_reserved(v.ident, span)?;

                // Add the map binding to scope
                let sym = Symbol {
                    ident: v.ident,
                    kind: SymbolKind::LocalVar(SymLocalVar {
                        vtype: SymType::Unresolved,
                        scope: map_scope,
                    }),
                    scope: map_scope,
                    span,
                };
                let sym_id = self.symbols.insert(sym);
                self.scopes
                    .insert(map_scope, v.ident, sym_id)
                    .assume("map scope should be valid")?;

                let block = self
                    .hir
                    .blocks
                    .get(v.block)
                    .assume("map block should exist")?;
                for stmt in &block.stmts {
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
    fn resolve_expr(&mut self, scope: ScopeId, expr_id: ExprId) -> Result<()> {
        self.resolve_expr_with_hint(scope, expr_id, LocationHint::Expr(expr_id))
    }

    /// Resolve references in an expression with a location hint.
    fn resolve_expr_with_hint(
        &mut self,
        scope: ScopeId,
        expr_id: ExprId,
        hint: LocationHint,
    ) -> Result<()> {
        let expr = self
            .hir
            .exprs
            .get(expr_id)
            .assume("expression should exist in HIR")?;
        match &expr.kind {
            // Literals do not have any references to resolve.
            ExprKind::Int(_) | ExprKind::String(_) | ExprKind::Bool(_) => {}
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
            ExprKind::Ternary(v) => {
                self.resolve_expr(scope, v.cond)?;
                self.resolve_expr(scope, v.true_expr)?;
                self.resolve_expr(scope, v.false_expr)?;
            }
            ExprKind::Intrinsic(v) => match v {
                Intrinsic::Query(fact) => {
                    self.resolve_fact_literal(scope, fact, LocationHint::Expr(expr_id))?;
                }
                Intrinsic::FactCount(_, _, fact) => {
                    self.resolve_fact_literal(scope, fact, LocationHint::Expr(expr_id))?;
                }
                Intrinsic::Serialize(expr) | Intrinsic::Deserialize(expr) => {
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
                // Resolve FFI module first
                let module_sym_id = self
                    .scopes
                    .get(ScopeId::GLOBAL, &v.module)
                    .assume("global scope should always be valid")?
                    .ok_or_else(|| {
                        let span = self.get_span_from_hint(hint);
                        SymbolResolutionError::Undefined {
                            ident: v.module,
                            span,
                        }
                    })?;

                // Get the module's scope
                let module_sym = self
                    .symbols
                    .get(module_sym_id)
                    .assume("symbol should exist")?;
                let module_scope = match &module_sym.kind {
                    SymbolKind::FfiModule(ffi_module) => ffi_module.scope,
                    _ => {
                        let span = self.get_span_from_hint(hint);
                        return Err(SymbolResolutionError::Undefined {
                            ident: v.module,
                            span,
                        });
                    }
                };

                // Resolve function within module scope
                let func_sym_id = self
                    .scopes
                    .get(module_scope, &v.ident)
                    .assume("module scope should be valid")?
                    .ok_or_else(|| {
                        let span = self.get_span_from_hint(hint);
                        SymbolResolutionError::Undefined {
                            ident: v.ident,
                            span,
                        }
                    })?;

                // Record resolutions
                self.resolved_idents.insert(v.module, module_sym_id);
                self.resolved_idents.insert(v.ident, func_sym_id);

                // Resolve arguments
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
    ) -> Result<()> {
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
    ) -> Result<()> {
        let sym_id = self
            .scopes
            .get(scope, &ident)
            .assume("scope should always be valid")?
            .ok_or_else(|| {
                let span = self.get_span_from_hint(location_hint);
                SymbolResolutionError::Undefined { ident, span }
            })?;
        self.resolved_idents.insert(ident, sym_id);
        Ok(())
    }

    /// Resolve type references within a type.
    fn resolve_type_ref(&mut self, vtype_id: VTypeId) -> Result<()> {
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
                self.resolve_type_ref(*inner_type)?;
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
