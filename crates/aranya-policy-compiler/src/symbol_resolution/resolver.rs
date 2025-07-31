//! Main symbol resolver implementation.

use std::collections::{HashMap, HashSet};

use aranya_policy_ast::{ident, Identifier};
use buggy::{bug, BugExt};

use crate::{
    hir::{
        ActionDef, ActionId, AstNodes, BlockId, CmdDef, CmdId, EffectDef, EffectField,
        EffectFieldKind, EffectId, EnumDef, EnumId, ExprId, ExprKind, FactDef, FactField, FactId,
        FactLiteral, FfiModuleDef, FinishFuncDef, FinishFuncId, FuncDef, FuncId, GlobalId,
        GlobalLetDef, Hir, IdentId, Intrinsic, MatchArm, MatchPattern, Span, StmtId, StmtKind,
        StructDef, StructFieldKind, StructId, VType, VTypeId, VTypeKind,
    },
    symbol_resolution::{
        error::SymbolResolutionError,
        scope::{InsertError, ScopeId, Scopes},
        symbols::{
            FinishBlock, PolicyBlock, RecallBlock, SymAction, SymCmd, SymEffect, SymEnum, SymFact,
            SymFfiModule, SymFinishFunc, SymFunc, SymGlobalVar, SymLocalVar, SymStruct, Symbol,
            SymbolId, SymbolKind, Symbols,
        },
        ResolvedHir,
    },
};

type Result<T, E = SymbolResolutionError> = std::result::Result<T, E>;

/// Walks [`Hir`] and builds the symbol table.
// TODO(eric): use `Visitor` instead of manually walking.
#[derive(Clone, Debug)]
pub(super) struct Resolver<'hir> {
    /// The HIR being resolved.
    hir: &'hir Hir,
    /// Identifiers that cannot be redefined.
    reserved_idents: HashSet<Identifier>,
    scopes: Scopes,
    symbols: Symbols,
    resolutions: HashMap<IdentId, SymbolId>,
}

impl<'hir> Resolver<'hir> {
    /// Create a new resolver.
    pub fn resolve(hir: &'hir Hir) -> Result<ResolvedHir<'hir>> {
        let mut v = Self {
            hir,
            reserved_idents: HashSet::new(),
            scopes: Scopes::new(),
            symbols: Symbols::new(),
            resolutions: HashMap::new(),
        };

        v.add_reserved_idents();

        // First pass: collect all top-level declarations.
        v.collect_defs()?;

        // Second pass: resolve all identifier references.
        v.resolve_refs()?;

        for ident in v.hir.idents.keys() {
            if !v.resolutions.contains_key(&ident) {
                // We goofed up somewhere!
                bug!("missed identifier")
            }
        }

        Ok(ResolvedHir {
            hir: v.hir,
            resolutions: v.resolutions,
            scopes: v.scopes,
            symbols: v.symbols,
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

    fn create_child_scope(&mut self, scope: ScopeId) -> Result<ScopeId> {
        let child = self
            .scopes
            .create_child_scope(scope)
            .assume("scope should always be valid")?;
        Ok(child)
    }

    /// Adds a symbol to the global symbol table.
    // TODO(eric): make this generic over Into<SymKind>
    fn add_global_def(
        &mut self,
        ident: IdentId,
        kind: SymbolKind,
        span: Option<Span>,
    ) -> Result<()> {
        self.add_symbol(ScopeId::GLOBAL, ident, kind, span)
    }

    fn add_symbol(
        &mut self,
        scope: ScopeId,
        ident: IdentId,
        kind: SymbolKind,
        span: Option<Span>,
    ) -> Result<()> {
        self.check_reserved(ident, None)?;

        let sym = Symbol {
            ident,
            kind,
            scope,
            span,
        };
        let sym_id = self.symbols.insert(sym);
        match self.scopes.insert(scope, ident, sym_id) {
            Ok(()) => Ok(()),
            Err(InsertError::Duplicate(err)) => Err(SymbolResolutionError::Duplicate(err)),
            Err(InsertError::InvalidScopeId(_)) => bug!("scope should always be valid"),
        }
    }

    fn add_local_var(&mut self, scope: ScopeId, ident: IdentId, span: Span) -> Result<()> {
        let kind = SymbolKind::LocalVar(SymLocalVar { scope });
        self.add_symbol(scope, ident, kind, Some(span))
    }

    fn collect_defs(&mut self) -> Result<()> {
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
            self.collect_cmd(cmd)?;
        }
        for func in self.hir.funcs.values() {
            self.collect_func(func)?;
        }
        for func in self.hir.finish_funcs.values() {
            self.collect_finish_function(func)?;
        }
        for _def in self.hir.ffi_modules.values() {
            // TODO
        }
        Ok(())
    }

    /// Collect a global let statement.
    fn collect_global_let(&mut self, global: &GlobalLetDef) -> Result<()> {
        let kind = SymbolKind::GlobalVar(SymGlobalVar {
            scope: self.create_child_scope(ScopeId::GLOBAL)?,
        });
        self.add_global_def(global.ident, kind, Some(global.span))
    }

    /// Collect a fact definition.
    fn collect_fact(&mut self, fact: &FactDef) -> Result<()> {
        let kind = SymbolKind::Fact(SymFact {});
        self.add_global_def(fact.ident, kind, Some(fact.span))
    }

    /// Collect an action definition.
    fn collect_action(&mut self, action: &ActionDef) -> Result<()> {
        let kind = SymbolKind::Action(SymAction {
            scope: self.create_child_scope(ScopeId::GLOBAL)?,
        });
        self.add_global_def(action.ident, kind, Some(action.span))
    }

    /// Collect an effect definition.
    fn collect_effect(&mut self, effect: &EffectDef) -> Result<()> {
        let kind = SymbolKind::Effect(SymEffect {});
        self.add_global_def(effect.ident, kind, Some(effect.span))
    }

    /// Collect a struct definition.
    fn collect_struct(&mut self, struct_def: &StructDef) -> Result<()> {
        let kind = SymbolKind::Struct(SymStruct {});
        self.add_global_def(struct_def.ident, kind, Some(struct_def.span))
    }

    /// Collect an enum definition.
    fn collect_enum(&mut self, enum_def: &EnumDef) -> Result<()> {
        let kind = SymbolKind::Enum(SymEnum {});
        self.add_global_def(enum_def.ident, kind, Some(enum_def.span))
    }

    /// Collect a command definition.
    fn collect_cmd(&mut self, cmd: &CmdDef) -> Result<()> {
        let policy_scope = self.create_child_scope(ScopeId::GLOBAL)?;
        let policy = PolicyBlock {
            scope: policy_scope,
            finish: FinishBlock {
                scope: self.create_child_scope(policy_scope)?,
            },
        };

        let recall_scope = self.create_child_scope(ScopeId::GLOBAL)?;
        let recall = RecallBlock {
            scope: recall_scope,
            finish: FinishBlock {
                scope: self.create_child_scope(recall_scope)?,
            },
        };

        let kind = SymbolKind::Cmd(SymCmd { policy, recall });
        self.add_global_def(cmd.ident, kind, Some(cmd.span))
    }

    /// Collect a function definition.
    fn collect_func(&mut self, func: &FuncDef) -> Result<()> {
        let kind = SymbolKind::Func(SymFunc {
            scope: self.create_child_scope(ScopeId::GLOBAL)?,
        });
        self.add_global_def(func.ident, kind, Some(func.span))
    }

    /// Collect a finish function definition.
    fn collect_finish_function(&mut self, func: &FinishFuncDef) -> Result<()> {
        let kind = SymbolKind::FinishFunc(SymFinishFunc {
            scope: self.create_child_scope(ScopeId::GLOBAL)?,
        });
        self.add_global_def(func.ident, kind, Some(func.span))
    }

    /// Collects an FFI module.
    fn collect_ffi_module(&mut self, def: &FfiModuleDef) -> Result<()> {
        let scope = self.create_child_scope(ScopeId::GLOBAL)?;
        let kind = SymbolKind::FfiModule(SymFfiModule { scope });
        self.add_global_def(def.ident, kind, Some(def.span))?;

        // FFI modules are self-contained and cannot reference
        // anything in the policy file, so resolve everything
        // now.
        for &id in &def.functions {
            let f = &self.hir.ffi_funcs[id];
            let kind = SymbolKind::Func(SymFunc {
                scope: self.create_child_scope(scope)?,
            });
            self.add_symbol(scope, f.ident, kind, Some(f.span))?;
        }

        Ok(())
    }
}

impl Resolver<'_> {
    fn get_symbol(&self, id: SymbolId) -> Result<&Symbol> {
        let sym = self.symbols.get(id).assume("symbol ID should be valid")?;
        Ok(sym)
    }

    fn get_symbol_id(&self, ident: IdentId) -> Result<SymbolId> {
        let sym_id = self
            .scopes
            .get(ScopeId::GLOBAL, ident)
            .assume("global scope should always be valid")?
            .ok_or(SymbolResolutionError::Undefined {
                ident,
                // TODO: Use actual span from HIR nodes
                span: Span::dummy(),
            })?;
        Ok(sym_id)
    }

    /// Retrieves a globa symbol.
    fn get_global(&self, ident: IdentId) -> Result<&Symbol> {
        let sym_id = self.get_symbol_id(ident)?;
        assert_eq!(sym_id, self.resolutions[&ident]);
        let sym = self
            .symbols
            .get(sym_id)
            .assume("symbol ID should be valid")?;
        Ok(sym)
    }

    fn get_global_mut(&mut self, ident: IdentId) -> Result<&mut Symbol> {
        let sym_id = self.get_symbol_id(ident)?;
        let sym = self
            .symbols
            .get_mut(sym_id)
            .assume("symbol ID should be valid")?;
        Ok(sym)
    }

    fn get_symbol_scope(&self, ident: IdentId) -> Result<ScopeId> {
        self.get_global(ident).map(|sym| sym.scope)
    }

    fn lookup_sym2(&self, ident: IdentId) -> Result<&Symbol> {
        let sym_id = self.resolutions[&ident];
        let sym = self
            .symbols
            .get(sym_id)
            .assume("symbol should always be valid")?;
        Ok(sym)
    }

    /// Second pass: resolve all identifier references.
    fn resolve_refs(&mut self) -> Result<()> {
        for def in self.hir.actions.values() {
            self.resolve_action(def)?;
        }
        for def in self.hir.funcs.values() {
            self.resolve_func(def)?;
        }
        for def in self.hir.finish_funcs.values() {
            self.resolve_finish_func(def)?;
        }
        for def in self.hir.global_lets.values() {
            self.resolve_global_let(def)?;
        }
        for def in self.hir.facts.values() {
            self.resolve_fact_def(def)?;
        }
        for def in self.hir.effects.values() {
            self.resolve_effect_def(def)?;
        }
        for def in self.hir.structs.values() {
            self.resolve_struct_def(def)?;
        }
        for def in self.hir.enums.values() {
            self.resolve_enum_def(def)?;
        }
        // TODO(eric): resolve commands
        // TODO(eric): resolve FFI stuff
        Ok(())
    }

    /// Resolves an identifier to a symbol and returns the
    /// symbol's ID.
    fn resolve_ident(&mut self, scope: ScopeId, ident: IdentId) -> Result<SymbolId> {
        // TODO(eric): All identifier usages are unique, so
        // return an error if we've already resolved this ident.
        let sym_id = self
            .scopes
            .get(scope, ident)
            .assume("scope should always be valid")?
            .ok_or_else(|| SymbolResolutionError::Undefined {
                ident,
                span: Span::dummy(),
            })?;
        self.resolutions.insert(ident, sym_id);
        Ok(sym_id)
    }

    /// Resolves a type.
    fn resolve_vtype(&mut self, scope: ScopeId, vtype: VTypeId) -> Result<()> {
        let vtype = &self.hir.types[vtype];
        match &vtype.kind {
            VTypeKind::String
            | VTypeKind::Bytes
            | VTypeKind::Int
            | VTypeKind::Bool
            | VTypeKind::Id => {}
            VTypeKind::Struct(ident) | VTypeKind::Enum(ident) => {
                self.resolve_ident(scope, *ident)?;
            }
            VTypeKind::Optional(id) => {
                self.resolve_vtype(scope, *id)?;
            }
        }
        Ok(())
    }

    /// Resolve references within an action, including in its
    /// signature.
    fn resolve_action(&mut self, def: &ActionDef) -> Result<()> {
        let &Symbol {
            kind: SymbolKind::Action(SymAction { scope }),
            ..
        } = self.get_global(def.ident)?
        else {
            bug!("symbol should be an action");
        };

        // Add the action's parameters to its scope.
        for &id in &def.args {
            let arg = &self.hir.action_args[id];
            self.resolve_vtype(scope, arg.ty)?;
            self.add_local_var(scope, arg.ident, def.span)?;
        }
        self.resolve_block(scope, def.block)?;

        Ok(())
    }

    /// Resolve references within a function, including in its
    /// signature.
    fn resolve_func(&mut self, def: &FuncDef) -> Result<()> {
        let &Symbol {
            kind: SymbolKind::Func(SymFunc { scope }),
            ..
        } = self.get_global(def.ident)?
        else {
            bug!("symbol should be a function");
        };

        // Add the function's parameters to its scope.
        for &id in &def.args {
            let arg = &self.hir.func_args[id];
            self.resolve_vtype(scope, arg.ty)?;
            self.add_local_var(scope, arg.ident, def.span)?;
        }
        self.resolve_vtype(scope, def.result)?;
        self.resolve_block(scope, def.block)?;

        Ok(())
    }

    /// Resolve references within a finish function, including in
    /// its signature.
    fn resolve_finish_func(&mut self, def: &FinishFuncDef) -> Result<()> {
        let &Symbol {
            kind: SymbolKind::FinishFunc(SymFinishFunc { scope }),
            ..
        } = self.get_global(def.ident)?
        else {
            bug!("symbol should be a finish function");
        };

        // Add the function's parameters to its scope.
        for &id in &def.args {
            let arg = &self.hir.finish_func_args[id];
            self.resolve_vtype(scope, arg.ty)?;
            self.add_local_var(scope, arg.ident, def.span)?;
        }
        self.resolve_block(scope, def.block)?;

        Ok(())
    }

    /// Resolve references within a global let statement.
    fn resolve_global_let(&mut self, def: &GlobalLetDef) -> Result<()> {
        let &Symbol {
            kind: SymbolKind::GlobalVar(SymGlobalVar { scope }),
            ..
        } = self.get_global(def.ident)?
        else {
            bug!("symbol should be a global var");
        };
        self.resolve_expr(scope, def.expr)
    }

    /// Resolve references within a fact definition.
    fn resolve_fact_def(&mut self, def: &FactDef) -> Result<()> {
        let &Symbol {
            kind: SymbolKind::Fact(SymFact { .. }),
            scope,
            ..
        } = self.get_global(def.ident)?
        else {
            bug!("symbol should be a global var");
        };

        for &id in &def.keys {
            let key = &self.hir.fact_keys[id];
            self.resolve_vtype(scope, key.ty)?;
        }
        for &id in &def.vals {
            let key = &self.hir.fact_vals[id];
            self.resolve_vtype(scope, key.ty)?;
        }
        Ok(())
    }

    fn resolve_effect_def(&mut self, def: &EffectDef) -> Result<()> {
        let &Symbol {
            kind: SymbolKind::Effect(SymEffect { .. }),
            scope,
            ..
        } = self.get_global(def.ident)?
        else {
            bug!("symbol should be an effect");
        };

        for &id in &def.items {
            let field = &self.hir.effect_fields[id];
            match &field.kind {
                EffectFieldKind::Field { ident, ty } => {
                    self.resolve_ident(scope, *ident)?;
                    self.resolve_vtype(scope, *ty)?;
                }
                EffectFieldKind::StructRef(ident) => {
                    self.resolve_ident(scope, *ident)?;
                }
            }
        }

        Ok(())
    }

    fn resolve_struct_def(&mut self, def: &StructDef) -> Result<()> {
        let &Symbol {
            kind: SymbolKind::Struct(SymStruct { .. }),
            scope,
            ..
        } = self.get_global(def.ident)?
        else {
            bug!("symbol should be a struct");
        };

        for &id in &def.items {
            let field = &self.hir.struct_fields[id];
            match &field.kind {
                StructFieldKind::Field { ident, ty } => {
                    self.resolve_ident(scope, *ident)?;
                    self.resolve_vtype(scope, *ty)?;
                }
                StructFieldKind::StructRef(ident) => {
                    self.resolve_ident(scope, *ident)?;
                }
            }
        }

        Ok(())
    }

    fn resolve_enum_def(&mut self, def: &EnumDef) -> Result<()> {
        let &Symbol {
            kind: SymbolKind::Enum(SymEnum { .. }),
            ..
        } = self.get_global(def.ident)?
        else {
            bug!("symbol should be an enum");
        };
        // Nothing else to do here!
        Ok(())
    }

    fn resolve_block(&mut self, scope: ScopeId, id: BlockId) -> Result<()> {
        let block = &self.hir.blocks[id];
        for &id in &block.stmts {
            self.resolve_stmt(scope, id)?;
        }
        Ok(())
    }

    fn resolve_stmt(&mut self, scope: ScopeId, id: StmtId) -> Result<()> {
        let stmt = &self.hir.stmts[id];
        match &stmt.kind {
            StmtKind::Let(v) => {
                // Resolve the value expression first so that it
                // cannot refer to the named value. Eg, this
                // should be illegal:
                //
                //    let x = x + 1;
                self.resolve_expr(scope, v.expr)?;
                self.add_local_var(scope, v.ident, stmt.span)?;
            }
            StmtKind::Check(v) => self.resolve_expr(scope, v.expr)?,
            StmtKind::Match(v) => {
                self.resolve_expr(scope, v.expr)?;
                for arm in &v.arms {
                    match &arm.pattern {
                        MatchPattern::Default => {}
                        MatchPattern::Values(exprs) => {
                            for &expr in exprs {
                                self.resolve_expr(scope, expr)?;
                            }
                        }
                    }
                    // Given
                    //
                    // ```policy
                    // match foo {
                    //     bar => { block1 }
                    //     baz => { block2 }
                    // }
                    // ```
                    //
                    // `foo`, `bar`, and `baz` are evaluated in
                    // the same scope. `block1` and `block2` are
                    // evaluated in a child scope.
                    let arm_block_scope = self.create_child_scope(scope)?;
                    self.resolve_block(arm_block_scope, arm.block)?;
                }
            }
            StmtKind::If(v) => {
                for branch in &v.branches {
                    self.resolve_expr(scope, branch.expr)?;

                    let branch_scope = self.create_child_scope(scope)?;
                    self.resolve_block(branch_scope, branch.block)?;
                }
                if let Some(else_block) = v.else_block {
                    let else_scope = self.create_child_scope(scope)?;
                    self.resolve_block(else_scope, else_block)?;
                }
            }
            StmtKind::Finish(block_id) => {
                let finish_scope = self.create_child_scope(scope)?;
                let block = self
                    .hir
                    .blocks
                    .get(*block_id)
                    .assume("finish block should exist")?;
                for stmt in &block.stmts {
                    self.resolve_stmt(finish_scope, *stmt)?;
                }
            }
            StmtKind::Map(v) => {
                self.resolve_fact_literal(scope, &v.fact)?;

                // Create scope for map body with the binding
                let map_scope = self.create_child_scope(scope)?;

                // Check if the map binding is a reserved identifier
                let span = self.hir.stmts.get(id).map(|stmt| stmt.span);
                self.check_reserved(v.ident, span)?;

                // Add the map binding to scope
                let sym = Symbol {
                    ident: v.ident,
                    kind: SymbolKind::LocalVar(SymLocalVar { scope: map_scope }),
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
                    self.resolve_stmt(map_scope, *stmt)?;
                }
            }
            StmtKind::Return(v) => {
                self.resolve_expr(scope, v.expr)?;
            }
            StmtKind::ActionCall(v) => {
                self.resolve_ident(scope, v.ident)?;
                for arg in &v.args {
                    self.resolve_expr(scope, *arg)?;
                }
            }
            StmtKind::Publish(v) => {
                self.resolve_expr(scope, v.exor)?;
            }
            StmtKind::Delete(v) => {
                self.resolve_fact_literal(scope, &v.fact)?;
            }
            StmtKind::Create(v) => {
                self.resolve_fact_literal(scope, &v.fact)?;
            }
            StmtKind::Update(v) => {
                self.resolve_fact_literal(scope, &v.fact)?;
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
                self.resolve_ident(scope, v.ident)?;
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

    fn resolve_expr(&mut self, scope: ScopeId, expr: ExprId) -> Result<()> {
        let expr = &self.hir.exprs[expr];
        match &expr.kind {
            // Literals do not have any references to resolve.
            ExprKind::Int(_) | ExprKind::String(_) | ExprKind::Bool(_) => {}
            ExprKind::Optional(v) => {
                if let Some(expr) = v {
                    self.resolve_expr(scope, *expr)?;
                }
            }
            ExprKind::NamedStruct(v) => {
                self.resolve_ident(scope, v.ident)?;
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
                    self.resolve_fact_literal(scope, fact)?;
                }
                Intrinsic::FactCount(_, _, fact) => {
                    self.resolve_fact_literal(scope, fact)?;
                }
                Intrinsic::Serialize(expr) | Intrinsic::Deserialize(expr) => {
                    self.resolve_expr(scope, *expr)?;
                }
            },
            ExprKind::FunctionCall(v) => {
                self.resolve_ident(scope, v.ident)?;
                for &expr in &v.args {
                    self.resolve_expr(scope, expr)?;
                }
            }
            ExprKind::ForeignFunctionCall(v) => {
                // FFI calls are a little funky. They're written
                // as `module::function(...)`, so we first have
                // to resolve `module` to a module symbol, then
                // look up `function` from there.
                let module_sym_id = self.resolve_ident(scope, v.module)?;
                let module_sym = self
                    .symbols
                    .get(module_sym_id)
                    .assume("symbol should exist")?;
                let SymbolKind::FfiModule(SymFfiModule {
                    scope: module_scope,
                }) = &module_sym.kind
                else {
                    return Err(SymbolResolutionError::Undefined {
                        ident: v.module,
                        span: Span::dummy(),
                    });
                };
                self.resolve_ident(*module_scope, v.ident)?;

                for &expr in &v.args {
                    self.resolve_expr(scope, expr)?;
                }
            }
            ExprKind::Identifier(ident) => {
                self.resolve_ident(scope, *ident)?;
            }
            ExprKind::EnumReference(v) => {
                self.resolve_ident(scope, v.ident)?;
            }
            ExprKind::Dot(expr, _field) => {
                self.resolve_expr(scope, *expr)?;
                // `_field` is "resolved" during type checking.
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
            ExprKind::Is(expr, true | false) => {
                self.resolve_expr(scope, *expr)?;
            }
            ExprKind::Block(block_id, expr) => {
                let block = self
                    .hir
                    .blocks
                    .get(*block_id)
                    .assume("block should exist in HIR")?;
                let block_scope = self.create_child_scope(scope)?;
                for stmt in &block.stmts {
                    self.resolve_stmt(block_scope, *stmt)?;
                }
                self.resolve_expr(block_scope, *expr)?;
            }
            ExprKind::Substruct(expr, ident) => {
                self.resolve_expr(scope, *expr)?;
                self.resolve_ident(scope, *ident)?;
            }
            ExprKind::Match(expr) => {
                self.resolve_expr(scope, expr.scrutinee)?;
                for arm in &expr.arms {
                    match &arm.pattern {
                        MatchPattern::Default => {}
                        MatchPattern::Values(exprs) => {
                            for &expr in exprs {
                                self.resolve_expr(scope, expr)?;
                            }
                        }
                    }
                    // Given
                    //
                    // ```policy
                    // match foo {
                    //     bar => { expr1 }
                    //     baz => { expr2 }
                    // }
                    // ```
                    //
                    // `foo`, `bar`, and `baz` are evaluated in
                    // the same scope. `expr1` and `expr2` are
                    // evaluated in a child scope.
                    let arm_expr_scope = self.create_child_scope(scope)?;
                    self.resolve_expr(arm_expr_scope, arm.expr)?;
                }
            }
        }
        Ok(())
    }

    fn resolve_fact_literal(&mut self, scope: ScopeId, fact: &FactLiteral) -> Result<()> {
        self.resolve_ident(scope, fact.ident)?;
        for (_, field) in &fact.keys {
            if let FactField::Expr(expr) = field {
                self.resolve_expr(scope, *expr)?;
            }
        }
        for (_, field) in &fact.vals {
            if let FactField::Expr(expr) = field {
                self.resolve_expr(scope, *expr)?;
            }
        }
        Ok(())
    }
}
