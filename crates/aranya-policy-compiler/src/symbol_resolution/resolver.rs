//! Main symbol resolver implementation.

use std::mem;

use aranya_policy_ast::ident;
use buggy::{bug, BugExt};

use crate::{
    hir::{
        visit::{self, Visitor},
        ActionArg, ActionDef, Block, BlockId, CmdDef, EffectDef, EffectFieldKind, EnumDef, ExprId,
        ExprKind, FactDef, FactField, FactLiteral, FfiModuleDef, FinishFuncArg, FinishFuncDef,
        FuncArg, FuncDef, GlobalLetDef, Hir, Ident, IdentId, IdentInterner, IdentRef, Intrinsic,
        MatchPattern, Span, Stmt, StmtId, StmtKind, StructDef, StructFieldKind, VTypeId, VTypeKind,
    },
    symbol_resolution::{
        error::SymbolResolutionError,
        scope::{InsertError, ScopeId},
        symbols::{
            FinishBlock, PolicyBlock, RecallBlock, SymAction, SymCmd, SymEffect, SymEnum, SymFact,
            SymFfiModule, SymFinishFunc, SymFunc, SymGlobalVar, SymLocalVar, SymStruct, Symbol,
            SymbolId, SymbolKind,
        },
        Result, SymbolTable,
    },
};

impl SymbolTable {
    /// Sugar for creating a child scope of `scope`.
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

    /// Adds a symbol created from `ident`, `kind`, and `span` to
    /// `scope`.
    fn add_symbol(
        &mut self,
        scope: ScopeId,
        ident: IdentId,
        kind: SymbolKind,
        span: Option<Span>,
    ) -> Result<()> {
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

    /// Adds a local variable symbol to `scope`.
    fn add_local_var(&mut self, scope: ScopeId, ident: IdentId, span: Span) -> Result<()> {
        let kind = SymbolKind::LocalVar(SymLocalVar { scope });
        self.add_symbol(scope, ident, kind, Some(span))
    }
}

/// Walks [`Hir`] and builds the symbol table.
// TODO(eric): use `Visitor` instead of manually walking.
#[derive(Clone, Debug)]
pub(super) struct Resolver<'hir> {
    /// The HIR being resolved.
    hir: &'hir Hir,
    /// The table being built.
    table: SymbolTable,
    reserved_idents: Vec<IdentRef>,
}

impl<'hir> Resolver<'hir> {
    /// Creates a symbol table from the given HIR.
    pub(super) fn resolve(hir: &'hir Hir, idents: &mut IdentInterner) -> Result<SymbolTable> {
        let reserved_idents = [ident!("this"), ident!("envelope"), ident!("id")]
            .into_iter()
            .map(|ident| idents.intern(ident))
            .collect::<Vec<_>>();

        let mut v = Self {
            hir,
            table: SymbolTable::empty(),
            reserved_idents,
        };

        // First pass: collect all top-level declarations.
        v.collect_defs()?;

        // Second pass: resolve all identifier references.
        v.resolve_refs()?;

        for (ident, _) in &v.hir.idents {
            if !v.table.resolutions.contains_key(&ident) {
                // We goofed up somewhere!
                bug!("missed identifier")
            }
        }

        Ok(v.table)
    }
}

impl<'hir> Resolver<'hir> {
    fn collect_defs(&mut self) -> Result<()> {
        let mut visitor = Collector {
            hir: self.hir,
            table: &mut self.table,
        };
        visitor.visit_all()?;

        // TODO(eric): Add this to Visitor.
        for (_, def) in &self.hir.ffi_modules {
            self.collect_ffi_module(def)?;
        }

        Ok(())
    }

    /// Collects an FFI module.
    fn collect_ffi_module(&mut self, def: &'hir FfiModuleDef) -> Result<()> {
        let scope = self.table.create_child_scope(ScopeId::GLOBAL)?;
        let kind = SymbolKind::FfiModule(SymFfiModule { scope });
        self.table.add_global_def(def.ident, kind, Some(def.span))?;

        // FFI modules are self-contained and cannot reference
        // anything in the policy file, so resolve everything
        // now.
        for &id in &def.functions {
            let f = &self.hir.ffi_funcs[id];
            let kind = SymbolKind::Func(SymFunc {
                scope: self.table.create_child_scope(scope)?,
            });
            self.table.add_symbol(scope, f.ident, kind, Some(f.span))?;
        }

        // TODO: other FFI module items

        Ok(())
    }
}

impl Resolver<'_> {
    fn get_symbol_id(&self, ident: IdentId) -> Result<SymbolId> {
        let sym_id = self
            .table
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
        assert_eq!(sym_id, self.table.resolutions[&ident]);
        let sym = self
            .table
            .symbols
            .get(sym_id)
            .assume("symbol ID should be valid")?;
        Ok(sym)
    }

    /// Second pass: resolve all identifier references.
    fn resolve_refs(&mut self) -> Result<()> {
        let mut visitor = Resolver2 {
            hir: self.hir,
            table: &mut self.table,
            scope: ScopeId::GLOBAL,
            reserved_idents: &self.reserved_idents,
        };
        visitor.visit_all()?;

        // TODO(eric): resolve commands
        // TODO(eric): resolve FFI stuff
        Ok(())
    }
}

#[derive(Debug)]
struct Collector<'a> {
    hir: &'a Hir,
    table: &'a mut SymbolTable,
}

impl<'a: 'hir, 'hir> Visitor<'hir> for Collector<'a> {
    type Result = Result<()>;

    fn hir(&self) -> &'hir Hir {
        self.hir
    }

    fn visit_action(&mut self, def: &'hir ActionDef) -> Self::Result {
        let kind = SymbolKind::Action(SymAction {
            scope: self.table.create_child_scope(ScopeId::GLOBAL)?,
        });
        self.table.add_global_def(def.ident, kind, Some(def.span))
    }

    fn visit_effect_def(&mut self, def: &'hir EffectDef) -> Self::Result {
        let kind = SymbolKind::Effect(SymEffect {});
        self.table.add_global_def(def.ident, kind, Some(def.span))
    }

    fn visit_enum_def(&mut self, def: &'hir EnumDef) -> Self::Result {
        let kind = SymbolKind::Enum(SymEnum {});
        self.table.add_global_def(def.ident, kind, Some(def.span))
    }

    fn visit_fact_def(&mut self, def: &'hir FactDef) -> Self::Result {
        let kind = SymbolKind::Fact(SymFact {});
        self.table.add_global_def(def.ident, kind, Some(def.span))
    }

    fn visit_finish_func_def(&mut self, def: &'hir FinishFuncDef) -> Self::Result {
        let kind = SymbolKind::FinishFunc(SymFinishFunc {
            scope: self.table.create_child_scope(ScopeId::GLOBAL)?,
        });
        self.table.add_global_def(def.ident, kind, Some(def.span))
    }

    fn visit_func_def(&mut self, def: &'hir FuncDef) -> Self::Result {
        let kind = SymbolKind::Func(SymFunc {
            scope: self.table.create_child_scope(ScopeId::GLOBAL)?,
        });
        self.table.add_global_def(def.ident, kind, Some(def.span))
    }

    fn visit_global_def(&mut self, def: &'hir GlobalLetDef) -> Self::Result {
        let kind = SymbolKind::GlobalVar(SymGlobalVar {
            scope: self.table.create_child_scope(ScopeId::GLOBAL)?,
        });
        self.table.add_global_def(def.ident, kind, Some(def.span))
    }

    fn visit_struct_def(&mut self, def: &'hir StructDef) -> Self::Result {
        let kind = SymbolKind::Struct(SymStruct {});
        self.table.add_global_def(def.ident, kind, Some(def.span))
    }
}

#[derive(Debug)]
struct Resolver2<'a> {
    hir: &'a Hir,
    table: &'a mut SymbolTable,
    reserved_idents: &'a [IdentRef],
    scope: ScopeId,
}

impl Resolver2<'_> {
    /// Check if an identifier is reserved and return an error if
    /// it is.
    fn check_reserved(&self, ident: &Ident) -> Result<()> {
        if self.reserved_idents.contains(&ident.ident) {
            Err(SymbolResolutionError::ReservedIdentifier {
                ident: ident.id,
                span: Some(ident.span),
                reserved_for: "language built-ins",
            })
        } else {
            Ok(())
        }
    }

    fn get_symbol_id(&self, ident: IdentId) -> Result<SymbolId> {
        let sym_id = self
            .table
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
        assert_eq!(sym_id, self.table.resolutions[&ident]);
        let sym = self
            .table
            .symbols
            .get(sym_id)
            .assume("symbol ID should be valid")?;
        Ok(sym)
    }

    fn with_scope<F, R>(&mut self, scope: ScopeId, f: F) -> Result<R>
    where
        F: FnOnce(&mut Self) -> Result<R>,
    {
        let prev = mem::replace(&mut self.scope, scope);
        let result = f(self);
        self.scope = prev;
        result
    }

    fn resolve_ident(&mut self, ident: &Ident) -> Result<SymbolId> {
        self.check_reserved(ident)?;

        // TODO(eric): All identifier usages are unique, so
        // return an error if we've already resolved this ident.
        let sym_id = self
            .table
            .scopes
            .get(self.scope, ident.id)
            .assume("scope should always be valid")?
            .ok_or(SymbolResolutionError::Undefined {
                ident: ident.id,
                span: ident.span,
            })?;
        self.table.resolutions.insert(ident.id, sym_id);
        Ok(sym_id)
    }
}

impl<'a: 'hir, 'hir> Visitor<'hir> for Resolver2<'a> {
    type Result = Result<()>;

    fn hir(&self) -> &'hir Hir {
        self.hir
    }

    fn visit_action(&mut self, def: &'hir ActionDef) -> Self::Result {
        let &Symbol {
            kind: SymbolKind::Action(SymAction { scope }),
            ..
        } = self.get_global(def.ident)?
        else {
            bug!("symbol should be an action");
        };
        self.with_scope(scope, |this| visit::walk_action(this, def))
    }

    fn visit_action_arg(&mut self, arg: &'hir ActionArg) -> Self::Result {
        self.table.add_local_var(self.scope, arg.ident, arg.span)
    }

    fn visit_effect_def(&mut self, def: &'hir EffectDef) -> Self::Result {
        let &Symbol {
            kind: SymbolKind::Effect(SymEffect {}),
            ..
        } = self.get_global(def.ident)?
        else {
            bug!("symbol should be an effect");
        };
        self.with_scope(ScopeId::GLOBAL, |this| visit::walk_effect(this, def))
    }

    fn visit_enum_def(&mut self, def: &'hir EnumDef) -> Self::Result {
        let &Symbol {
            kind: SymbolKind::Enum(SymEnum {}),
            ..
        } = self.get_global(def.ident)?
        else {
            bug!("symbol should be an enum");
        };
        self.with_scope(ScopeId::GLOBAL, |this| visit::walk_enum(this, def))
    }

    fn visit_fact_def(&mut self, def: &'hir FactDef) -> Self::Result {
        let &Symbol {
            kind: SymbolKind::Fact(SymFact {}),
            scope,
            ..
        } = self.get_global(def.ident)?
        else {
            bug!("symbol should be a fact");
        };
        self.with_scope(scope, |this| visit::walk_fact(this, def))
    }

    fn visit_finish_func_def(&mut self, def: &'hir FinishFuncDef) -> Self::Result {
        let &Symbol {
            kind: SymbolKind::FinishFunc(SymFinishFunc { scope }),
            ..
        } = self.get_global(def.ident)?
        else {
            bug!("symbol should be a finish function");
        };
        self.with_scope(scope, |this| visit::walk_finish_func(this, def))
    }

    fn visit_finish_func_arg(&mut self, arg: &'hir FinishFuncArg) -> Self::Result {
        self.table.add_local_var(self.scope, arg.ident, arg.span)
    }

    fn visit_func_def(&mut self, def: &'hir FuncDef) -> Self::Result {
        let &Symbol {
            kind: SymbolKind::Func(SymFunc { scope }),
            ..
        } = self.get_global(def.ident)?
        else {
            bug!("symbol should be a function");
        };
        self.with_scope(scope, |this| visit::walk_func(this, def))
    }

    fn visit_func_arg(&mut self, arg: &'hir FuncArg) -> Self::Result {
        self.table.add_local_var(self.scope, arg.ident, arg.span)
    }

    fn visit_global_def(&mut self, def: &'hir GlobalLetDef) -> Self::Result {
        let &Symbol {
            kind: SymbolKind::GlobalVar(SymGlobalVar { scope }),
            ..
        } = self.get_global(def.ident)?
        else {
            bug!("symbol should be a global variable");
        };
        self.with_scope(scope, |this| visit::walk_global_let(this, def))
    }

    fn visit_struct_def(&mut self, def: &'hir StructDef) -> Self::Result {
        let &Symbol {
            kind: SymbolKind::Struct(SymStruct {}),
            ..
        } = self.get_global(def.ident)?
        else {
            bug!("symbol should be a struct");
        };
        self.with_scope(ScopeId::GLOBAL, |this| visit::walk_struct(this, def))
    }

    fn visit_ident(&mut self, ident: &'hir Ident) -> Self::Result {
        self.resolve_ident(ident)?;
        Ok(())
    }

    fn visit_stmt(&mut self, stmt: &'hir Stmt) -> Self::Result {
        let StmtKind::Let(v) = &stmt.kind else {
            return visit::walk_stmt(self, stmt);
        };
        // Resolve the value expression first so that it
        // cannot refer to the named value. Eg, this
        // should be illegal:
        //
        //    let x = x + 1;
        self.visit_expr(&self.hir.exprs[v.expr])?;
        self.table.add_local_var(self.scope, v.ident, stmt.span)
    }

    fn visit_block(&mut self, block: &'hir Block) -> Self::Result {
        let scope = self
            .table
            .create_child_scope(self.scope)
            .assume("scope should always be valid")?;
        self.with_scope(scope, |this| visit::walk_block(this, block))
    }

    fn visit_expr_kind(&mut self, kind: &'hir ExprKind) -> Self::Result {
        match kind {
            ExprKind::EnumRef(v) => {
                self.resolve_ident(&self.hir.idents[v.ident])?;
                // NB: The variant is 'resolved' during type
                // checking.
                Ok(())
            }
            ExprKind::Dot(expr, _field) => {
                let expr = &self.hir.exprs[*expr];
                self.visit_expr(expr)
                // NB: `_field` is 'resolved' during type
                // checking.
            }
            ExprKind::ForeignFunctionCall(call) => {
                // FFI calls are a little funky. They're written as
                // `module::function(...)`, so we first have to resolve
                // `module` to a module symbol, look up `function` in the
                // module scope, then manually resolve the arguments.
                let module_sym_id = self.resolve_ident({
                    let id = call.module;
                    &self.hir.idents[id]
                })?;
                let module_sym = self
                    .table
                    .symbols
                    .get(module_sym_id)
                    .assume("symbol should exist")?;
                let SymbolKind::FfiModule(SymFfiModule {
                    scope: module_scope,
                }) = &module_sym.kind
                else {
                    return Err(SymbolResolutionError::Undefined {
                        ident: call.module,
                        span: Span::dummy(),
                    });
                };

                self.with_scope(*module_scope, |this| {
                    let id = call.ident;
                    this.resolve_ident(&self.hir.idents[id])
                })?;

                for &id in &call.args {
                    let expr = &self.hir.exprs[id];
                    self.visit_expr(expr)?;
                }
                Ok(())
            }
            kind => visit::walk_expr_kind(self, kind),
        }
    }
}
