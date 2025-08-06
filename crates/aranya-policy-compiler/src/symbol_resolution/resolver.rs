//! Main symbol resolver implementation.

use std::{
    mem,
    ops::{ControlFlow, Index},
};

use aranya_policy_ast::ident;
use buggy::{bug, Bug, BugExt};
use tracing::{instrument, trace};

use super::{
    error::SymbolResolutionError,
    scope::{InsertError, ScopeId},
    symbols::{
        SymAction, SymEffect, SymEnum, SymFact, SymFfiModule, SymFinishFunc, SymFunc, SymGlobalVar,
        SymLocalVar, SymStruct, Symbol, SymbolId, SymbolKind,
    },
    Result, SymbolTable,
};
use crate::{
    diag::{BugAbort, DiagCtx, ErrorGuaranteed},
    hir::{
        visit::{self, Visitor},
        ActionArg, ActionDef, Block, EffectDef, EnumDef, ExprKind, FactDef, FfiModuleDef,
        FinishFuncArg, FinishFuncDef, FuncArg, FuncDef, GlobalLetDef, Hir, Ident, IdentId,
        IdentInterner, IdentRef, Span, Stmt, StmtKind, StructDef,
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
        ident: &Ident,
        kind: SymbolKind,
        span: Option<Span>,
    ) -> Result<()> {
        self.add_symbol(ScopeId::GLOBAL, ident, kind, span)
    }

    /// Adds a symbol created from `ident`, `kind`, and `span` to
    /// `scope`.
    #[instrument(skip(self))]
    fn add_symbol(
        &mut self,
        scope: ScopeId,
        ident: &Ident,
        kind: SymbolKind,
        span: Option<Span>,
    ) -> Result<()> {
        trace!("adding symbol");
        let sym = Symbol {
            ident: ident.id,
            kind,
            scope,
            span,
        };
        let sym_id = self.symbols.insert(sym);
        trace!(?sym_id, "added symbol");
        match self.scopes.try_insert(scope, ident.xref, sym_id) {
            Ok(()) => Ok(()),
            Err(InsertError::Duplicate(err)) => Err(SymbolResolutionError::Duplicate(err)),
            Err(InsertError::InvalidScopeId(_)) => bug!("scope should always be valid"),
        }
    }

    /// Adds a local variable symbol to `scope`.
    fn add_local_var(&mut self, scope: ScopeId, ident: &Ident, span: Span) -> Result<()> {
        let kind = SymbolKind::LocalVar(SymLocalVar { scope });
        self.add_symbol(scope, ident, kind, Some(span))
    }
}

pub(super) fn intern_reserved_idents(idents: &mut IdentInterner) -> Vec<IdentRef> {
    [ident!("this"), ident!("envelope"), ident!("id")]
        .into_iter()
        .map(|ident| idents.intern(ident))
        .collect::<Vec<_>>()
}

/// Walks [`Hir`] and builds the symbol table.
#[derive(Debug)]
pub(super) struct Resolver<'hir> {
    pub dcx: &'hir DiagCtx,
    /// The HIR being resolved.
    pub hir: &'hir Hir,
    /// The table being built.
    pub table: SymbolTable,
    pub idents: &'hir IdentInterner,
    pub reserved_idents: Vec<IdentRef>,
}

impl<'hir> Resolver<'hir> {
    /// Creates a symbol table from the given HIR.
    pub(super) fn resolve(mut self) -> Result<SymbolTable> {
        // First pass: collect all top-level declarations.
        self.collect_defs()?;

        // Second pass: resolve all identifier references.
        self.resolve_refs()?;

        for (ident, _) in &self.hir.idents {
            if !self.table.resolutions.contains_key(&ident) {
                // We goofed up somewhere!
                bug!("missed identifier")
            }
        }

        Ok(self.table)
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
        self.table
            .add_global_def(&self.hir[def.ident], kind, Some(def.span))?;

        // FFI modules are self-contained and cannot reference
        // anything in the policy file, so resolve everything
        // now.
        for &id in &def.functions {
            let f = &self.hir.ffi_funcs[id];
            let kind = SymbolKind::Func(SymFunc {
                scope: self.table.create_child_scope(scope)?,
            });
            self.table
                .add_symbol(scope, &self.hir[f.ident], kind, Some(f.span))?;
        }

        // TODO: other FFI module items

        Ok(())
    }

    /// Second pass: resolve all identifier references.
    fn resolve_refs(&mut self) -> Result<()> {
        let mut visitor = ResolveRefs {
            dcx: self.dcx,
            hir: self.hir,
            idents: self.idents,
            table: &mut self.table,
            scope: ScopeId::GLOBAL,
            reserved_idents: &self.reserved_idents,
            max_errs: 10,
            errs: Vec::new(),
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

impl Collector<'_> {
    fn add_global_def(
        &mut self,
        ident: IdentId,
        kind: SymbolKind,
        span: Option<Span>,
    ) -> Result<()> {
        self.table.add_global_def(&self.hir[ident], kind, span)
    }
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
        self.add_global_def(def.ident, kind, Some(def.span))
    }

    fn visit_effect_def(&mut self, def: &'hir EffectDef) -> Self::Result {
        let kind = SymbolKind::Effect(SymEffect {});
        self.add_global_def(def.ident, kind, Some(def.span))
    }

    fn visit_enum_def(&mut self, def: &'hir EnumDef) -> Self::Result {
        let kind = SymbolKind::Enum(SymEnum {});
        self.add_global_def(def.ident, kind, Some(def.span))
    }

    fn visit_fact_def(&mut self, def: &'hir FactDef) -> Self::Result {
        let kind = SymbolKind::Fact(SymFact {});
        self.add_global_def(def.ident, kind, Some(def.span))
    }

    fn visit_finish_func_def(&mut self, def: &'hir FinishFuncDef) -> Self::Result {
        let kind = SymbolKind::FinishFunc(SymFinishFunc {
            scope: self.table.create_child_scope(ScopeId::GLOBAL)?,
        });
        self.add_global_def(def.ident, kind, Some(def.span))
    }

    fn visit_func_def(&mut self, def: &'hir FuncDef) -> Self::Result {
        let kind = SymbolKind::Func(SymFunc {
            scope: self.table.create_child_scope(ScopeId::GLOBAL)?,
        });
        self.add_global_def(def.ident, kind, Some(def.span))
    }

    fn visit_global_def(&mut self, def: &'hir GlobalLetDef) -> Self::Result {
        let kind = SymbolKind::GlobalVar(SymGlobalVar {
            scope: self.table.create_child_scope(ScopeId::GLOBAL)?,
        });
        self.add_global_def(def.ident, kind, Some(def.span))
    }

    fn visit_struct_def(&mut self, def: &'hir StructDef) -> Self::Result {
        let kind = SymbolKind::Struct(SymStruct {});
        self.add_global_def(def.ident, kind, Some(def.span))
    }
}

#[derive(Debug)]
struct ResolveRefs<'a> {
    dcx: &'a DiagCtx,
    hir: &'a Hir,
    idents: &'a IdentInterner,
    table: &'a mut SymbolTable,
    reserved_idents: &'a [IdentRef],
    scope: ScopeId,
    /// The maximum number of errors we collect before failing.
    max_errs: usize,
    /// Collected errors.
    errs: Vec<SymbolResolutionError>,
}

impl ResolveRefs<'_> {
    /// Check if an identifier is reserved and return an error if
    /// it is.
    fn check_reserved(&self, ident: &Ident) -> Result<(), ErrorGuaranteed> {
        if self.reserved_idents.contains(&ident.xref) {
            Err(self.dcx.emit_err_diag(SymbolResolutionError::Reserved {
                ident: ident.id,
                span: ident.span,
                reserved_for: "language built-ins",
            }))
        } else {
            Ok(())
        }
    }

    /// Retrieves a global symbol.
    ///
    /// NB: By this point, all global symbols must have been
    /// collected.
    #[instrument(skip(self))]
    fn get_global(&mut self, id: IdentId) -> &Symbol {
        let ident = self.hir.index(id);
        if let Err(err) = self.resolve_ident(ident) {
            err.raise_fatal();
        }

        let sym_id = match self.table.scopes.get(ScopeId::GLOBAL, ident.xref) {
            Ok(Some(id)) => id,
            Ok(None) => self.dcx.emit_bug_diag(SymbolResolutionError::Undefined {
                ident: self.idents.get(ident.xref).unwrap().clone(),
                span: ident.span,
                scope: ScopeId::GLOBAL,
            }),
            Err(err) => self.dcx.emit_bug(err),
        };

        if let Some(got) = self.table.resolutions.get(&id) {
            assert_eq!(sym_id, *got);
        }

        match self.table.symbols.get(sym_id) {
            Some(sym) => sym,
            None => self.dcx.emit_bug("global symbol should exist"),
        }
    }

    /// Adds a local variable symbol to `scope`.
    fn add_local_var(&mut self, scope: ScopeId, ident: IdentId, span: Span) -> Result<()> {
        let ident = &self.hir[ident];
        self.table.add_local_var(scope, ident, span)
    }

    fn with_scope<F, R>(&mut self, scope: ScopeId, f: F) -> ControlFlow<R>
    where
        F: FnOnce(&mut Self) -> ControlFlow<R>,
    {
        let prev = mem::replace(&mut self.scope, scope);
        let result = f(self);
        self.scope = prev;
        result
    }

    #[instrument(skip(self))]
    fn resolve_ident(&mut self, ident: &Ident) -> Result<SymbolId, ErrorGuaranteed> {
        self.check_reserved(ident)?;

        let sym_id = self
            .table
            .scopes
            .get(self.scope, ident.xref)
            .map_err(|err| self.dcx.emit_bug(err))?
            .ok_or_else(|| {
                self.dcx.emit_err_diag(SymbolResolutionError::Undefined {
                    ident: self.idents.get(ident.xref).unwrap().clone(),
                    span: ident.span,
                    scope: self.scope,
                })
            })?;
        self.table.resolutions.insert(ident.id, sym_id);

        trace!(?sym_id, "resolved ident");
        Ok(sym_id)
    }
}

impl<'a: 'hir, 'hir> Visitor<'hir> for ResolveRefs<'a> {
    type Result = ControlFlow<Result<()>>;

    fn hir(&self) -> &'hir Hir {
        self.hir
    }

    fn visit_action(&mut self, def: &'hir ActionDef) -> Self::Result {
        let &Symbol {
            kind: SymbolKind::Action(SymAction { scope }),
            ..
        } = self.get_global(def.ident)
        else {
            self.dcx.emit_bug("symbol should be an action")
        };
        self.with_scope(scope, |this| visit::walk_action(this, def))
    }

    fn visit_action_arg(&mut self, arg: &'hir ActionArg) -> Self::Result {
        self.add_local_var(self.scope, arg.ident, arg.span)
    }

    fn visit_effect_def(&mut self, def: &'hir EffectDef) -> Self::Result {
        let &Symbol {
            kind: SymbolKind::Effect(SymEffect {}),
            ..
        } = self.get_global(def.ident)
        else {
            bug!("symbol should be an effect")
        };
        self.with_scope(ScopeId::GLOBAL, |this| visit::walk_effect(this, def))
    }

    fn visit_enum_def(&mut self, def: &'hir EnumDef) -> Self::Result {
        let &Symbol {
            kind: SymbolKind::Enum(SymEnum {}),
            ..
        } = self.get_global(def.ident)
        else {
            bug!("symbol should be an enum")
        };
        self.with_scope(ScopeId::GLOBAL, |this| visit::walk_enum(this, def))
    }

    fn visit_fact_def(&mut self, def: &'hir FactDef) -> Self::Result {
        let &Symbol {
            kind: SymbolKind::Fact(SymFact {}),
            scope,
            ..
        } = self.get_global(def.ident)
        else {
            bug!("symbol should be a fact")
        };
        self.with_scope(scope, |this| visit::walk_fact(this, def))
    }

    fn visit_finish_func_def(&mut self, def: &'hir FinishFuncDef) -> Self::Result {
        let &Symbol {
            kind: SymbolKind::FinishFunc(SymFinishFunc { scope }),
            ..
        } = self.get_global(def.ident)
        else {
            bug!("symbol should be a finish function")
        };
        self.with_scope(scope, |this| visit::walk_finish_func(this, def))
    }

    fn visit_finish_func_arg(&mut self, arg: &'hir FinishFuncArg) -> Self::Result {
        self.add_local_var(self.scope, arg.ident, arg.span)
    }

    fn visit_func_def(&mut self, def: &'hir FuncDef) -> Self::Result {
        let &Symbol {
            kind: SymbolKind::Func(SymFunc { scope }),
            ..
        } = self.get_global(def.ident)
        else {
            bug!("symbol should be a function")
        };
        self.with_scope(scope, |this| visit::walk_func(this, def))
    }

    fn visit_func_arg(&mut self, arg: &'hir FuncArg) -> Self::Result {
        self.add_local_var(self.scope, arg.ident, arg.span)
    }

    fn visit_global_def(&mut self, def: &'hir GlobalLetDef) -> Self::Result {
        let &Symbol {
            kind: SymbolKind::GlobalVar(SymGlobalVar { scope }),
            ..
        } = self.get_global(def.ident)
        else {
            bug!("symbol should be a global variable")
        };
        self.with_scope(scope, |this| visit::walk_global_let(this, def))
    }

    fn visit_struct_def(&mut self, def: &'hir StructDef) -> Self::Result {
        let &Symbol {
            kind: SymbolKind::Struct(SymStruct {}),
            ..
        } = self.get_global(def.ident)
        else {
            bug!("symbol should be a struct")
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
        self.add_local_var(self.scope, v.ident, stmt.span)
    }

    fn visit_block(&mut self, block: &'hir Block) -> Self::Result {
        let scope = self
            .table
            .create_child_scope(self.scope)
            .assume("self.scope should always be valid")?;
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
                // FFI calls are a little funky. They're written
                // as `module::function(...)`, so we first have
                // to resolve `module` to a module symbol, look
                // up `function` in the module scope, then
                // manually resolve the arguments in the
                // `self.scope`.
                //
                // TODO(eric): Do not use `get_global` here since
                // it should be a regular compiler error if the
                // module is not defined, not an ICE.
                let &Symbol {
                    kind: SymbolKind::FfiModule(SymFfiModule { scope }),
                    ..
                } = self.get_global(call.module)
                else {
                    bug!("symbol should be an FFI module")
                };
                self.with_scope(scope, |this| {
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
