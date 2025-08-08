use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, mem,
    ops::{ControlFlow, Index},
};

use aranya_policy_ast::{self as ast, ident};
use tracing::{instrument, trace};

use super::{
    error::SymbolResolutionError,
    scope::{InsertError, ScopeId, ScopedId},
    symbols::{Symbol, SymbolId, SymbolKind},
    Result, SymbolTable,
};
use crate::{
    diag::{
        Diag, DiagCtx, DiagMsg, Diagnostic, EmissionGuarantee, ErrorGuaranteed, MultiSpan,
        OptionExt, ResultExt, Severity,
    },
    hir::{
        visit::{self, Visitor},
        ActionArg, ActionCall, ActionDef, Block, BlockId, CmdDef, CmdFieldKind, EffectDef,
        EffectFieldKind, EnumDef, EnumRef, Expr, ExprKind, FactDef, FfiEnumDef, FfiFuncDef,
        FfiModuleDef, FfiStructDef, FinishFuncArg, FinishFuncDef, ForeignFunctionCall, FuncArg,
        FuncDef, FunctionCall, GlobalLetDef, Hir, Ident, IdentId, IdentInterner, IdentRef, LetStmt,
        Span, Stmt, StmtKind, StructDef, StructFieldKind, VType, VTypeKind,
    },
};

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
    /// Interned identifiers.
    pub idents: &'hir IdentInterner,
    /// Reserved identifiers.
    pub reserved_idents: Vec<IdentRef>,
}

impl<'hir> Resolver<'hir> {
    /// Creates a symbol table from the given HIR.
    pub(super) fn resolve(mut self) -> Result<SymbolTable, ErrorGuaranteed> {
        let scopes = self.collect_defs()?;
        let skipped = self.resolve_refs(scopes)?;

        // Make sure that we resolved all identifiers.
        for (id, ident) in &self.hir.idents {
            let mut spans = Vec::new();
            if !self.table.resolutions.contains_key(&id) && !skipped.contains(&id) {
                let msg = self.idents.get(ident.xref).unwrap().to_string();
                spans.push((ident.span, DiagMsg::from(msg)));
            }
            if !spans.is_empty() {
                let span = MultiSpan::from(spans);
                self.dcx.emit_span_bug(span, "missed identifiers")
            }
        }

        Ok(self.table)
    }
}

impl<'hir> Resolver<'hir> {
    /// First pass: collect all globals.
    #[instrument(skip(self))]
    fn collect_defs(&mut self) -> Result<ScopeMap, ErrorGuaranteed> {
        let mut visitor = CollectDefs {
            dcx: self.dcx,
            hir: self.hir,
            table: &mut self.table,
            scopes: ScopeMap::new(),
            idents: &self.idents,
            max_errs: 10,
            num_errs: 0,
        };
        visitor.visit_all();

        if let Some(err) = self.dcx.has_errors() {
            Err(err)
        } else {
            Ok(visitor.scopes)
        }
    }

    /// Second pass: resolve all identifier references.
    ///
    /// It returns the idents that were skipped because they will
    /// be resolved during type checking.
    #[instrument(skip(self))]
    fn resolve_refs(&mut self, scopes: ScopeMap) -> Result<BTreeSet<IdentId>, ErrorGuaranteed> {
        let mut visitor = ResolveIdents {
            dcx: self.dcx,
            hir: self.hir,
            idents: self.idents,
            table: &mut self.table,
            scope: ScopeId::GLOBAL,
            scopes,
            reserved_idents: &self.reserved_idents,
            max_errs: 10,
            num_errs: 0,
            skipped: BTreeSet::new(),
        };
        visitor.visit_all();

        let skipped = mem::take(&mut visitor.skipped);

        #[cfg(test)]
        {
            self.table.scopemap = mem::take(&mut visitor.scopes);
        }

        if let Some(err) = self.dcx.has_errors() {
            Err(err)
        } else {
            Ok(skipped)
        }
    }
}

/// Collects global symbols and adds them to the symbol table.
#[derive(Debug)]
struct CollectDefs<'a> {
    dcx: &'a DiagCtx,
    hir: &'a Hir,
    idents: &'a IdentInterner,
    table: &'a mut SymbolTable,
    scopes: ScopeMap,
    /// The maximum number of errors we collect before failing.
    max_errs: usize,
    /// The number of errors we've seen.
    num_errs: usize,
}

impl CollectDefs<'_> {
    /// Checks the result of an operation.
    ///
    /// If we've seen `self.max_errs` failed operations, exit
    /// early. Otherwise, collect the error and continue.
    fn check<E>(&mut self, result: Result<(), E>) -> ControlFlow<()> {
        assert!(self.num_errs < self.max_errs);
        if result.is_ok() {
            return ControlFlow::Continue(());
        }
        self.num_errs += 1;
        if self.num_errs >= self.max_errs {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }

    /// Adds a global symbol.
    #[instrument(skip_all)]
    fn add_global(&mut self, ident: IdentId, kind: SymbolKind, span: Span) -> ControlFlow<()> {
        let ident = self.hir.index(ident);

        trace!(
            ident = %self.idents.get(ident.xref).unwrap(),
            ?kind,
            ?span,
            "adding global",
        );

        // Some global items have their own child scope.
        if let Some(id) = ScopedId::try_from_sym_kind(kind) {
            let scope = self
                .table
                .create_child_scope(ScopeId::GLOBAL)
                .unwrap_or_bug(&self.dcx, "`ScopeId::GLOBAL` should always be valid");
            self.scopes.insert(id, scope);
        }

        let result = match self
            .table
            .add_symbol(ScopeId::GLOBAL, ident, kind, Some(span))
        {
            Ok(()) => Ok(()),
            Err(InsertError::Bug(err)) => self.dcx.emit_bug_diag(err),
            Err(InsertError::InvalidScopeId(_)) => {
                self.dcx.emit_bug("scope should always be valid")
            }
            Err(InsertError::Duplicate(id)) => {
                let id = self.table.symbols.get(id).unwrap().ident;
                let prev = self.hir.index(id).span;
                Err(self.dcx.emit_err_diag(AlreadyDefinedError {
                    ident: self.idents.get(ident.xref).unwrap().clone(),
                    span,
                    prev,
                }))
            }
        };
        self.check(result)
    }
}

impl<'a: 'hir, 'hir> Visitor<'hir> for CollectDefs<'a> {
    type Result = ControlFlow<()>;

    fn hir(&self) -> &'hir Hir {
        self.hir
    }

    fn visit_action(&mut self, def: &'hir ActionDef) -> Self::Result {
        let kind = SymbolKind::Action(def.id);
        self.add_global(def.ident, kind, def.span)
    }

    fn visit_cmd(&mut self, def: &'hir CmdDef) -> Self::Result {
        let kind = SymbolKind::Cmd(def.id);
        self.add_global(def.ident, kind, def.span)
    }

    fn visit_effect_def(&mut self, def: &'hir EffectDef) -> Self::Result {
        let kind = SymbolKind::Effect(def.id);
        self.add_global(def.ident, kind, def.span)
    }

    fn visit_enum_def(&mut self, def: &'hir EnumDef) -> Self::Result {
        let kind = SymbolKind::Enum(def.id);
        self.add_global(def.ident, kind, def.span)
    }

    fn visit_fact_def(&mut self, def: &'hir FactDef) -> Self::Result {
        let kind = SymbolKind::Fact(def.id);
        self.add_global(def.ident, kind, def.span)
    }

    fn visit_ffi_module(&mut self, def: &'hir FfiModuleDef) -> Self::Result {
        let kind = SymbolKind::FfiModule(def.id);
        self.add_global(def.ident, kind, def.span)
    }

    fn visit_ffi_enum(&mut self, def: &'hir FfiEnumDef) -> Self::Result {
        let kind = SymbolKind::FfiEnum(def.id);
        self.add_global(def.ident, kind, def.span)
    }

    fn visit_ffi_func(&mut self, def: &'hir FfiFuncDef) -> Self::Result {
        let kind = SymbolKind::FfiFunc(def.id);
        self.add_global(def.ident, kind, def.span)
    }

    fn visit_ffi_struct(&mut self, def: &'hir FfiStructDef) -> Self::Result {
        let kind = SymbolKind::FfiStruct(def.id);
        self.add_global(def.ident, kind, def.span)
    }

    fn visit_finish_func_def(&mut self, def: &'hir FinishFuncDef) -> Self::Result {
        let kind = SymbolKind::FinishFunc(def.id);
        self.add_global(def.ident, kind, def.span)
    }

    fn visit_func_def(&mut self, def: &'hir FuncDef) -> Self::Result {
        let kind = SymbolKind::Func(def.id);
        self.add_global(def.ident, kind, def.span)
    }

    fn visit_global_def(&mut self, def: &'hir GlobalLetDef) -> Self::Result {
        let kind = SymbolKind::GlobalVar(def.id);
        self.add_global(def.ident, kind, def.span)
    }

    fn visit_struct_def(&mut self, def: &'hir StructDef) -> Self::Result {
        let kind = SymbolKind::Struct(def.id);
        self.add_global(def.ident, kind, def.span)
    }
}

/// Resolves identifier usages.
#[derive(Debug)]
struct ResolveIdents<'a> {
    dcx: &'a DiagCtx,
    hir: &'a Hir,
    /// Interned identifiers.
    idents: &'a IdentInterner,
    /// The table that we're building.
    table: &'a mut SymbolTable,
    /// Languge reserved identifiers.
    reserved_idents: &'a [IdentRef],
    /// The current scope.
    scope: ScopeId,
    scopes: ScopeMap,
    /// The maximum number of errors we collect before failing.
    max_errs: usize,
    /// The number of errors we've seen.
    num_errs: usize,
    /// Identifiers that we skipped because they'll be "resolved"
    /// during while type checking. E.g., struct fields, enum
    /// variants, etc.
    skipped: BTreeSet<IdentId>,
}

impl ResolveIdents<'_> {
    /// Invokes `f` in the provided scope.
    #[instrument(skip_all, fields(old = %self.scope, new = %scope))]
    fn with_scope<F, R>(&mut self, scope: ScopeId, f: F) -> ControlFlow<R>
    where
        F: FnOnce(&mut Self) -> ControlFlow<R>,
    {
        let prev = mem::replace(&mut self.scope, scope);
        let result = f(self);
        self.scope = prev;
        result
    }

    /// Checks the result of an operation.
    ///
    /// If we've seen `self.max_errs` failed operations, exit
    /// early. Otherwise, collect the error and continue.
    fn check<E>(&mut self, result: Result<(), E>) -> ControlFlow<()> {
        assert!(self.num_errs < self.max_errs);
        if result.is_ok() {
            return ControlFlow::Continue(());
        }
        self.num_errs += 1;
        if self.num_errs >= self.max_errs {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }

    /// Retrieves the scope for the given `id`.
    fn lookup_scope(&mut self, id: impl Into<ScopedId>) -> ScopeId {
        let id = id.into();
        *self
            .scopes
            .get(&id)
            .unwrap_or_bug(&self.dcx, format!("unknown scope for `{id}`"))
    }

    /// Retrieves a symbol from the global scope.
    ///
    /// `id` must be the `IdentId` for a global symbol, like an
    /// action or a struct. Do not use this method to resolve
    /// a non-global `IdentId`.
    ///
    /// By this point, all global symbols should have been
    /// collected, so it emits an ICE if the symbol is not found.
    #[instrument(skip(self))]
    fn get_global(&mut self, id: IdentId) -> &Symbol {
        let &Ident { id, xref, span, .. } = self.hir.index(id);

        trace!(ident = %self.idents.get(xref).unwrap());

        let sym_id = match self.table.scopes.get(ScopeId::GLOBAL, xref) {
            Ok(Some(id)) => id,
            Ok(None) => self.dcx.emit_bug_diag(UndefinedError {
                ident: self.idents.get(xref).unwrap().clone(),
                span,
                kind: IdentKind::Def,
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

    /// Adds a function/arction/etc parameter as a local variable
    /// to the current scope.
    #[instrument(skip_all)]
    fn add_param(&mut self, ident: IdentId, span: Span) -> ControlFlow<()> {
        self.add_local_var(ident, span, None)
    }

    /// Adds a local variable to the current scope.
    ///
    /// If `block` is `Some` then the resulting symbol will be
    /// associated with the block.
    #[instrument(skip_all, fields(?block, scope = %self.scope))]
    fn add_local_var(
        &mut self,
        ident: IdentId,
        span: Span,
        block: Option<BlockId>,
    ) -> ControlFlow<()> {
        let ident = self.hir.index(ident);

        trace!(ident = %self.idents.get(ident.xref).unwrap());

        let kind = SymbolKind::LocalVar(block);
        let result = match self.table.add_symbol(self.scope, ident, kind, Some(span)) {
            Ok(()) => Ok(()),
            Err(InsertError::Bug(err)) => self.dcx.emit_bug_diag(err),
            Err(InsertError::InvalidScopeId(_)) => {
                self.dcx.emit_bug("scope should always be valid")
            }
            Err(InsertError::Duplicate(id)) => {
                let id = self.table.symbols.get(id).unwrap().ident;
                let prev = self.hir.index(id).span;
                Err(self.dcx.emit_err_diag(AlreadyDefinedError {
                    ident: self.idents.get(ident.xref).unwrap().clone(),
                    span,
                    prev,
                }))
            }
        };
        self.check(result)
    }

    /// Creates a child scope of the current scope.
    fn create_child_scope(&mut self, id: impl Into<ScopedId>) -> ScopeId {
        let scope = self
            .table
            .create_child_scope(self.scope)
            .unwrap_or_bug(&self.dcx, "`self.scope` should always be valid");
        self.scopes.insert(id.into(), scope);
        scope
    }

    /// Skips an identifier.
    #[instrument(skip_all, fields(%ident, scope = %self.scope))]
    fn skip(&mut self, ident: IdentId) {
        trace!("skipping ident");
        self.skipped.insert(ident);
    }

    /// Resolves `ident` to a symbol in the current scope and
    /// adds a resolution to the symbol table.
    ///
    /// `ident` must be a *usage*, not a *definition*.
    #[instrument(skip_all, fields(scope = %self.scope, %id, %kind))]
    fn resolve_ident_by_id(&mut self, id: IdentId, kind: IdentKind) -> ControlFlow<()> {
        let ident = self.hir.index(id);
        self.resolve_ident(ident, kind)
    }

    /// Resolves `ident` to a symbol in the current scope and
    /// adds a resolution to the symbol table.
    ///
    /// `ident` must be a *usage*, not a *definition*.
    #[instrument(skip_all, fields(
        scope = %self.scope,
        id = %ident.id,
        xref = %ident.xref,
        ident = %self.idents.get(ident.xref).unwrap(),
        %kind,
    ))]
    fn resolve_ident(&mut self, ident: &Ident, kind: IdentKind) -> ControlFlow<()> {
        let result = self.try_resolve_ident(ident, kind).map(|_| ());
        self.check(result)
    }

    fn try_resolve_ident(
        &mut self,
        ident: &Ident,
        kind: IdentKind,
    ) -> Result<SymbolId, ErrorGuaranteed> {
        trace!("resolving ident");

        if self.reserved_idents.contains(&ident.xref) {
            return Err(self.dcx.emit_err_diag(SymbolResolutionError::Reserved {
                ident: self.idents.get(ident.xref).unwrap().clone(),
                span: ident.span,
                reserved_for: "language builtins",
            }));
        }

        let sym_id = self
            .table
            .scopes
            .get(self.scope, ident.xref)
            .map_err(|err| self.dcx.emit_bug(err))?
            .ok_or_else(|| {
                self.dcx.emit_err_diag(UndefinedError {
                    ident: self.idents.get(ident.xref).unwrap().clone(),
                    span: ident.span,
                    kind,
                })
            })?;
        self.table.resolutions.insert(ident.id, sym_id);

        trace!(%sym_id, "resolved ident");

        Ok(sym_id)
    }
}

impl<'a: 'hir, 'hir> Visitor<'hir> for ResolveIdents<'a> {
    type Result = ControlFlow<()>;

    fn hir(&self) -> &'hir Hir {
        self.hir
    }

    #[instrument(skip_all, fields(id = %def.id, scope = %self.scope))]
    fn visit_action(&mut self, def: &'hir ActionDef) -> Self::Result {
        let scope = self.lookup_scope(def.id);
        self.with_scope(scope, |this| visit::walk_action(this, def))
    }

    #[instrument(skip_all, fields(id = %arg.id, scope = %self.scope))]
    fn visit_action_arg(&mut self, arg: &'hir ActionArg) -> Self::Result {
        let ActionArg {
            id: _id,
            span,
            ident,
            ty,
        } = arg;
        self.add_param(*ident, *span)?;
        self.visit_vtype(self.hir.index(*ty))
    }

    // TODO(eric): Delete this?
    #[instrument(skip_all, fields(id = %def.id, scope = %self.scope))]
    fn visit_cmd(&mut self, def: &'hir CmdDef) -> Self::Result {
        visit::walk_cmd(self, def)
    }

    #[instrument(skip(self))]
    fn visit_cmd_field_kind(&mut self, kind: &'hir CmdFieldKind) -> Self::Result {
        match kind {
            CmdFieldKind::Field { ident, ty } => {
                self.skip(*ident);
                self.visit_vtype(self.hir.index(*ty))
            }
            CmdFieldKind::StructRef(ident) => self.resolve_ident_by_id(*ident, IdentKind::Struct),
        }
    }

    // TODO(eric): Delete this?
    #[instrument(skip_all, fields(id = %def.id, scope = %self.scope))]
    fn visit_effect_def(&mut self, def: &'hir EffectDef) -> Self::Result {
        visit::walk_effect(self, def)
    }

    #[instrument(skip(self))]
    fn visit_effect_field_kind(&mut self, kind: &'hir EffectFieldKind) -> Self::Result {
        match kind {
            EffectFieldKind::Field { ident, ty } => {
                self.skip(*ident);
                self.visit_vtype(self.hir.index(*ty))
            }
            EffectFieldKind::StructRef(ident) => {
                self.resolve_ident_by_id(*ident, IdentKind::Struct)
            }
        }
    }

    #[instrument(skip_all, fields(id = %def.id, scope = %self.scope))]
    fn visit_enum_def(&mut self, def: &'hir EnumDef) -> Self::Result {
        // Do not visit the rest of the enum. We do not need to
        // resolve its field names.
        ControlFlow::Continue(())
    }

    // TODO(eric): Delete this?
    #[instrument(skip_all, fields(id = %def.id, scope = %self.scope))]
    fn visit_fact_def(&mut self, def: &'hir FactDef) -> Self::Result {
        visit::walk_fact(self, def)
    }

    #[instrument(skip_all, fields(id = %def.id))]
    fn visit_finish_func_def(&mut self, def: &'hir FinishFuncDef) -> Self::Result {
        let scope = self.lookup_scope(def.id);
        self.with_scope(scope, |this| visit::walk_finish_func(this, def))
    }

    #[instrument(skip_all, fields(id = %arg.id))]
    fn visit_finish_func_arg(&mut self, arg: &'hir FinishFuncArg) -> Self::Result {
        self.add_param(arg.ident, arg.span)?;
        self.visit_vtype(self.hir.index(arg.ty))
    }

    #[instrument(skip_all, fields(id = %def.id))]
    fn visit_func_def(&mut self, def: &'hir FuncDef) -> Self::Result {
        let scope = self.lookup_scope(def.id);
        self.with_scope(scope, |this| visit::walk_func(this, def))
    }

    #[instrument(skip_all, fields(id = %arg.id))]
    fn visit_func_arg(&mut self, arg: &'hir FuncArg) -> Self::Result {
        trace!(
            ?arg,
            ident = ?self.idents.get(self.hir.index(arg.ident).xref).unwrap(),
            vtype = ?self.hir.index(arg.ty),
            "func arg",
        );
        self.add_param(arg.ident, arg.span)?;
        self.visit_vtype(self.hir.index(arg.ty))
    }

    // TODO(eric): Delete this?
    #[instrument(skip_all, fields(id = %def.id))]
    fn visit_global_def(&mut self, def: &'hir GlobalLetDef) -> Self::Result {
        visit::walk_global_let(self, def)
    }

    // TODO(eric): Delete this?
    #[instrument(skip_all, fields(id = %def.id))]
    fn visit_struct_def(&mut self, def: &'hir StructDef) -> Self::Result {
        visit::walk_struct(self, def)
    }

    #[instrument(skip(self))]
    fn visit_struct_field_kind(&mut self, kind: &'hir StructFieldKind) -> Self::Result {
        match kind {
            StructFieldKind::Field { ident, ty } => {
                self.skip(*ident);
                self.visit_vtype(self.hir.index(*ty))
            }
            StructFieldKind::StructRef(ident) => {
                self.resolve_ident_by_id(*ident, IdentKind::Struct)
            }
        }
    }

    #[instrument(skip_all, fields(id = %ident.id))]
    fn visit_ident(&mut self, ident: &'hir Ident) -> Self::Result {
        self.resolve_ident(ident, IdentKind::Value)
    }

    #[instrument(skip_all, fields(id = %block.id))]
    fn visit_block(&mut self, block: &'hir Block) -> Self::Result {
        let scope = self.create_child_scope(block.id);
        self.with_scope(scope, |this| visit::walk_block(this, block))
    }

    #[instrument(skip_all, fields(id = %stmt.id))]
    fn visit_stmt(&mut self, stmt: &'hir Stmt) -> Self::Result {
        match &stmt.kind {
            StmtKind::Let(LetStmt { ident, expr }) => {
                // Resolve the value expression first so that it
                // cannot refer to the named value. Eg, these
                // should be illegal:
                //
                //    let x = x + 1;
                //    let y = {
                //        : y + 1
                //    }
                let expr = &self.hir.exprs[*expr];
                self.visit_expr(expr)?;

                let block = match &expr.kind {
                    ExprKind::Block(block, _) => Some(*block),
                    _ => None,
                };
                self.add_local_var(*ident, stmt.span, block)
            }
            StmtKind::ActionCall(ActionCall { ident, args }) => {
                self.resolve_ident_by_id(*ident, IdentKind::Action)?;
                for &id in args {
                    self.visit_expr(self.hir.index(id))?;
                }
                ControlFlow::Continue(())
            }
            _ => visit::walk_stmt(self, stmt),
        }
    }

    #[instrument(skip(self))]
    fn visit_expr(&mut self, expr: &'hir Expr) -> Self::Result {
        match &expr.kind {
            ExprKind::EnumRef(EnumRef { ident, value }) => {
                self.resolve_ident_by_id(*ident, IdentKind::Enum)?;
                self.skip(*value);
                ControlFlow::Continue(())
            }
            ExprKind::Dot(expr, field) => {
                self.visit_expr(self.hir.index(*expr))?;
                self.skip(*field);
                ControlFlow::Continue(())
            }
            ExprKind::ForeignFunctionCall(ForeignFunctionCall {
                module,
                ident,
                args,
            }) => {
                // FFI calls are a little funky. They're written
                // as `module::function(...)`, so we first have
                // to resolve `module` to a module symbol, look
                // up `function` in the module scope, then
                // manually resolve the arguments in the
                // `self.scope`.
                //
                // TODO(eric): `get_global` and `lookup_scope`
                // both emit ICEs instead of regular errors, so
                // they shouldn't be used here. (Except that
                // this is the only use of `get_global`, so it
                // should be updated to emit a regular error.)
                let &Symbol {
                    kind: SymbolKind::FfiModule(id),
                    ..
                } = self.get_global(*module)
                else {
                    self.dcx.emit_bug("symbol should be an FFI module")
                };
                let scope = self.lookup_scope(id);
                self.with_scope(scope, |this| {
                    this.resolve_ident_by_id(*ident, IdentKind::FfiFn)
                })?;

                for &id in args {
                    let expr = &self.hir.exprs[id];
                    self.visit_expr(expr)?;
                }
                ControlFlow::Continue(())
            }
            ExprKind::Block(block, expr) => {
                // Handle block expressions manually, otherwise
                // we'll resolve the terminating expr *outside*
                // the block scope, which is incorrect.
                let scope = self.create_child_scope(*block);
                self.with_scope(scope, |this| {
                    visit::walk_block(this, this.hir.index(*block))?;
                    visit::walk_expr(this, this.hir.index(*expr))
                })
            }
            ExprKind::FunctionCall(FunctionCall { ident, args }) => {
                self.resolve_ident_by_id(*ident, IdentKind::Fn)?;
                for &id in args {
                    let expr = &self.hir.exprs[id];
                    self.visit_expr(expr)?;
                }
                ControlFlow::Continue(())
            }
            _ => visit::walk_expr(self, expr),
        }
    }

    #[instrument(skip(self))]
    fn visit_vtype(&mut self, vtype: &'hir VType) -> Self::Result {
        match vtype.kind {
            VTypeKind::Struct(ident) => self.resolve_ident_by_id(ident, IdentKind::Struct),
            VTypeKind::Enum(ident) => self.resolve_ident_by_id(ident, IdentKind::Enum),
            _ => visit::walk_vtype(self, vtype),
        }
    }
}

/// Whether we expect the next identifier to be a value
/// (variable, parameter, etc.) or a type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum IdentKind {
    Action,
    Def,
    Enum,
    Fn,
    FfiFn,
    Struct,
    Value,
}

impl fmt::Display for IdentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Action => write!(f, "action"),
            Self::Def => write!(f, "definition"),
            Self::Enum => write!(f, "enum"),
            Self::Fn => write!(f, "function"),
            Self::FfiFn => write!(f, "FFI function"),
            Self::Struct => write!(f, "struct"),
            Self::Value => write!(f, "value"),
        }
    }
}

/// An identifier is undefined.
#[derive(Clone, Debug, thiserror::Error)]
struct UndefinedError {
    ident: ast::Identifier,
    span: Span,
    kind: IdentKind,
}

impl fmt::Display for UndefinedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cannot find {} `{}` in this scope",
            self.kind, self.ident,
        )
    }
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for UndefinedError {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let span = MultiSpan::from_span(self.span, "not found in this scope");
        Diag::new(ctx, severity, self.to_string()).with_span(span)
    }
}

/// An identifier has already been defined in this scope.
#[derive(Clone, Debug, thiserror::Error)]
#[error("`{ident}` has already been defined in this scope")]
struct AlreadyDefinedError {
    ident: ast::Identifier,
    span: Span,
    prev: Span,
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for AlreadyDefinedError {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let mut span = MultiSpan::from_span(self.span, "already defined in this scope");
        span.push_label(self.prev, "previous definition is here");
        Diag::new(ctx, severity, self.to_string()).with_span(span)
    }
}

pub(crate) type ScopeMap = BTreeMap<ScopedId, ScopeId>;
