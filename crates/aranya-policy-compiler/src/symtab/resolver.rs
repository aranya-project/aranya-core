#![expect(clippy::unwrap_used)]

use std::{fmt, mem, ops::ControlFlow};

use aranya_policy_ast as ast;
use tracing::{instrument, trace};

use super::{
    error::SymbolResolutionError,
    scope::{InsertError, ScopeId, ScopedId},
    symbols::{Symbol, SymbolId, SymbolKind},
    Result, ScopeMap, SymbolTable,
};
use crate::{
    ctx::Ctx,
    diag::{
        Diag, DiagCtx, DiagMsg, Diagnostic, EmissionGuarantee, ErrorGuaranteed, MultiSpan,
        OptionExt, ResultExt, Severity,
    },
    hir::{
        visit::{self, Visitor},
        ActionCall, Block, BlockId, Body, CmdDef, CmdFieldKind, EffectFieldKind, EnumDef, EnumRef,
        Expr, ExprKind, ForeignFunctionCall, FunctionCall, GlobalLetDef, GlobalSymbol, Hir,
        HirView, Ident, IdentId, IdentRef, LetStmt, Param, Span, Stmt, StmtKind, StructFieldKind,
        VType, VTypeKind,
    },
};

/// Builds the symbol table.
#[derive(Debug)]
pub(super) struct Resolver<'cx> {
    pub ctx: Ctx<'cx>,
    pub hir: HirView<'cx>,
    /// The table being built.
    pub table: SymbolTable,
    /// Reserved identifiers.
    pub reserved_idents: Vec<IdentRef>,
}

impl<'ctx> Resolver<'ctx> {
    fn dcx(&self) -> &'ctx DiagCtx {
        self.ctx.dcx()
    }

    /// Creates a symbol table from the given HIR.
    pub(super) fn resolve(mut self) -> Result<SymbolTable, ErrorGuaranteed> {
        let scopes = self.mark()?;
        self.resolve_refs(scopes)?;

        // Make sure that we resolved all identifiers.
        for (id, ident) in &self.hir.hir().idents {
            let mut spans = Vec::new();
            if !self.table.resolutions.contains_key(&id) && !self.table.skipped.contains(&id) {
                let msg = self.ctx.get_ident(ident.xref).to_string();
                spans.push((ident.span, DiagMsg::from(msg)));
            }
            if !spans.is_empty() {
                let span = MultiSpan::from(spans);
                self.dcx().emit_span_bug(span, "missed identifiers")
            }
        }

        Ok(self.table)
    }

    /// First pass: mark all globals.
    #[instrument(skip(self))]
    fn mark(&mut self) -> Result<ScopeMap, ErrorGuaranteed> {
        let mut visitor = Mark {
            ctx: self.ctx,
            hir: self.hir,
            table: &mut self.table,
            scopes: ScopeMap::new(),
            max_errs: 10,
            num_errs: 0,
        };
        visitor.visit_all();

        match self.ctx.dcx().has_errors() {
            Some(err) => Err(err),
            None => Ok(visitor.scopes),
        }
    }

    /// Second pass: resolve all identifier references.
    ///
    /// It returns the idents that were skipped because they will
    /// be resolved during type checking.
    #[instrument(skip_all)]
    fn resolve_refs(&mut self, scopes: ScopeMap) -> Result<(), ErrorGuaranteed> {
        let mut visitor = ResolveIdents {
            ctx: self.ctx,
            hir: self.hir,
            table: &mut self.table,
            scope: ScopeId::GLOBAL,
            scopes,
            reserved_idents: &self.reserved_idents,
            max_errs: 10,
            num_errs: 0,
        };
        visitor.visit_all();

        #[cfg(test)]
        {
            self.table.scopemap = mem::take(&mut visitor.scopes);
        }

        if let Some(err) = self.dcx().has_errors() {
            Err(err)
        } else {
            Ok(())
        }
    }
}

/// Marks top-level items (i.e., global symbols) and adds them to
/// the symbol table.
#[derive(Debug)]
struct Mark<'ctx> {
    ctx: Ctx<'ctx>,
    hir: HirView<'ctx>,
    table: &'ctx mut SymbolTable,
    scopes: ScopeMap,
    /// The maximum number of errors we collect before failing.
    max_errs: usize,
    /// The number of errors we've seen.
    num_errs: usize,
}

impl<'ctx> Mark<'ctx> {
    fn dcx(&self) -> &'ctx DiagCtx {
        self.ctx.dcx()
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
        self.num_errs = self.num_errs.saturating_add(1);
        if self.num_errs >= self.max_errs {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }

    /// "Marks" a global item by adding it to the symbol table.
    #[instrument(skip_all)]
    fn mark<T>(&mut self, node: T) -> ControlFlow<()>
    where
        T: GlobalSymbol,
        SymbolKind: From<T::Id>,
    {
        let ident = self.hir.lookup(node.ident());
        let span = node.span();
        let kind = SymbolKind::from(node.id());

        trace!(
            ident = %self.ctx.get_ident(ident.xref),
            ?kind,
            ?span,
            "adding global",
        );

        let result = match self.table.add_symbol(ScopeId::GLOBAL, ident, kind, span) {
            Ok(()) => Ok(()),
            Err(InsertError::Bug(err)) => self.dcx().emit_bug_diag(err),
            Err(InsertError::InvalidScopeId(_)) => {
                self.dcx().emit_bug("scope should always be valid")
            }
            Err(InsertError::Duplicate(id)) => {
                let id = self.table.symbols.get(id).unwrap().ident;
                let prev = self.hir.lookup(id).span;
                Err(self.dcx().emit_err_diag(AlreadyDefinedError {
                    ident: self.ctx.get_ident(ident.xref).clone(),
                    span,
                    prev,
                }))
            }
        };
        self.check(result)
    }
}

macro_rules! mark {
    ($visit:ident => $ty:ty) => {
        #[instrument(skip_all, fields(id = %def.id))]
        fn $visit(&mut self, def: &'hir $ty) -> ControlFlow<()> {
            self.mark(def)
        }
    };
}

impl<'ctx: 'hir, 'hir> Visitor<'hir> for Mark<'ctx> {
    type Result = ControlFlow<()>;

    fn hir(&self) -> &'hir Hir {
        self.hir.hir()
    }

    visit::for_each_top_level_item!(mark);
}

/// Resolves identifier usages.
#[derive(Debug)]
struct ResolveIdents<'cx> {
    ctx: Ctx<'cx>,
    hir: HirView<'cx>,
    /// The table that we're building.
    table: &'cx mut SymbolTable,
    /// Languge reserved identifiers.
    reserved_idents: &'cx [IdentRef],
    /// The current scope.
    scope: ScopeId,
    scopes: ScopeMap,
    /// The maximum number of errors we collect before failing.
    max_errs: usize,
    /// The number of errors we've seen.
    num_errs: usize,
}

impl<'ctx> ResolveIdents<'ctx> {
    fn dcx(&self) -> &'ctx DiagCtx {
        self.ctx.dcx()
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
        self.num_errs = self.num_errs.saturating_add(1);
        if self.num_errs >= self.max_errs {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }

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

    /// Invokes `f` in a child scope of the current scope.
    #[instrument(skip_all)]
    fn with_child_scope<F, R>(&mut self, id: impl Into<ScopedId>, f: F) -> ControlFlow<R>
    where
        F: FnOnce(&mut Self) -> ControlFlow<R>,
    {
        let scope = self.create_child_scope(id.into());
        self.with_scope(scope, f)
    }

    /// Creates a child scope of the current scope.
    #[instrument(skip_all, fields(?id))]
    fn create_child_scope(&mut self, id: ScopedId) -> ScopeId {
        let scope = self
            .table
            .create_child_scope(self.scope)
            .unwrap_or_bug(self.dcx(), "`self.scope` should always be valid");
        self.scopes.insert(id, scope);
        trace!(%scope, "created child scope");
        scope
    }

    /// Retrieves the scope for the given `id`.
    fn lookup_scope(&mut self, id: impl Into<ScopedId>) -> ScopeId {
        let id = id.into();
        *self
            .scopes
            .get(&id)
            .unwrap_or_bug(self.dcx(), format!("unknown scope for `{id}`"))
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
        let &Ident { id, xref, span, .. } = self.hir.lookup(id);

        trace!(ident = %self.ctx.get_ident(xref));

        let sym_id = match self.table.scopes.get_sym(ScopeId::GLOBAL, xref) {
            Ok(Some(id)) => id,
            Ok(None) => self.dcx().emit_bug_diag(UndefinedError {
                ident: self.ctx.get_ident(xref).clone(),
                span,
                kind: IdentKind::Def,
            }),
            Err(err) => self.dcx().emit_bug(err),
        };

        if let Some(got) = self.table.resolutions.get(&id) {
            assert_eq!(sym_id, *got);
        }

        match self.table.symbols.get(sym_id) {
            Some(sym) => sym,
            None => self.dcx().emit_bug("global symbol should exist"),
        }
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
        let ident = self.hir.lookup(ident);

        trace!(ident = %self.ctx.get_ident(ident.xref));

        let kind = SymbolKind::LocalVar(block);
        let result = match self.table.add_symbol(self.scope, ident, kind, span) {
            Ok(()) => Ok(()),
            Err(InsertError::Bug(err)) => self.dcx().emit_bug_diag(err),
            Err(InsertError::InvalidScopeId(_)) => {
                self.dcx().emit_bug("scope should always be valid")
            }
            Err(InsertError::Duplicate(id)) => {
                let id = self.table.symbols.get(id).unwrap().ident;
                let prev = self.hir.lookup(id).span;
                Err(self.dcx().emit_err_diag(AlreadyDefinedError {
                    ident: self.ctx.get_ident(ident.xref).clone(),
                    span,
                    prev,
                }))
            }
        };
        self.check(result)
    }

    /// Skips an identifier.
    #[instrument(skip_all, fields(%ident, scope = %self.scope))]
    fn skip_ident(&mut self, ident: IdentId) {
        trace!(
            ident = %{
                let ident = self.hir.lookup(ident);
                self.ctx.get_ident(ident.xref)
            },
            "skipping ident",
        );
        self.table.skipped.insert(ident);
    }

    /// Resolves `ident` to a symbol in the current scope and
    /// adds a resolution to the symbol table.
    ///
    /// `ident` must be a *usage*, not a *definition*.
    #[instrument(skip_all, fields(scope = %self.scope, %id, %kind))]
    fn resolve_ident_by_id(&mut self, id: IdentId, kind: IdentKind) -> ControlFlow<()> {
        let ident = self.hir.lookup(id);
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
        ident = %self.ctx.get_ident(ident.xref),
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
            return Err(self.dcx().emit_err_diag(SymbolResolutionError::Reserved {
                ident: self.ctx.get_ident(ident.xref).clone(),
                span: ident.span,
                reserved_for: "language builtins",
            }));
        }

        let sym_id = self
            .table
            .scopes
            .get_sym(self.scope, ident.xref)
            .map_err(|err| self.dcx().emit_bug(err))?
            .ok_or_else(|| {
                self.dcx().emit_err_diag(UndefinedError {
                    ident: self.ctx.get_ident(ident.xref).clone(),
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
        self.hir.hir()
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
                self.skip_ident(*ident);
                self.visit_vtype(self.hir.lookup(*ty))
            }
            CmdFieldKind::StructRef(ident) => self.resolve_ident_by_id(*ident, IdentKind::Struct),
        }
    }

    #[instrument(skip(self))]
    fn visit_effect_field_kind(&mut self, kind: &'hir EffectFieldKind) -> Self::Result {
        match kind {
            EffectFieldKind::Field { ident, ty } => {
                self.skip_ident(*ident);
                self.visit_vtype(self.hir.lookup(*ty))
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

    #[instrument(skip_all, fields(id = %def.id))]
    fn visit_global_def(&mut self, def: &'hir GlobalLetDef) -> Self::Result {
        // TODO(eric): See the comment in visit_stmt about
        // LetStmt.
        visit::walk_global_let(self, def)
    }

    #[instrument(skip(self))]
    fn visit_struct_field_kind(&mut self, kind: &'hir StructFieldKind) -> Self::Result {
        match kind {
            StructFieldKind::Field { ident, ty } => {
                self.skip_ident(*ident);
                self.visit_vtype(self.hir.lookup(*ty))
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
        self.with_child_scope(block.id, |this| visit::walk_block(this, block))
    }

    #[instrument(skip_all, fields(id = %body.id))]
    fn visit_body(&mut self, body: &'hir Body) -> Self::Result {
        self.with_child_scope(body.id, |this| visit::walk_body(this, body))
    }

    #[instrument(skip_all, fields(id = %param.id))]
    fn visit_param(&mut self, param: &'hir Param) -> Self::Result {
        let Param {
            id: _,
            span,
            ident,
            ty,
        } = param;
        self.add_local_var(*ident, *span, None)?;
        self.visit_vtype(self.hir.lookup(*ty))
    }

    #[instrument(skip_all, fields(id = %stmt.id))]
    fn visit_stmt(&mut self, stmt: &'hir Stmt) -> Self::Result {
        let Stmt {
            id: _,
            span,
            kind,
            returns: _,
        } = stmt;
        match &kind {
            StmtKind::Let(LetStmt { ident, expr }) => {
                // Resolve the value expression first so that it
                // cannot refer to the named value. Eg, these
                // should be illegal:
                //
                //    let x = x + 1
                //    let y = {
                //        : y + 1
                //    }
                let expr = self.hir.lookup(*expr);
                self.visit_expr(expr)?;

                let block = match &expr.kind {
                    ExprKind::Block(block, _) => Some(*block),
                    _ => None,
                };
                self.add_local_var(*ident, *span, block)
            }
            StmtKind::ActionCall(ActionCall { ident, args }) => {
                self.resolve_ident_by_id(*ident, IdentKind::Action)?;
                for &id in args {
                    self.visit_expr(self.hir.lookup(id))?;
                }
                ControlFlow::Continue(())
            }
            StmtKind::FunctionCall(FunctionCall { ident, args }) => {
                self.resolve_ident_by_id(*ident, IdentKind::Fn)?;
                for &id in args {
                    self.visit_expr(self.hir.lookup(id))?;
                }
                ControlFlow::Continue(())
            }
            _ => visit::walk_stmt(self, stmt),
        }
    }

    #[instrument(skip(self))]
    fn visit_expr(&mut self, expr: &'hir Expr) -> Self::Result {
        let Expr {
            id: _,
            span: _,
            kind,
            pure: _,
            returns: _,
        } = expr;
        match &kind {
            ExprKind::EnumRef(EnumRef { ident, value }) => {
                self.resolve_ident_by_id(*ident, IdentKind::Enum)?;
                self.skip_ident(*value);
                ControlFlow::Continue(())
            }
            ExprKind::Dot(expr, field) => {
                self.visit_expr(self.hir.lookup(*expr))?;
                self.skip_ident(*field);
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
                    self.dcx().emit_bug("symbol should be an FFI module")
                };
                let scope = self.lookup_scope(id);
                self.with_scope(scope, |this| {
                    this.resolve_ident_by_id(*ident, IdentKind::FfiFn)
                })?;

                for &id in args {
                    let expr = self.hir.lookup(id);
                    self.visit_expr(expr)?;
                }
                ControlFlow::Continue(())
            }
            ExprKind::Block(block, expr) => {
                // Handle block expressions manually, otherwise
                // we'd resolve the terminating expr *outside*
                // the block scope, which is incorrect.
                self.with_child_scope(*block, |this| {
                    visit::walk_block(this, this.hir.lookup(*block))?;
                    visit::walk_expr(this, this.hir.lookup(*expr))
                })
            }
            ExprKind::FunctionCall(FunctionCall { ident, args }) => {
                self.resolve_ident_by_id(*ident, IdentKind::Fn)?;
                for &id in args {
                    let expr = self.hir.lookup(id);
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
