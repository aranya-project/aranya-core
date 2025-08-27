use std::{borrow::Cow, cell::RefCell, collections::BTreeMap};

use aranya_policy_ast as ast;
use indexmap::IndexSet;

use super::{
    types::{
        EnumVariant, FactField, Item, ItemAction, ItemCmd, ItemEffect, ItemFact, ItemFfiFunc,
        ItemFfiModule, ItemFinishFunc, ItemFunc, ItemKind, ItemRef, StructField, Type, TypeEnum,
        TypeEnv, TypeKind, TypeOptional, TypeRef, TypeStruct, TypeStructOrigin, TypeVar,
    },
    unify::UnifierState,
    Types,
};
use crate::{
    ctx::Ctx,
    depgraph::DepsView,
    diag::{
        Diag, DiagCtx, Diagnostic, EmissionGuarantee, ErrorGuaranteed, MultiSpan, OptionExt,
        Severity,
    },
    hir::{
        self, ActionCall, ActionDef, ActionId, BinOp, Block, BlockId, Body, CheckStmt,
        CmdFieldKind, CmdId, Create, DebugAssert, Delete, EffectFieldKind, EffectId, Emit, EnumDef,
        EnumId, EnumRef, Expr, ExprId, ExprKind, FactCountType, FactDef, FactFieldExpr, FactId,
        FactLiteral, FfiEnumId, FfiFuncId, FfiImportId, FfiModuleId, FfiStructId, FinishFuncDef,
        FinishFuncId, ForeignFunctionCall, FuncDef, FuncId, FunctionCall, GlobalId, GlobalLetDef,
        HirView, IdentId, IfBranch, IfStmt, Intrinsic, LetStmt, Lit, LitKind, MapStmt, MatchArm,
        MatchExpr, MatchPattern, MatchStmt, NamedStruct, Param, ParamId, Publish, ReturnStmt, Span,
        Stmt, StmtId, StmtKind, StructDef, StructFieldExpr, StructId, Ternary, UnaryOp, Update,
        VTypeId, VTypeKind,
    },
    symtab::{self, Symbol, SymbolId, SymbolKind, SymbolsView},
};

pub(super) struct TypeChecker<'cx> {
    pub ctx: Ctx<'cx>,

    pub hir: HirView<'cx>,
    pub symbols: SymbolsView<'cx>,
    pub deps: DepsView<'cx>,

    // TODO: Add expr (and other) types here.
    pub types: Types,

    pub state: RefCell<UnifierState>,

    /// Current type environment
    pub env: TypeEnv,

    /// Maps local variable symbols to their types
    pub local_vars: RefCell<BTreeMap<SymbolId, TypeRef>>,

    /// Maximum number of errors before stopping
    pub max_errs: usize,
    /// Number of errors emitted so far
    pub num_errs: usize,
}

// misc helpers
impl<'cx> TypeChecker<'cx> {
    fn dcx(&self) -> &'cx DiagCtx {
        self.ctx.dcx()
    }

    /// Retrieves an item.
    fn lookup_item(&self, ident: IdentId) -> Item<'cx> {
        let sym_id = self.symbols.resolve_item(ident);
        let xref = self
            .env
            .item_symbols
            .get(&sym_id)
            .copied()
            .unwrap_or_bug(self.dcx(), "item not found");
        let kind = self.ctx.get_item(xref);
        Item { xref, kind }
    }

    /// Retrieves a type.
    fn lookup_type(&self, ident: IdentId) -> Type<'cx> {
        let sym_id = self.symbols.resolve_type(ident);
        let xref = self
            .env
            .type_symbols
            .get(&sym_id)
            .copied()
            .unwrap_or_bug(self.dcx(), "type not found");
        let kind = self.ctx.get_type(xref);
        Type { xref, kind }
    }

    /// Retrieves a symbol's name (identifier).
    fn get_sym_name(&self, id: SymbolId) -> &'cx ast::Identifier {
        let sym = self.symbols.get(id);
        self.hir.lookup_ident(sym.ident)
    }

    /// Returns a string that describes the type.
    fn get_type_string(&self, ty: &'cx TypeKind) -> Cow<'static, str> {
        match ty {
            TypeKind::String => Cow::Borrowed("string"),
            TypeKind::Int => Cow::Borrowed("int"),
            TypeKind::Bool => Cow::Borrowed("bool"),
            TypeKind::Bytes => Cow::Borrowed("bytes"),
            TypeKind::Id => Cow::Borrowed("id"),
            TypeKind::Struct(TypeStruct { symbol, .. }) => {
                Cow::Owned(format!("struct {}", self.get_sym_name(*symbol)))
            }
            TypeKind::Enum(TypeEnum { symbol, .. }) => {
                Cow::Owned(format!("enum {}", self.get_sym_name(*symbol)))
            }
            TypeKind::Optional(TypeOptional { inner: ty }) => match ty {
                Some(xref) => Cow::Owned(format!("optional {}", self.get_type_ref_string(*xref))),
                None => Cow::Borrowed("None"),
            },
            TypeKind::TypeVar(TypeVar { id }) => Cow::Owned(format!("typevar({id})")),
            TypeKind::Unit => Cow::Borrowed("unit"),
            TypeKind::Error => Cow::Borrowed("error"),
            TypeKind::Infer => Cow::Borrowed("infer"),
            TypeKind::Never => Cow::Borrowed("never"),
        }
    }

    fn get_type_ref_string(&self, id: TypeRef) -> Cow<'static, str> {
        self.get_type_string(self.ctx.get_type(id))
    }

    /// Attempts to find a struct field.
    ///
    /// It emits an error and returns `None` if the field is not
    /// found.
    fn find_struct_field(&self, ty: &'cx TypeStruct, field: IdentId) -> Option<&'cx StructField> {
        let field_xref = self.hir.lookup_ident_ref(field);
        if let Some(field) = ty.find_field(field_xref) {
            return Some(field);
        }
        let st_name = self.get_sym_name(ty.symbol);
        let field_name = self.ctx.get_ident(field_xref);
        let span = MultiSpan::from_span(
            self.hir.lookup_span(field),
            format!("struct `{st_name}` does not have field `{field_name}`"),
        );
        self.dcx().emit_span_err(span, "unknown field");
        None
    }

    /// Gets the struct TypeRef for a fact by looking up its struct_id.
    fn get_struct_type_for_fact(&self, fact_id: FactId) -> TypeRef {
        let fact_def = self.hir.lookup(fact_id);
        let struct_def = self.hir.lookup(fact_def.struct_id);
        let struct_symbol_id = self.symbols.resolve_type(struct_def.ident);
        self.env
            .type_symbols
            .get(&struct_symbol_id)
            .copied()
            .unwrap_or_bug(self.dcx(), "struct type not found for fact")
    }

    /// Helper method to check for field conflicts and insert field if no conflict exists.
    /// Returns true if the field was successfully inserted, false if there was a conflict.
    fn check_and_insert_field(
        &self,
        fields: &mut IndexSet<StructField>,
        new_field: StructField,
    ) -> bool {
        // Check if a field with the same name (xref) already exists
        if let Some(existing_field) = fields.iter().find(|f| f.xref == new_field.xref) {
            // We have a duplicate field name - check if it's the exact same field
            if existing_field.ty != new_field.ty {
                // Different types - this is an error
                let field_name = self.ctx.get_ident(new_field.xref);
                let existing_type = self.get_type_ref_string(existing_field.ty);
                let new_type = self.get_type_ref_string(new_field.ty);

                self.dcx().emit_err_diag(DuplicateField {
                    span: new_field.span,
                    field_name: field_name.to_string().into(),
                    first_definition_span: existing_field.span,
                    first_definition_type: existing_type,
                    second_definition_type: new_type,
                });
                return false;
            }
            // Same type - this is allowed (e.g., multiple StructRefs with the same field)
            return true;
        }

        // No conflict - insert the field
        fields.insert(new_field);
        true
    }
}

// `check` routines.
impl<'cx> TypeChecker<'cx> {
    pub(super) fn check(&mut self) -> Result<(), ErrorGuaranteed> {
        let sorted = self.deps.topo_sorted();
        for &id in sorted {
            if let Err(err) = self.check_symbol(id) {
                self.num_errs = self.num_errs.saturating_add(1);
                if self.num_errs > self.max_errs {
                    return Err(err);
                }
            }
        }
        match self.dcx().has_errors() {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn check_symbol(&mut self, sym_id: SymbolId) -> Result<(), ErrorGuaranteed> {
        let sym = self.symbols.get(sym_id);
        match sym.kind {
            SymbolKind::Item(v) => self.check_item(v, sym_id, sym),
            SymbolKind::Type(v) => self.check_type(v, sym_id),
        }
        Ok(())
    }

    fn check_item(&mut self, item: symtab::ItemKind, sym_id: SymbolId, _sym: &'cx Symbol) {
        use symtab::ItemKind;
        match item {
            ItemKind::Func(id) => self.check_func(id, sym_id),
            ItemKind::Action(id) => self.check_action(id, sym_id),
            ItemKind::GlobalVar(id) => self.check_global_var(id, sym_id),
            ItemKind::Fact(id) => {
                self.check_fact(id, sym_id);
            }
            ItemKind::FinishFunc(id) => self.check_finish_func(id, sym_id),
            ItemKind::Cmd(id) => {
                self.check_cmd(id, sym_id);
            }
            ItemKind::Effect(id) => {
                self.check_effect(id, sym_id);
            }
            ItemKind::FfiFunc(id) => self.check_ffi_func(id, sym_id),
            ItemKind::FfiModule(id) => self.check_ffi_module(id, sym_id),
            ItemKind::FfiImport(id) => self.check_ffi_import(id, sym_id),
            ItemKind::FfiStruct(id) => self.check_ffi_struct(id, sym_id),
            ItemKind::FfiEnum(id) => self.check_ffi_enum(id, sym_id),
            // Local variables are handled inside top-level
            // items.
            ItemKind::LocalVar(_) => {}
        }
    }

    fn check_func(&mut self, id: FuncId, sym_id: SymbolId) {
        let FuncDef {
            id: _,
            span: _,
            ident: _,
            result,
            body,
        } = self.hir.lookup(id);

        let body_data = self.hir.lookup(*body);
        let Body {
            id: _,
            span,
            params,
            stmts,
            returns: _,
        } = body_data;

        let func = ItemFunc {
            symbol: sym_id,
            params: params.iter().map(|&id| self.check_param(id)).collect(),
            return_type: self.check_vtype(*result),
        };
        self.ctx.intern_item(ItemKind::Func(func.clone()));

        let mut last_stmt_type = self.ctx.builtins.unit;
        for &id in stmts {
            last_stmt_type = self.check_stmt(id);
        }
        let body_type = last_stmt_type;

        if self.unify(body_type, func.return_type).is_none() {
            self.dcx().emit_err_diag(TypeMismatch {
                span: *span,
                expected: self.get_type_ref_string(func.return_type),
                found: self.get_type_ref_string(body_type),
                reason: Some(self.hir.lookup_span(*result)),
            });
        }
    }

    fn check_action(&mut self, id: ActionId, sym_id: SymbolId) {
        let ActionDef {
            id: _,
            span: _,
            ident: _,
            body,
        } = self.hir.lookup(id);

        let body_data = self.hir.lookup(*body);
        let Body {
            id: _,
            span: _,
            params,
            stmts,
            returns: _,
        } = body_data;

        let action = ItemAction {
            symbol: sym_id,
            params: params.iter().map(|&id| self.check_param(id)).collect(),
        };
        self.ctx.intern_item(ItemKind::Action(action));

        for &id in stmts {
            self.check_stmt(id);
        }
    }

    fn check_global_var(&mut self, id: GlobalId, sym_id: SymbolId) {
        let GlobalLetDef {
            id: _,
            span: _,
            ident: _,
            expr,
        } = self.hir.lookup(id);

        let expr_type = self.check_expr(*expr);

        // Store the global variable type for lookups
        if let Some(type_ref) = self.env.type_symbols.get_mut(&sym_id) {
            *type_ref = expr_type;
        } else {
            self.env.type_symbols.insert(sym_id, expr_type);
        }
    }

    fn check_fact(&mut self, id: FactId, sym_id: SymbolId) -> ItemRef {
        let FactDef {
            id: _,
            span: _,
            ident: _,
            keys,
            vals,
            struct_id: _,
        } = self.hir.lookup(id);

        let keys = keys
            .iter()
            .map(|&key_id| {
                let key = self.hir.lookup(key_id);
                FactField {
                    xref: self.hir.lookup_ident_ref(key.ident),
                    ty: self.check_vtype(key.ty),
                }
            })
            .collect();

        let vals = vals
            .iter()
            .map(|&val_id| {
                let val = self.hir.lookup(val_id);
                FactField {
                    xref: self.hir.lookup_ident_ref(val.ident),
                    ty: self.check_vtype(val.ty),
                }
            })
            .collect();

        let fact = ItemFact {
            symbol: sym_id,
            keys,
            vals,
        };
        self.ctx.intern_item(ItemKind::Fact(fact))
    }

    fn check_finish_func(&mut self, id: FinishFuncId, sym_id: SymbolId) {
        let FinishFuncDef {
            id: _,
            span: _,
            ident: _,
            body,
        } = self.hir.lookup(id);

        let body_data = self.hir.lookup(*body);
        let Body {
            id: _,
            span: _,
            params,
            stmts,
            returns: _,
        } = body_data;

        let finish_func = ItemFinishFunc {
            symbol: sym_id,
            params: params.iter().map(|&id| self.check_param(id)).collect(),
            return_type: None, // Finish functions typically don't return values
        };
        self.ctx.intern_item(ItemKind::FinishFunc(finish_func));

        for &id in stmts {
            self.check_stmt(id);
        }
    }

    fn check_cmd(&mut self, id: CmdId, sym_id: SymbolId) -> ItemRef {
        // Extract fields directly from the command definition
        let cmd_def = self.hir.lookup(id);

        let mut fields = IndexSet::new();

        for &field_id in &cmd_def.fields {
            let field = self.hir.lookup(field_id);
            match &field.kind {
                CmdFieldKind::Field { ident, ty } => {
                    let new_field = StructField {
                        xref: self.hir.lookup_ident_ref(*ident),
                        ty: self.check_vtype(*ty),
                        span: self.hir.lookup_span(*ident),
                    };
                    self.check_and_insert_field(&mut fields, new_field);
                }
                CmdFieldKind::StructRef(struct_ident) => {
                    // Look up the referenced struct and include its fields with conflict detection
                    let referenced_type = self.lookup_type(*struct_ident);
                    if let TypeKind::Struct(ref_struct) = referenced_type.kind {
                        for field in ref_struct.fields.iter() {
                            // Create a new field with the span of the StructRef for better error messages
                            let imported_field = StructField {
                                xref: field.xref,
                                ty: field.ty,
                                span: self.hir.lookup_span(*struct_ident), // Use StructRef location for conflicts
                            };
                            self.check_and_insert_field(&mut fields, imported_field);
                        }
                    }
                }
            }
        }

        let cmd = ItemCmd {
            symbol: sym_id,
            fields,
        };
        self.ctx.intern_item(ItemKind::Cmd(cmd))
    }

    fn check_effect(&mut self, id: EffectId, sym_id: SymbolId) -> ItemRef {
        // Extract fields directly from the effect definition
        let effect_def = self.hir.lookup(id);

        let mut fields = IndexSet::new();

        for &field_id in &effect_def.items {
            let field = self.hir.lookup(field_id);
            match &field.kind {
                EffectFieldKind::Field { ident, ty } => {
                    let new_field = StructField {
                        xref: self.hir.lookup_ident_ref(*ident),
                        ty: self.check_vtype(*ty),
                        span: self.hir.lookup_span(*ident),
                    };
                    self.check_and_insert_field(&mut fields, new_field);
                }
                EffectFieldKind::StructRef(struct_ident) => {
                    // Look up the referenced struct and include its fields with conflict detection
                    let referenced_type = self.lookup_type(*struct_ident);
                    if let TypeKind::Struct(ref_struct) = referenced_type.kind {
                        for field in ref_struct.fields.iter() {
                            // Create a new field with the span of the StructRef for better error messages
                            let imported_field = StructField {
                                xref: field.xref,
                                ty: field.ty,
                                span: self.hir.lookup_span(*struct_ident), // Use StructRef location for conflicts
                            };
                            self.check_and_insert_field(&mut fields, imported_field);
                        }
                    }
                }
            }
        }

        let effect = ItemEffect {
            symbol: sym_id,
            fields,
        };
        self.ctx.intern_item(ItemKind::Effect(effect))
    }

    fn check_ffi_func(&mut self, _id: FfiFuncId, sym_id: SymbolId) {
        // FFI functions need to be checked for their parameter and return types
        // For now, we'll create a basic FFI function item in the type environment
        let ffi_func = ItemFfiFunc {
            symbol: sym_id,
            params: IndexSet::new(), // TODO: Extract from FFI function definition
            return_type: self.ctx.builtins.infer, // TODO: Extract from FFI function definition
        };
        self.ctx.intern_item(ItemKind::FfiFunc(ffi_func));
    }

    fn check_ffi_module(&mut self, _id: FfiModuleId, sym_id: SymbolId) {
        // FFI modules are mostly structural - they don't need complex type checking
        let ffi_module = ItemFfiModule { symbol: sym_id };
        self.ctx.intern_item(ItemKind::FfiModule(ffi_module));
    }

    fn check_ffi_import(&mut self, _id: FfiImportId, _sym_id: SymbolId) {
        // FFI imports are handled by the import system, no additional type checking needed
        // For now, we don't need to create any items for imports
    }

    fn check_ffi_struct(&mut self, _id: FfiStructId, _sym_id: SymbolId) {
        // FFI structs should be handled by the type checking system
        // They would need to be added to the type environment, not the item environment
        // This is a design choice - FFI structs could be considered types rather than items
    }

    fn check_ffi_enum(&mut self, _id: FfiEnumId, _sym_id: SymbolId) {
        // Similar to FFI structs, FFI enums are types, not items
        // They should be handled in the type checking pass
    }

    fn check_type(&mut self, type_kind: symtab::TypeKind, sym_id: SymbolId) {
        use symtab::TypeKind;
        match type_kind {
            TypeKind::Struct(id, _origin) => {
                let type_ref = self.check_struct(id, sym_id);
                self.env.type_symbols.insert(sym_id, type_ref);
            }
            TypeKind::Enum(id) => {
                let type_ref = self.check_enum(id, sym_id);
                self.env.type_symbols.insert(sym_id, type_ref);
            }
        }
    }

    fn check_struct(&mut self, id: StructId, sym_id: SymbolId) -> TypeRef {
        let StructDef {
            id: _,
            span: _,
            ident: _,
            items,
            origin,
        } = self.hir.lookup(id);

        let mut struct_fields = IndexSet::new();

        for &id in items {
            let field = self.hir.lookup(id);
            match &field.kind {
                hir::StructFieldKind::Field { ident, ty } => {
                    let new_field = StructField {
                        xref: self.hir.lookup_ident_ref(*ident),
                        ty: self.check_vtype(*ty),
                        span: self.hir.lookup_span(*ident),
                    };
                    self.check_and_insert_field(&mut struct_fields, new_field);
                }
                hir::StructFieldKind::StructRef(struct_ident) => {
                    // Look up the referenced struct and include its fields with conflict detection
                    let referenced_type = self.lookup_type(*struct_ident);
                    if let TypeKind::Struct(ref_struct) = referenced_type.kind {
                        for field in ref_struct.fields.iter() {
                            // Create a new field with the span of the StructRef for better error messages
                            let imported_field = StructField {
                                xref: field.xref,
                                ty: field.ty,
                                span: self.hir.lookup_span(*struct_ident), // Use StructRef location for conflicts
                            };
                            self.check_and_insert_field(&mut struct_fields, imported_field);
                        }
                    }
                }
            }
        }

        let type_struct_origin = match origin {
            hir::StructOrigin::Explicit => TypeStructOrigin::Explicit,
            hir::StructOrigin::AutoCmd(cmd_id) => {
                // Delegate to check_cmd to create the command item
                let item_ref = self.check_cmd(*cmd_id, sym_id);
                TypeStructOrigin::Auto(item_ref)
            }
            hir::StructOrigin::AutoEffect(effect_id) => {
                // Delegate to check_effect to create the effect item
                let item_ref = self.check_effect(*effect_id, sym_id);
                TypeStructOrigin::Auto(item_ref)
            }
            hir::StructOrigin::AutoFact(fact_id) => {
                // Delegate to check_fact to create the fact item
                let item_ref = self.check_fact(*fact_id, sym_id);
                TypeStructOrigin::Auto(item_ref)
            }
        };

        let type_struct = TypeStruct {
            symbol: sym_id,
            fields: struct_fields,
            origin: type_struct_origin,
        };

        self.ctx.intern_type(TypeKind::Struct(type_struct))
    }

    fn check_enum(&mut self, id: EnumId, sym_id: SymbolId) -> TypeRef {
        let EnumDef {
            id: _,
            span: _,
            ident: _,
            variants,
        } = self.hir.lookup(id);

        let variants = variants
            .iter()
            .map(|&ident| EnumVariant {
                xref: self.hir.lookup_ident_ref(ident),
            })
            .collect();

        let type_enum = TypeEnum {
            symbol: sym_id,
            variants,
        };

        self.ctx.intern_type(TypeKind::Enum(type_enum))
    }

    /// Checks a [`Param`].
    fn check_param(&self, id: ParamId) -> TypeRef {
        let Param {
            id: _,
            span: _,
            ident: _,
            ty,
        } = self.hir.lookup(id);
        self.check_vtype(*ty)
    }

    /// Type checks a [`VType`].
    fn check_vtype(&self, id: VTypeId) -> TypeRef {
        let vtype = self.hir.lookup(id);
        match &vtype.kind {
            VTypeKind::String => self.ctx.builtins.string,
            VTypeKind::Bytes => self.ctx.builtins.bytes,
            VTypeKind::Int => self.ctx.builtins.int,
            VTypeKind::Bool => self.ctx.builtins.bool,
            VTypeKind::Id => self.ctx.builtins.id,
            VTypeKind::Struct(id) => self.lookup_type(*id).xref,
            VTypeKind::Enum(id) => self.lookup_type(*id).xref,
            VTypeKind::Optional(id) => self.ctx.intern_type(TypeKind::Optional(TypeOptional {
                inner: Some(self.check_vtype(*id)),
            })),
        }
    }

    /// Type checks an expr.
    fn check_expr(&self, expr: ExprId) -> TypeRef {
        let Expr {
            id: _,
            span: _,
            kind,
            pure: _,
            returns: _,
        } = self.hir.lookup(expr);
        match kind {
            ExprKind::Lit(lit) => self.check_lit(lit),
            ExprKind::Intrinsic(v) => self.check_intrinsic(v),
            ExprKind::FunctionCall(v) => self.check_function_call_expr(v),
            ExprKind::ForeignFunctionCall(v) => self.check_foreign_function_call_expr(v),
            ExprKind::Identifier(ident) => self.check_identifier(*ident),
            ExprKind::EnumRef(v) => self.check_enum_ref(v),
            ExprKind::Binary(op, left, right) => self.check_bin_op(*op, *left, *right),
            ExprKind::Unary(op, operand) => self.check_unary_op(*op, *operand),
            ExprKind::Dot(expr, ident) => self.check_dot(*expr, *ident),
            ExprKind::Is(expr, is_some) => self.check_is(*expr, *is_some),
            ExprKind::Block(block_id, expr_id) => self.check_block_expr(*block_id, *expr_id),
            ExprKind::Substruct(base, target) => self.check_substruct(*base, *target),
            ExprKind::Match(expr) => self.check_match(expr),
            ExprKind::Ternary(ternary) => self.check_ternary(ternary),
            ExprKind::Cast(expr, ident) => self.check_cast(*expr, *ident),
        }
    }

    /// Checks that `expr` has the expected type and returns the
    /// resulting type.
    ///
    /// `reason` is the reason why `expr` must have a particular
    /// type.
    fn check_expr_is_ty(&self, expr: ExprId, expect: TypeRef, reason: Option<Span>) -> TypeRef {
        let found = self.check_expr(expr);
        if let Some(result) = self.unify(found, expect) {
            return result;
        }
        self.dcx().emit_err_diag(TypeMismatch {
            span: self.hir.lookup_span(expr),
            expected: self.get_type_ref_string(expect),
            found: self.get_type_ref_string(found),
            reason,
        });
        self.ctx.builtins.error
    }

    /// Type checks a [`Lit`].
    fn check_lit(&self, lit: &'cx Lit) -> TypeRef {
        let Lit { kind } = lit;
        match kind {
            LitKind::Int(_) => self.ctx.builtins.int,
            LitKind::String(_) => self.ctx.builtins.string,
            LitKind::Bool(_) => self.ctx.builtins.bool,
            LitKind::Optional(expr) => match expr {
                Some(expr) => {
                    let inner = self.check_expr(*expr);
                    self.ctx
                        .intern_type(TypeKind::Optional(TypeOptional { inner: Some(inner) }))
                }
                None => self.ctx.builtins.none,
            },
            LitKind::NamedStruct(v) => self.check_lit_named_struct(v),
            LitKind::Fact(v) => self.check_lit_fact(v),
        }
    }

    /// Type checks a [`NamedStruct`].
    fn check_lit_named_struct(&self, st: &'cx NamedStruct) -> TypeRef {
        let NamedStruct { ident, fields } = st;

        let Type { xref, kind } = self.lookup_type(*ident);
        let TypeKind::Struct(st) = kind else {
            let name = self.hir.lookup_ident(*ident);
            let mut span = MultiSpan::from_span(self.hir.lookup_span(*ident), "expected struct");
            if let Some(sym_id) = kind.symbol_id() {
                // TODO(eric): Should this be a note?
                span.push_label(
                    self.symbols.get_span(sym_id),
                    format!("`{name}` is defined here"),
                );
            }
            self.dcx()
                .emit_span_err(span, format!("`{name}` is not a struct"));
            return self.ctx.builtins.error;
        };

        for &StructFieldExpr { ident, expr } in fields {
            let expect = match self.find_struct_field(st, ident) {
                Some(field) => field.ty,
                None => return self.ctx.builtins.error,
            };
            self.check_expr_is_ty(expr, expect, Some(self.hir.lookup_span(ident)));
        }

        xref
    }

    /// Type checks a [`FactLiteral`].
    fn check_lit_fact(&self, fact: &'cx FactLiteral) -> TypeRef {
        let FactLiteral { ident, keys, vals } = fact;

        let item = self.lookup_item(*ident);
        let ItemKind::Fact(fact) = item.kind else {
            let name = self.hir.lookup_ident(*ident);
            let mut span = MultiSpan::from_span(self.hir.lookup_span(*ident), "expected fact");
            // TODO(eric): Should this be a note?
            span.push_label(
                self.symbols.get_span(item.kind.symbol_id()),
                format!("`{name}` is defined here"),
            );
            self.dcx()
                .emit_span_err(span, format!("`{name}` is not a fact"));
            return self.ctx.builtins.error;
        };

        for &FactFieldExpr { ident, expr } in keys {
            let ty = match self.find_fact_key(fact, ident) {
                Some(field) => field.ty,
                None => return self.ctx.builtins.error,
            };
            match expr {
                hir::FactField::Expr(expr) => {
                    self.check_expr_is_ty(expr, ty, Some(self.hir.lookup_span(ident)));
                }
                hir::FactField::Bind => {}
            }
        }

        for &FactFieldExpr { ident, expr } in vals {
            let ty = match self.find_fact_val(fact, ident) {
                Some(field) => field.ty,
                None => return self.ctx.builtins.error,
            };
            match expr {
                hir::FactField::Expr(expr) => {
                    self.check_expr_is_ty(expr, ty, Some(self.hir.lookup_span(ident)));
                }
                hir::FactField::Bind => {}
            }
        }

        // Get the fact ID from the symbol to look up the struct type
        let fact_symbol = self.symbols.get(item.kind.symbol_id());
        let SymbolKind::Item(symtab::ItemKind::Fact(fact_id)) = fact_symbol.kind else {
            self.dcx().emit_span_bug(
                MultiSpan::from_span(fact_symbol.span, "fact symbol should have fact kind"),
                "internal compiler error",
            );
        };
        self.get_struct_type_for_fact(fact_id)
    }

    /// Attempts to find the fact field for `key`.
    ///
    /// It emits an error and returns `None` if the field is not
    /// found.
    fn find_fact_key(&self, item: &'cx ItemFact, key: IdentId) -> Option<&'cx FactField> {
        let key_xref = self.hir.lookup_ident_ref(key);
        if let Some(field) = item.find_key(key_xref) {
            return Some(field);
        }
        let fact_name = self.get_sym_name(item.symbol);
        let field_name = self.ctx.get_ident(key_xref);
        let span = MultiSpan::from_span(
            self.hir.lookup_span(key),
            format!("fact `{fact_name}` does not have key `{field_name}`"),
        );
        self.dcx().emit_span_err(span, "unknown field");
        None
    }

    /// Attempts to find the fact field for `val`.
    ///
    /// It emits an error and returns `None` if the field is not
    /// found.
    fn find_fact_val(&self, item: &'cx ItemFact, val: IdentId) -> Option<&'cx FactField> {
        let xref = self.hir.lookup_ident_ref(val);
        if let Some(field) = item.find_val(xref) {
            return Some(field);
        }
        let fact_name = self.get_sym_name(item.symbol);
        let field_name = self.ctx.get_ident(xref);
        let span = MultiSpan::from_span(
            self.hir.lookup_span(val),
            format!("fact `{fact_name}` does not have value `{field_name}`"),
        );
        self.dcx().emit_span_err(span, "unknown field");
        None
    }

    /// Type checks an [`EnumRef`].
    fn check_enum_ref(&self, xref: &'cx EnumRef) -> TypeRef {
        let EnumRef { ident, value } = xref;

        let Type { xref, kind } = self.lookup_type(*ident);
        let TypeKind::Enum(enum_) = kind else {
            let name = self.hir.lookup_ident(*ident);
            let mut span = MultiSpan::from_span(self.hir.lookup_span(*ident), "expected enum");
            span.push_label(
                self.hir.lookup_span(*value),
                "this is a reference to an enum variant",
            );
            if let Some(sym_id) = kind.symbol_id() {
                // TODO(eric): Should this be a note?
                span.push_label(
                    self.symbols.get_span(sym_id),
                    format!("`{name}` is defined here"),
                );
            }
            self.dcx()
                .emit_span_err(span, format!("`{name}` is not an enum"));
            return self.ctx.builtins.error;
        };

        let variant_xref = self.hir.lookup_ident_ref(*value);
        if !enum_.has_variant(variant_xref) {
            let enum_name = self.hir.lookup_ident(*ident);
            let variant_name = self.ctx.get_ident(variant_xref);
            let span = MultiSpan::from_span(
                self.hir.lookup_span(*value),
                format!("enum `{enum_name}` does not have variant `{variant_name}`"),
            );
            self.dcx().emit_span_err(span, "unknown variant");
            return self.ctx.builtins.error;
        }

        xref
    }

    /// Type checks a binary operation.
    fn check_bin_op(&self, op: BinOp, left: ExprId, right: ExprId) -> TypeRef {
        let expect = match op {
            BinOp::Add | BinOp::Sub | BinOp::Gt | BinOp::Lt | BinOp::GtEq | BinOp::LtEq => {
                self.check_expr_is_ty(left, self.ctx.builtins.int, None)
            }
            BinOp::And | BinOp::Or => self.check_expr_is_ty(left, self.ctx.builtins.bool, None),
            BinOp::Eq | BinOp::Neq => self.check_expr(right),
        };
        self.check_expr_is_ty(right, expect, Some(self.hir.lookup_span(left)))
    }

    /// Type checks a unary operation.
    fn check_unary_op(&self, op: UnaryOp, expr: ExprId) -> TypeRef {
        match op {
            UnaryOp::Not => self.check_expr_is_ty(expr, self.ctx.builtins.bool, None),
            UnaryOp::Neg => self.check_expr_is_ty(expr, self.ctx.builtins.int, None),
            UnaryOp::Check => self.check_expr_is_ty(expr, self.ctx.builtins.bool, None),
            UnaryOp::CheckUnwrap | UnaryOp::Unwrap => {
                let expr_ty = self.check_expr(expr);
                match self.ctx.get_type(expr_ty) {
                    TypeKind::Optional(TypeOptional { inner: Some(id) }) => *id,
                    // Cannot unwrap a `None`.
                    TypeKind::Optional(TypeOptional { inner: None }) => {
                        let span = MultiSpan::from_span(
                            self.hir.lookup(expr).span,
                            "cannot unwrap `None`",
                        );
                        self.dcx().emit_span_err(span, "type mismatch");
                        self.ctx.builtins.error
                    }
                    // Cannot unwrap a non-optional type.
                    found => {
                        self.dcx().emit_err_diag(TypeMismatch {
                            span: self.hir.lookup(expr).span,
                            expected: "optional".into(),
                            found: self.get_type_string(found),
                            reason: None,
                        });
                        self.ctx.builtins.error
                    }
                }
            }
        }
    }

    /// Type checks a "dot" operation (struct access).
    fn check_dot(&self, expr: ExprId, ident: IdentId) -> TypeRef {
        let expr_span = self.hir.lookup_span(expr);
        let expr_ty = self.check_expr(expr);

        let st = match self.ctx.get_type(expr_ty) {
            ty @ (TypeKind::String
            | TypeKind::Bytes
            | TypeKind::Int
            | TypeKind::Bool
            | TypeKind::Id) => {
                let span = MultiSpan::from_span(expr_span, "");
                self.dcx().emit_span_err(
                    span,
                    format!(
                        "`{}` is a primitive type and does not have fields",
                        self.get_type_string(ty)
                    ),
                );
                return self.ctx.builtins.error;
            }
            TypeKind::Optional(TypeOptional { inner }) => {
                let span = MultiSpan::from_span(expr_span, "optional types do not have fields");
                let mut err = self.dcx().create_err("type mismatch").with_span(span);
                if let Some(TypeKind::Struct(_)) = inner.map(|id| self.ctx.get_type(id)) {
                    err = err.with_note("try unwrapping the optional first");
                }
                err.emit();
                return self.ctx.builtins.error;
            }
            TypeKind::Struct(st) => st,
            TypeKind::Enum(TypeEnum { symbol, .. }) => {
                let name = {
                    let sym = self.symbols.get(*symbol);
                    let xref = self.hir.lookup(sym.ident).xref;
                    self.ctx.get_ident(xref)
                };
                let span = MultiSpan::from_span(expr_span, "");
                self.dcx().emit_span_err(
                    span,
                    format!("`{name}` is an enum and does not have fields"),
                );
                return self.ctx.builtins.error;
            }
            TypeKind::TypeVar(_) => self
                .dcx()
                .emit_bug("expression should not resolve to a type variable"),
            TypeKind::Unit => self
                .dcx()
                .emit_bug("expression should not resolve to a unit type"),
            TypeKind::Error => return self.ctx.builtins.error,
            TypeKind::Infer => {
                // Cannot access fields of an inferred type
                let span = MultiSpan::from_span(expr_span, "cannot access fields of inferred type");
                self.dcx().emit_span_err(span, "type inference failed");
                return self.ctx.builtins.error;
            }
            TypeKind::Never => return self.ctx.builtins.never,
        };

        match self.find_struct_field(st, ident) {
            Some(field) => field.ty,
            None => self.ctx.builtins.error,
        }
    }

    /// Type checks a [`Ternary`].
    fn check_ternary(&self, ternary: &'cx Ternary) -> TypeRef {
        let Ternary {
            cond,
            true_expr,
            false_expr,
        } = ternary;

        self.check_expr_is_ty(*cond, self.ctx.builtins.bool, None);

        let true_type = self.check_expr(*true_expr);
        let false_type = self.check_expr(*false_expr);

        let Some(ty) = self.unify(true_type, false_type) else {
            self.dcx().emit_err_diag(TernaryBranchTypeMismatch {
                span: self.hir.lookup_span(*false_expr),
                expected: self.get_type_ref_string(true_type),
                found: self.get_type_ref_string(false_type),
                reason: Some(self.hir.lookup_span(*true_expr)),
            });
            return self.ctx.builtins.error;
        };
        ty
    }

    /// Type checks a struct substruct expression.
    fn check_substruct(&self, expr: ExprId, ident: IdentId) -> TypeRef {
        let base_type = self.check_expr(expr);
        let TypeKind::Struct(base_st) = self.ctx.get_type(base_type) else {
            let span = MultiSpan::from_span(
                self.hir.lookup_span(expr),
                format!(
                    "expected struct, found `{}`",
                    self.get_type_ref_string(base_type)
                ),
            );
            self.dcx()
                .emit_span_err(span, "cannot apply substruct to non-struct type");
            return self.ctx.builtins.error;
        };

        let Type { xref, kind } = self.lookup_type(ident);
        let TypeKind::Struct(target_st) = kind else {
            let name = self.hir.lookup_ident(ident);
            let mut span = MultiSpan::from_span(self.hir.lookup_span(ident), "expected struct");
            if let Some(sym_id) = kind.symbol_id() {
                // TODO(eric): Should this be a note?
                span.push_label(
                    self.symbols.get_span(sym_id),
                    format!("`{name}` is defined here"),
                );
            }
            self.dcx()
                .emit_span_err(span, format!("`{name}` is not a struct"));
            return self.ctx.builtins.error;
        };

        if let Some(err) =
            self.check_is_substruct_of(target_st, base_st, self.hir.lookup_span(ident))
        {
            err.emit();
            self.ctx.builtins.error
        } else {
            xref
        }
    }

    /// Checks whether `target` is a substruct of `base`.
    fn check_is_substruct_of(
        &self,
        target: &TypeStruct,
        base: &TypeStruct,
        target_span: Span,
    ) -> Option<Diag<'cx>> {
        let mut span = MultiSpan::new();

        // Fields in target but not in base
        for field in target.fields.difference(&base.fields) {
            let field_name = self.ctx.get_ident(field.xref);
            let base_name = self.get_sym_name(base.symbol);
            span.push_label(
                field.span,
                format!("field `{field_name}` not found in `{base_name}`"),
            );
        }

        // Find fields in both but with different types
        for field in target.fields.intersection(&base.fields) {
            let base_field = base
                .fields
                .get(field)
                .unwrap_or_bug(self.dcx(), "field in intersection not found in base");

            if field.ty == base_field.ty {
                continue;
            }

            let field_name = self.ctx.get_ident(field.xref);
            let target_type = self.get_type_ref_string(field.ty);
            let base_type = self.get_type_ref_string(base_field.ty);
            let target_name = self.get_sym_name(target.symbol);
            let base_name = self.get_sym_name(base.symbol);
            let msg = format!(
                "field `{field_name}` has type `{target_type}` in `{target_name}`, \
                     but `{base_type}` in `{base_name}`"
            );
            span.push_label(field.span, msg);
        }

        if span.is_empty() {
            return None;
        }

        span.push_primary(target_span, "not a subset");
        let target_name = self.get_sym_name(target.symbol);
        let base_name = self.get_sym_name(base.symbol);
        let diag = self
            .dcx()
            .create_err(format!(
                "struct `{target_name}` is not a subset of struct `{base_name}`"
            ))
            .with_span(span);
        Some(diag)
    }

    /// Type checks an `is` expression.
    fn check_is(&self, expr: ExprId, _is_some: bool) -> TypeRef {
        let ty = self.check_expr(expr);
        let TypeKind::Optional(_) = self.ctx.get_type(ty) else {
            let span = MultiSpan::from_span(
                self.hir.lookup_span(expr),
                format!(
                    "expected optional type, found `{}`",
                    self.get_type_ref_string(ty)
                ),
            );
            self.dcx()
                .emit_span_err(span, "`is` expects an `optional` expression");
            return self.ctx.builtins.error;
        };
        self.ctx.builtins.bool
    }

    /// Type checks an identifier.
    fn check_identifier(&self, ident: IdentId) -> TypeRef {
        let sym_id = self.symbols.resolve_item(ident);

        // Check local variables first
        if let Some(&local_type) = self.local_vars.borrow().get(&sym_id) {
            return local_type;
        }

        // Check global type environment
        *self
            .env
            .type_symbols
            .get(&sym_id)
            .unwrap_or_bug(self.dcx(), "type not found")
    }

    /// Type checks a cast expression.
    fn check_cast(&self, expr: ExprId, ident: IdentId) -> TypeRef {
        let source_type = self.check_expr(expr);

        let TypeKind::Struct(source_st) = self.ctx.get_type(source_type) else {
            let span = MultiSpan::from_span(
                self.hir.lookup_span(expr),
                format!(
                    "expected struct, found `{}`",
                    self.get_type_ref_string(source_type)
                ),
            );
            self.dcx()
                .emit_span_err(span, "cannot cast non-struct type");
            return self.ctx.builtins.error;
        };

        let Type { xref, kind } = self.lookup_type(ident);
        let TypeKind::Struct(target_st) = kind else {
            let name = self.hir.lookup_ident(ident);
            let mut span = MultiSpan::from_span(self.hir.lookup_span(ident), "expected struct");
            if let Some(sym_id) = kind.symbol_id() {
                // TODO(eric): Should this be a note?
                span.push_label(
                    self.symbols.get_span(sym_id),
                    format!("`{name}` is defined here"),
                );
            }
            self.dcx()
                .emit_span_err(span, format!("`{name}` is not a struct"));
            return self.ctx.builtins.error;
        };

        if let Some(err) =
            self.check_structs_isomorphic(source_st, target_st, self.hir.lookup_span(ident))
        {
            err.emit();
            self.ctx.builtins.error
        } else {
            xref
        }
    }

    /// Checks if two structs are isomorphic (same field names
    /// and types).
    fn check_structs_isomorphic(
        &self,
        source: &TypeStruct,
        target: &TypeStruct,
        target_span: Span,
    ) -> Option<Diag<'cx>> {
        let mut span = MultiSpan::new();

        // Fields in source but not in target
        for field in source.fields.difference(&target.fields) {
            let field_name = self.ctx.get_ident(field.xref);
            let target_name = self.get_sym_name(target.symbol);
            span.push_label(
                field.span,
                format!("field `{field_name}` not found in `{target_name}`"),
            );
        }

        // Fields in target but not in source
        for field in target.fields.difference(&source.fields) {
            let field_name = self.ctx.get_ident(field.xref);
            let source_name = self.get_sym_name(source.symbol);
            span.push_label(
                field.span,
                format!("field `{field_name}` not found in `{source_name}`"),
            );
        }

        // Find fields in both but with different types.
        for field in source.fields.intersection(&target.fields) {
            let target_field = target
                .fields
                .get(field)
                .unwrap_or_bug(self.dcx(), "field in intersection not found in target");

            if field.ty == target_field.ty {
                continue;
            }

            let field_name = self.ctx.get_ident(field.xref);
            let source_type = self.get_type_ref_string(field.ty);
            let target_type = self.get_type_ref_string(target_field.ty);
            let source_name = self.get_sym_name(source.symbol);
            let target_name = self.get_sym_name(target.symbol);
            let msg = format!(
                "field `{field_name}` has type `{source_type}` in `{source_name}`, \
                     but `{target_type}` in `{target_name}`"
            );
            span.push_label(field.span, msg);
        }

        if span.is_empty() {
            return None;
        }

        span.push_primary(target_span, "not isomorphic");
        let source_name = self.get_sym_name(source.symbol);
        let target_name = self.get_sym_name(target.symbol);
        let diag = self
            .dcx()
            .create_err(format!(
                "struct `{source_name}` cannot be cast to struct `{target_name}`"
            ))
            .with_span(span);
        Some(diag)
    }

    /// Type checks a function call expression.
    fn check_function_call_expr(&self, call: &'cx FunctionCall) -> TypeRef {
        let FunctionCall { ident, args } = call;

        let item = self.lookup_item(*ident);
        let ItemKind::Func(func) = item.kind else {
            let name = self.hir.lookup_ident(*ident);
            let mut span = MultiSpan::from_span(self.hir.lookup_span(*ident), "expected function");
            span.push_label(
                self.symbols.get_span(item.kind.symbol_id()),
                format!("`{name}` is defined here"),
            );
            self.dcx()
                .emit_span_err(span, format!("`{name}` is not a function"));
            return self.ctx.builtins.error;
        };

        // Check argument count
        if args.len() != func.params.len() {
            let span = MultiSpan::from_span(
                self.hir.lookup_span(*ident),
                format!(
                    "expected {} arguments, found {}",
                    func.params.len(),
                    args.len()
                ),
            );
            self.dcx().emit_span_err(span, "argument count mismatch");
            return self.ctx.builtins.error;
        }

        // Check argument types
        for (&arg, &expected_type) in args.iter().zip(func.params.iter()) {
            self.check_expr_is_ty(arg, expected_type, None);
        }

        func.return_type
    }

    /// Type checks a foreign function call expression.
    fn check_foreign_function_call_expr(&self, call: &'cx ForeignFunctionCall) -> TypeRef {
        let ForeignFunctionCall {
            module,
            ident,
            args,
        } = call;

        // First resolve the module
        let module_item = self.lookup_item(*module);
        let ItemKind::FfiModule(_) = module_item.kind else {
            let name = self.hir.lookup_ident(*module);
            let mut span =
                MultiSpan::from_span(self.hir.lookup_span(*module), "expected FFI module");
            span.push_label(
                self.symbols.get_span(module_item.kind.symbol_id()),
                format!("`{name}` is defined here"),
            );
            self.dcx()
                .emit_span_err(span, format!("`{name}` is not an FFI module"));
            return self.ctx.builtins.error;
        };

        // Then resolve the function within the module
        let func_item = self.lookup_item(*ident);
        let ItemKind::FfiFunc(ffi_func) = func_item.kind else {
            let name = self.hir.lookup_ident(*ident);
            let mut span =
                MultiSpan::from_span(self.hir.lookup_span(*ident), "expected FFI function");
            span.push_label(
                self.symbols.get_span(func_item.kind.symbol_id()),
                format!("`{name}` is defined here"),
            );
            self.dcx()
                .emit_span_err(span, format!("`{name}` is not an FFI function"));
            return self.ctx.builtins.error;
        };

        // Check argument count
        if args.len() != ffi_func.params.len() {
            let span = MultiSpan::from_span(
                self.hir.lookup_span(*ident),
                format!(
                    "expected {} arguments, found {}",
                    ffi_func.params.len(),
                    args.len()
                ),
            );
            self.dcx().emit_span_err(span, "argument count mismatch");
            return self.ctx.builtins.error;
        }

        // Check argument types
        for (&arg, &expected_type) in args.iter().zip(ffi_func.params.iter()) {
            self.check_expr_is_ty(arg, expected_type, None);
        }

        ffi_func.return_type
    }

    /// Type checks a block expression.
    fn check_block_expr(&self, block_id: BlockId, expr_id: ExprId) -> TypeRef {
        // First check the block statements
        let _block_type = self.check_block(block_id);

        // Then check the final expression
        // The block expression type is the type of the final expression
        // The _block_type represents the type of statements in the block,
        // but the overall block expression evaluates to expr_type
        self.check_expr(expr_id)
    }

    /// Type checks an intrinsic.
    fn check_intrinsic(&self, intrinsic: &'cx Intrinsic) -> TypeRef {
        match intrinsic {
            Intrinsic::Query(fact) => {
                let fact_type = self.check_lit_fact(fact);
                self.ctx.intern_type(TypeKind::Optional(TypeOptional {
                    inner: Some(fact_type),
                }))
            }
            Intrinsic::FactCount(count_type, _limit, fact) => {
                self.check_lit_fact(fact);
                match count_type {
                    FactCountType::UpTo => self.ctx.builtins.int,
                    FactCountType::AtLeast | FactCountType::AtMost | FactCountType::Exactly => {
                        self.ctx.builtins.bool
                    }
                }
            }
            Intrinsic::Serialize(expr) => {
                let xref = self.check_expr(*expr);
                // `serialize` can only accept `struct` types.
                let TypeKind::Struct(_) = self.ctx.get_type(xref) else {
                    // TODO(eric): Use an "InvalidArg"
                    // diagnostic.
                    self.dcx().emit_err_diag(TypeMismatch {
                        span: self.hir.lookup_span(*expr),
                        expected: "struct".into(),
                        found: self.get_type_ref_string(xref),
                        reason: None,
                    });
                    return self.ctx.builtins.error;
                };
                self.ctx.builtins.bytes
            }
            Intrinsic::Deserialize(expr) => {
                let ty = self.check_expr(*expr);
                if self.unify(ty, self.ctx.builtins.bytes).is_none() {
                    self.dcx().emit_err_diag(TypeMismatch {
                        span: self.hir.lookup_span(*expr),
                        expected: self.get_type_ref_string(self.ctx.builtins.bytes),
                        found: self.get_type_ref_string(ty),
                        reason: None,
                    });
                    return self.ctx.builtins.error;
                }
                self.ctx.builtins.infer
            }
            Intrinsic::Todo => self.ctx.builtins.never,
        }
    }

    /// Type checks a [`MatchExpr`].
    fn check_match(&self, expr: &'cx MatchExpr) -> TypeRef {
        let MatchExpr { scrutinee, arms } = expr;

        let scrutinee = self.check_expr(*scrutinee);

        let mut expr_ty = self.check_expr(arms[0].expr);
        for arm in arms {
            self.check_match_pattern(&arm.pattern, scrutinee);

            let arm_type = self.check_expr(arm.expr);
            let Some(unified) = self.unify(arm_type, expr_ty) else {
                self.dcx().emit_err_diag(MatchArmTypeMismatch {
                    span: self.hir.lookup_span(arm.expr),
                    expected: self.get_type_ref_string(expr_ty),
                    found: self.get_type_ref_string(arm_type),
                    reason: Some(self.hir.lookup_span(arms[0].expr)),
                });
                return self.ctx.builtins.error;
            };
            expr_ty = unified;
        }
        expr_ty
    }

    /// Checks that each expr in the pattern is a literal with
    /// the same type as `ty`.
    fn check_match_pattern(&self, pat: &'cx MatchPattern, ty: TypeRef) {
        let exprs = match pat {
            MatchPattern::Default => return,
            MatchPattern::Values(exprs) => exprs,
        };
        for &id in exprs {
            let value_type = self.check_expr(id);
            if self.unify(value_type, ty).is_none() {
                self.dcx().emit_err_diag(TypeMismatch {
                    span: self.hir.lookup_span(id),
                    expected: self.get_type_ref_string(ty),
                    found: self.get_type_ref_string(value_type),
                    reason: None,
                });
            }
            let expr = self.hir.lookup(id);
            if !matches!(expr.kind, ExprKind::Lit(_)) {
                let span = MultiSpan::from_span(expr.span, "not a literal");
                self.dcx()
                    .emit_span_err(span, "match patterns must be literals");
            }
        }
    }

    /// Type checks a [`Stmt`].
    fn check_stmt(&self, id: StmtId) -> TypeRef {
        let Stmt {
            id: _,
            span: _,
            kind,
            returns: _,
        } = self.hir.lookup(id);
        match kind {
            StmtKind::Let(v) => self.check_let(v),
            StmtKind::Check(v) => self.check_check(v),
            StmtKind::Match(v) => self.check_match_stmt(v),
            StmtKind::If(v) => self.check_if(v),
            StmtKind::Finish(v) => self.check_finish(*v),
            StmtKind::Map(v) => self.check_map(v),
            StmtKind::Return(v) => self.check_return(v),
            StmtKind::ActionCall(v) => self.check_action_call(v),
            StmtKind::Publish(v) => self.check_publish(v),
            StmtKind::Create(v) => self.check_create(v),
            StmtKind::Update(v) => self.check_update(v),
            StmtKind::Delete(v) => self.check_delete(v),
            StmtKind::Emit(v) => self.check_emit(v),
            StmtKind::FunctionCall(v) => self.check_function_call_stmt(v),
            StmtKind::DebugAssert(v) => self.check_debug_assert(v),
        }
    }

    /// Type checks a let statement.
    fn check_let(&self, stmt: &'cx LetStmt) -> TypeRef {
        let LetStmt { ident, expr } = stmt;
        let expr_type = self.check_expr(*expr);

        // Store the variable type in local scope
        let sym_id = self.symbols.resolve_item(*ident);
        self.local_vars.borrow_mut().insert(sym_id, expr_type);

        self.ctx.builtins.unit
    }

    /// Type checks a check statement.
    fn check_check(&self, stmt: &'cx CheckStmt) -> TypeRef {
        let CheckStmt { expr } = stmt;
        self.check_expr_is_ty(*expr, self.ctx.builtins.bool, None);
        self.ctx.builtins.unit
    }

    /// Type checks a match statement.
    fn check_match_stmt(&self, stmt: &'cx MatchStmt) -> TypeRef {
        let MatchStmt { expr, arms } = stmt;
        let scrutinee_type = self.check_expr(*expr);

        for MatchArm { pattern, block } in arms {
            self.check_match_pattern(pattern, scrutinee_type);
            self.check_block(*block);
        }
        self.ctx.builtins.unit
    }

    /// Type checks an if statement.
    fn check_if(&self, stmt: &'cx IfStmt) -> TypeRef {
        let IfStmt {
            branches,
            else_block,
        } = stmt;

        for &IfBranch { expr, block } in branches {
            self.check_expr_is_ty(expr, self.ctx.builtins.bool, None);
            self.check_block(block);
        }

        if let Some(block) = else_block {
            self.check_block(*block);
        }

        self.ctx.builtins.unit
    }

    /// Type checks a finish statement.
    fn check_finish(&self, block_id: BlockId) -> TypeRef {
        self.check_block(block_id)
    }

    /// Type checks a map statement.
    fn check_map(&self, stmt: &'cx MapStmt) -> TypeRef {
        let MapStmt { fact, ident, block } = stmt;
        let fact_type = self.check_lit_fact(fact);

        let sym_id = self.symbols.resolve_item(*ident);
        self.local_vars.borrow_mut().insert(sym_id, fact_type);

        self.check_block(*block)
    }

    /// Type checks a return statement.
    fn check_return(&self, stmt: &'cx ReturnStmt) -> TypeRef {
        let ReturnStmt { expr } = stmt;
        self.check_expr(*expr)
    }

    /// Type checks an action call statement.
    fn check_action_call(&self, stmt: &'cx ActionCall) -> TypeRef {
        let ActionCall { ident, args } = stmt;

        let item = self.lookup_item(*ident);
        let ItemKind::Action(action) = item.kind else {
            let name = self.hir.lookup_ident(*ident);
            let mut span = MultiSpan::from_span(self.hir.lookup_span(*ident), "expected action");
            span.push_label(
                self.symbols.get_span(item.kind.symbol_id()),
                format!("`{name}` is defined here"),
            );
            self.dcx()
                .emit_span_err(span, format!("`{name}` is not an action"));
            return self.ctx.builtins.error;
        };

        // Check argument count
        if args.len() != action.params.len() {
            let span = MultiSpan::from_span(
                self.hir.lookup_span(*ident),
                format!(
                    "expected {} arguments, found {}",
                    action.params.len(),
                    args.len()
                ),
            );
            self.dcx().emit_span_err(span, "argument count mismatch");
            return self.ctx.builtins.error;
        }

        // Check argument types
        for (&arg, &expected_type) in args.iter().zip(action.params.iter()) {
            self.check_expr_is_ty(arg, expected_type, None);
        }

        self.ctx.builtins.unit
    }

    /// Type checks a publish statement.
    fn check_publish(&self, stmt: &'cx Publish) -> TypeRef {
        let Publish { expr } = stmt;
        let ty = self.check_expr(*expr);

        if !self.is_cmd_struct(ty) {
            self.dcx().emit_err_diag(TypeMismatch {
                span: self.hir.lookup_span(*expr),
                expected: "command".into(),
                found: self.get_type_ref_string(ty),
                reason: None,
            });
            return self.ctx.builtins.error;
        };

        self.ctx.builtins.unit
    }

    /// Does `ty` refer to a command's auto-defined struct?
    fn is_cmd_struct(&self, ty: TypeRef) -> bool {
        let kind = self.ctx.get_type(ty);
        let TypeKind::Struct(TypeStruct {
            origin: TypeStructOrigin::Auto(xref),
            ..
        }) = kind
        else {
            return false;
        };
        matches!(self.ctx.get_item(*xref), ItemKind::Cmd(_))
    }

    /// Type checks a create statement.
    fn check_create(&self, stmt: &'cx Create) -> TypeRef {
        let Create { fact } = stmt;
        self.check_lit_fact(fact);
        self.ctx.builtins.unit
    }

    /// Type checks an update statement.
    fn check_update(&self, stmt: &'cx Update) -> TypeRef {
        let Update { fact, to } = stmt;

        let item = self.lookup_item(fact.ident);
        let ItemKind::Fact(fact_item) = item.kind else {
            let name = self.hir.lookup_ident(fact.ident);
            let mut span = MultiSpan::from_span(self.hir.lookup_span(fact.ident), "expected fact");
            span.push_label(
                self.symbols.get_span(item.kind.symbol_id()),
                format!("`{name}` is defined here"),
            );
            self.dcx()
                .emit_span_err(span, format!("`{name}` is not a fact"));
            return self.ctx.builtins.error;
        };

        self.check_lit_fact(fact);

        for &FactFieldExpr { ident, expr } in to {
            let field_type = match self.find_fact_val(fact_item, ident) {
                Some(field) => field.ty,
                None => continue,
            };
            match expr {
                hir::FactField::Expr(expr) => {
                    self.check_expr_is_ty(expr, field_type, Some(self.hir.lookup_span(ident)));
                }
                hir::FactField::Bind => {}
            }
        }

        self.ctx.builtins.unit
    }

    /// Type checks a delete statement.
    fn check_delete(&self, stmt: &'cx Delete) -> TypeRef {
        let Delete { fact } = stmt;
        self.check_lit_fact(fact);
        self.ctx.builtins.unit
    }

    /// Type checks an emit statement.
    fn check_emit(&self, stmt: &'cx Emit) -> TypeRef {
        let Emit { expr } = stmt;
        let ty = self.check_expr(*expr);

        if !self.is_effect_struct(ty) {
            self.dcx().emit_err_diag(TypeMismatch {
                span: self.hir.lookup_span(*expr),
                expected: "effect".into(),
                found: self.get_type_ref_string(ty),
                reason: None,
            });
            return self.ctx.builtins.error;
        };

        self.ctx.builtins.unit
    }

    fn is_effect_struct(&self, ty: TypeRef) -> bool {
        let kind = self.ctx.get_type(ty);
        let TypeKind::Struct(TypeStruct {
            origin: TypeStructOrigin::Auto(xref),
            ..
        }) = kind
        else {
            return false;
        };
        matches!(self.ctx.get_item(*xref), ItemKind::Effect(_))
    }

    /// Type checks a function call statement.
    fn check_function_call_stmt(&self, stmt: &'cx FunctionCall) -> TypeRef {
        let FunctionCall { ident, args } = stmt;

        let item = self.lookup_item(*ident);
        let ItemKind::Func(func) = item.kind else {
            let name = self.hir.lookup_ident(*ident);
            let mut span = MultiSpan::from_span(self.hir.lookup_span(*ident), "expected function");
            span.push_label(
                self.symbols.get_span(item.kind.symbol_id()),
                format!("`{name}` is defined here"),
            );
            self.dcx()
                .emit_span_err(span, format!("`{name}` is not a function"));
            return self.ctx.builtins.error;
        };

        // Check argument count
        if args.len() != func.params.len() {
            let span = MultiSpan::from_span(
                self.hir.lookup_span(*ident),
                format!(
                    "expected {} arguments, found {}",
                    func.params.len(),
                    args.len()
                ),
            );
            self.dcx().emit_span_err(span, "argument count mismatch");
            return self.ctx.builtins.error;
        }

        // Check argument types
        for (&arg, &expected_type) in args.iter().zip(func.params.iter()) {
            self.check_expr_is_ty(arg, expected_type, None);
        }

        self.ctx.builtins.unit
    }

    /// Type checks a debug assert statement.
    fn check_debug_assert(&self, stmt: &'cx DebugAssert) -> TypeRef {
        let DebugAssert { expr } = stmt;
        self.check_expr_is_ty(*expr, self.ctx.builtins.bool, None);
        self.ctx.builtins.unit
    }

    /// Type checks a block.
    fn check_block(&self, block_id: BlockId) -> TypeRef {
        let Block {
            id: _,
            span: _,
            stmts,
            expr,
            returns: _,
        } = self.hir.lookup(block_id);
        let mut last_stmt_type = self.ctx.builtins.unit;
        for &id in stmts {
            last_stmt_type = self.check_stmt(id);
        }
        expr.map(|id| self.check_expr(id)).unwrap_or(last_stmt_type)
    }
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("`if` and `else` have incompatible types")]
struct TernaryBranchTypeMismatch {
    span: Span,
    expected: Cow<'static, str>,
    found: Cow<'static, str>,
    reason: Option<Span>,
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for TernaryBranchTypeMismatch {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let mut span = MultiSpan::from_span(
            self.span,
            format!("expected `{}`, found `{}`", self.expected, self.found),
        );
        if let Some(reason) = self.reason {
            span.push_label(reason, format!("because this is `{}`", self.expected));
        }
        Diag::new(ctx, severity, "`if` and `else` have incompatible types").with_span(span)
    }
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("`match` arms have incompatible types")]
struct MatchArmTypeMismatch {
    span: Span,
    expected: Cow<'static, str>,
    found: Cow<'static, str>,
    reason: Option<Span>,
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for MatchArmTypeMismatch {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let mut span = MultiSpan::from_span(
            self.span,
            format!("expected `{}`, found `{}`", self.expected, self.found),
        );
        if let Some(reason) = self.reason {
            span.push_label(reason, format!("because this is `{}`", self.expected));
        }
        Diag::new(ctx, severity, "`match` arms have incompatible types").with_span(span)
    }
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("mismatched types")]
struct TypeMismatch {
    span: Span,
    expected: Cow<'static, str>,
    found: Cow<'static, str>,
    reason: Option<Span>,
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for TypeMismatch {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let mut span = MultiSpan::from_span(
            self.span,
            format!("expected `{}`, found `{}`", self.expected, self.found),
        );
        if let Some(reason) = self.reason {
            span.push_label(reason, format!("because this is `{}`", self.expected));
        }
        Diag::new(ctx, severity, "mismatched types").with_span(span)
    }
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("duplicate field")]
struct DuplicateField {
    span: Span,
    field_name: Cow<'static, str>,
    first_definition_span: Span,
    first_definition_type: Cow<'static, str>,
    second_definition_type: Cow<'static, str>,
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for DuplicateField {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let mut span = MultiSpan::from_span(
            self.span,
            format!(
                "field `{}` with type `{}` conflicts with previous definition",
                self.field_name, self.second_definition_type
            ),
        );
        span.push_label(
            self.first_definition_span,
            format!(
                "field `{}` with type `{}` first defined here",
                self.field_name, self.first_definition_type
            ),
        );
        Diag::new(ctx, severity, "duplicate field").with_span(span)
    }
}
