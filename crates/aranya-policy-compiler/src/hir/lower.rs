//! Lowers [`Policy`] items into the HIR.

use std::{iter::ExactSizeIterator, marker::PhantomData};

use aranya_policy_ast::{self as ast, AstNode, Policy};
use aranya_policy_module::ffi::{self, ModuleSchema};
use bumpalo::Bump;

use crate::{
    ast::{Index, Item},
    ctx::Ctx,
    hir::{
        hir::{
            ActionArg, ActionArgId, ActionCall, ActionDef, ActionId, BinOp, Block, BlockId,
            CheckStmt, CmdDef, CmdField, CmdFieldId, CmdFieldKind, CmdId, Create, DebugAssert,
            Delete, EffectDef, EffectField, EffectFieldId, EffectFieldKind, Emit, EnumDef, EnumRef,
            Expr, ExprId, ExprKind, FactCountType, FactDef, FactField, FactFieldExpr, FactKey,
            FactKeyId, FactLiteral, FactVal, FactValId, FfiEnumDef, FfiFuncDef, FfiImportDef,
            FfiModuleDef, FfiStructDef, FieldDef, FinishFuncArg, FinishFuncArgId, FinishFuncDef,
            ForeignFunctionCall, FuncArg, FuncArgId, FuncDef, FunctionCall, GlobalLetDef, Hir,
            Ident, IdentId, IfBranch, IfStmt, Intrinsic, LetStmt, Lit, LitKind, MapStmt, MatchArm,
            MatchExpr, MatchExprArm, MatchPattern, MatchStmt, NamedStruct, Publish, Pure,
            ReturnStmt, Span, Stmt, StmtId, StmtKind, StructDef, StructField, StructFieldExpr,
            StructFieldId, StructFieldKind, Ternary, UnaryOp, Update, VType, VTypeId, VTypeKind,
        },
        visit::Visitor,
    },
};

/// Alocates HIR nodes.
#[derive(Debug)]
pub(crate) struct Arena<'ctx> {
    pub bump: Bump,
    pub _marker: PhantomData<&'ctx ()>,
}

impl<'ctx> Arena<'ctx> {
    pub fn new() -> Self {
        Self {
            bump: Bump::new(),
            _marker: PhantomData,
        }
    }

    fn alloc<T: Copy>(&'ctx self, value: T) -> &'ctx T {
        self.bump.alloc(value)
    }

    fn alloc_from_iter<T, I>(&'ctx self, iter: I) -> &'ctx [T]
    where
        T: Copy,
        I: IntoIterator<Item = T>,
        I::IntoIter: ExactSizeIterator,
    {
        self.bump.alloc_slice_fill_iter(iter)
    }
}

#[derive(Debug)]
pub(crate) struct LowerCtx<'ctx> {
    pub ast: &'ctx Index<'ctx>,
    pub arena: &'ctx Arena<'ctx>,
    pub hir: Hir<'ctx>,
}

impl<'ctx> LowerCtx<'ctx> {
    pub(crate) fn lower(self) -> Hir<'ctx> {
        for (id, item) in self.ast {
            match item {
                Item::Action(node) => self.lower_action(&*node),
                Item::Cmd(node) => self.lower_cmd(&*node),
                Item::Effect(node) => self.lower_effect(&*node),
                Item::Enum(node) => self.lower_enum(&*node),
                Item::Fact(node) => self.lower_fact(&*node),
                Item::FinishFunc(node) => self.lower_finish_func(&*node),
                Item::Func(node) => self.lower_func(&*node),
                Item::GlobalLet(node) => self.lower_global_let(&*node),
                Item::Struct(node) => self.lower_struct(&*node),
                Item::FfiFunc(node) => {}
                Item::FfiEnum(node) => {}
                Item::FfiStruct(node) => {}
            }
        }
        self.hir
    }

    /// Lowers a list.
    fn lower_list<I, T, U>(&mut self, list: I) -> &'ctx [T::Result]
    where
        I: IntoIterator<Item = &'ctx T>,
        T: Lower<U> + 'ctx,
    {
        self.arena
            .alloc_from_iter(list.into_iter().map(|item| item.lower(self)))
    }

    /// Lowers an [`ast::Identifier`].
    fn lower_ident(&mut self, ident: &'ctx ast::Identifier) -> Ident {
        let ident = self.hir.intern.intern(ident);
        self.hir.idents.insert_with_key(|id| Ident {
            id,
            span: Span::dummy(),
            ident,
        });
    }

    /// Lowers a [`ast::VType`].
    fn lower_vtype(&mut self, vtype: &'ctx ast::VType) -> &'ctx VType<'ctx> {
        let kind = match vtype {
            ast::VType::String => VTypeKind::String,
            ast::VType::Bytes => VTypeKind::Bytes,
            ast::VType::Int => VTypeKind::Int,
            ast::VType::Bool => VTypeKind::Bool,
            ast::VType::Id => VTypeKind::Id,
            ast::VType::Struct(v) => VTypeKind::Struct(self.lower_ident(v)),
            ast::VType::Enum(v) => VTypeKind::Enum(self.lower_ident(v)),
            ast::VType::Optional(v) => VTypeKind::Optional(v.lower(self)),
        };
        self.hir.types.insert_with_key(|id| {
            self.arena.alloc(VType {
                id,
                span: Span::dummy(),
                kind,
            })
        })
    }

    /// Lowers an [`ast::Expression`].
    fn lower_expr(&mut self, expr: &'ctx ast::Expression) -> &'ctx Expr<'ctx> {
        let kind = match expr {
            ast::Expression::Int(v) => ExprKind::Lit(self.arena.alloc(Lit {
                kind: LitKind::Int(*v),
            })),
            ast::Expression::String(v) => ExprKind::Lit(self.arena.alloc(Lit {
                kind: LitKind::String(v.clone()),
            })),
            ast::Expression::Bool(v) => ExprKind::Lit(self.arena.alloc(Lit {
                kind: LitKind::Bool(*v),
            })),
            ast::Expression::Optional(v) => ExprKind::Optional(v.lower(self)),
            ast::Expression::NamedStruct(v) => ExprKind::Lit(self.arena.alloc(Lit {
                kind: LitKind::NamedStruct(NamedStruct {
                    ident: self.lower_ident(&v.identifier),
                    fields: self.lower_list(&v.fields),
                }),
            })),
            ast::Expression::InternalFunction(v) => match v {
                ast::InternalFunction::Query(fact) => {
                    ExprKind::Intrinsic(Intrinsic::Query(fact.lower(self)))
                }
                ast::InternalFunction::Exists(fact) => {
                    // `exists` is sugar for `at_least 1`, so
                    // desugar it.
                    ExprKind::Intrinsic(Intrinsic::FactCount(
                        FactCountType::AtLeast,
                        1,
                        fact.lower(self),
                    ))
                }
                ast::InternalFunction::FactCount(count_type, limit, fact) => ExprKind::Intrinsic(
                    Intrinsic::FactCount(count_type.lower(self), *limit, fact.lower(self)),
                ),
                ast::InternalFunction::If(cond, then_expr, else_expr) => {
                    ExprKind::Ternary(Ternary {
                        cond: self.lower_expr(cond),
                        true_expr: self.lower_expr(then_expr),
                        false_expr: self.lower_expr(else_expr),
                    })
                }
                ast::InternalFunction::Serialize(expr) => {
                    ExprKind::Intrinsic(Intrinsic::Serialize(self.lower_expr(expr)))
                }
                ast::InternalFunction::Deserialize(expr) => {
                    ExprKind::Intrinsic(Intrinsic::Deserialize(self.lower_expr(expr)))
                }
            },
            ast::Expression::FunctionCall(v) => ExprKind::FunctionCall(FunctionCall {
                ident: self.lower_ident(&v.identifier),
                args: self.lower_list(&v.arguments),
            }),
            ast::Expression::ForeignFunctionCall(v) => {
                ExprKind::ForeignFunctionCall(ForeignFunctionCall {
                    module: self.lower_ident(&v.module),
                    ident: self.lower_ident(&v.identifier),
                    args: self.lower_list(&v.arguments),
                })
            }
            ast::Expression::Identifier(v) => ExprKind::Identifier(self.lower_ident(v)),
            ast::Expression::EnumReference(v) => ExprKind::EnumRef(EnumRef {
                ident: self.lower_ident(&v.identifier),
                value: self.lower_ident(&v.value),
            }),
            ast::Expression::Add(lhs, rhs) => {
                ExprKind::Add(self.lower_expr(lhs), self.lower_expr(rhs))
            }
            ast::Expression::Subtract(lhs, rhs) => {
                ExprKind::Sub(self.lower_expr(lhs), self.lower_expr(rhs))
            }
            ast::Expression::And(lhs, rhs) => {
                ExprKind::And(self.lower_expr(lhs), self.lower_expr(rhs))
            }
            ast::Expression::Or(lhs, rhs) => {
                ExprKind::Or(self.lower_expr(lhs), self.lower_expr(rhs))
            }
            ast::Expression::Dot(expr, ident) => {
                ExprKind::Dot(self.lower_expr(expr), self.lower_ident(ident))
            }
            ast::Expression::Equal(lhs, rhs) => {
                ExprKind::Equal(self.lower_expr(lhs), self.lower_expr(rhs))
            }
            ast::Expression::NotEqual(lhs, rhs) => {
                ExprKind::NotEqual(self.lower_expr(lhs), self.lower_expr(rhs))
            }
            ast::Expression::GreaterThan(lhs, rhs) => {
                ExprKind::GreaterThan(self.lower_expr(lhs), self.lower_expr(rhs))
            }
            ast::Expression::LessThan(lhs, rhs) => {
                ExprKind::LessThan(self.lower_expr(lhs), self.lower_expr(rhs))
            }
            ast::Expression::GreaterThanOrEqual(lhs, rhs) => {
                ExprKind::GreaterThanOrEqual(self.lower_expr(lhs), self.lower_expr(rhs))
            }
            ast::Expression::LessThanOrEqual(lhs, rhs) => {
                ExprKind::LessThanOrEqual(self.lower_expr(lhs), self.lower_expr(rhs))
            }
            ast::Expression::Negative(expr) => ExprKind::Negative(self.lower_expr(expr)),
            ast::Expression::Not(expr) => ExprKind::Not(self.lower_expr(expr)),
            ast::Expression::Unwrap(expr) => ExprKind::Unwrap(self.lower_expr(expr)),
            ast::Expression::CheckUnwrap(expr) => ExprKind::CheckUnwrap(self.lower_expr(expr)),
            ast::Expression::Is(expr, is_some) => ExprKind::Is(self.lower_expr(expr), *is_some),
            ast::Expression::Block(stmts, expr) => {
                ExprKind::Block(self.lower_block(stmts), self.lower_expr(expr))
            }
            ast::Expression::Substruct(expr, ident) => {
                ExprKind::Substruct(self.lower_expr(expr), self.lower_ident(ident))
            }
            ast::Expression::Match(expr) => ExprKind::Match(MatchExpr {
                scrutinee: self.lower_expr(&expr.scrutinee),
                arms: self.lower_list(&expr.arms),
            }),
        };

        let ExprInfo { pure, returns } = find_expr_info(&self.hir, &kind);
        self.arena.alloc(Expr {
            id: ExprId::default(), // TODO,
            span: Span::dummy(),
            kind,
            pure,
            returns,
        })
    }

    /// Lowers a [`ast::Statement`].
    fn lower_stmt(&mut self, stmt: &'ctx AstNode<ast::Statement>) -> Stmt<'ctx> {
        let kind = match &stmt.inner {
            ast::Statement::Let(v) => StmtKind::Let(LetStmt {
                ident: self.lower_ident(&v.identifier),
                expr: self.lower_expr(&v.expression),
            }),
            ast::Statement::Check(v) => StmtKind::Check(CheckStmt {
                expr: self.lower_expr(&v.expression),
            }),
            ast::Statement::Match(v) => StmtKind::Match(MatchStmt {
                expr: self.lower_expr(&v.expression),
                arms: self.lower_list(&v.arms),
            }),
            ast::Statement::If(v) => StmtKind::If(IfStmt {
                branches: self.lower_list(&v.branches),
                else_block: v.fallback.lower(self),
            }),
            ast::Statement::Finish(v) => StmtKind::Finish(self.lower_block(v)),
            ast::Statement::Map(v) => StmtKind::Map(MapStmt {
                fact: v.fact.lower(self),
                ident: self.lower_ident(&v.identifier),
                block: self.lower_block(&v.statements),
            }),
            ast::Statement::Return(v) => StmtKind::Return(ReturnStmt {
                expr: self.lower_expr(&v.expression),
            }),
            ast::Statement::ActionCall(v) => StmtKind::ActionCall(ActionCall {
                ident: self.lower_ident(&v.identifier),
                args: self.lower_list(&v.arguments),
            }),
            ast::Statement::Publish(v) => StmtKind::Publish(Publish {
                expr: self.lower_expr(v),
            }),
            ast::Statement::Create(v) => StmtKind::Create(Create {
                fact: v.fact.lower(self),
            }),
            ast::Statement::Update(v) => StmtKind::Update(Update {
                fact: v.fact.lower(self),
                to: self.lower_list::<_, _, (IdentId, FactField), _>(&v.to),
            }),
            ast::Statement::Delete(v) => StmtKind::Delete(Delete {
                fact: v.fact.lower(self),
            }),
            ast::Statement::Emit(v) => StmtKind::Emit(Emit {
                expr: self.lower_expr(v),
            }),
            ast::Statement::FunctionCall(v) => StmtKind::FunctionCall(FunctionCall {
                ident: self.lower_ident(&v.identifier),
                args: self.lower_list(&v.arguments),
            }),
            ast::Statement::DebugAssert(v) => StmtKind::DebugAssert(DebugAssert {
                expr: self.lower_expr(v),
            }),
        };

        let StmtInfo { returns } = find_stmt_info(&self.hir, &kind);
        self.arena.alloc(Stmt {
            id: StmtId::default(), // TODO
            span: Span::point(stmt.locator),
            kind,
            returns,
        });
    }

    /// Lowers a block.
    fn lower_block(&mut self, block: &'ctx Vec<AstNode<ast::Statement>>) -> &'ctx Block<'ctx> {
        // Use the span from the first statement if available.
        let span = block
            .first()
            .map(|stmt| Span::point(stmt.locator))
            .unwrap_or_else(Span::dummy);

        let stmts = self.lower_stmts(block);
        // TODO(eric): Figure this out while lowering the block.
        let returns = stmts.iter().any(|&id| self.hir.stmts[id].returns);

        self.arena.alloc(Block {
            id: BlockId::default(), // TODO
            span,
            stmts,
            expr: None,
            returns,
        })
    }

    fn lower_stmts(&mut self, stmts: &'ctx Vec<AstNode<ast::Statement>>) -> &'ctx [Stmt<'ctx>] {
        self.lower_list(stmts)
    }

    fn lower_action(&mut self, node: &'ctx AstNode<ast::ActionDefinition>) {
        let ident = self.lower_ident(&node.identifier);
        let args = self.lower_list(&node.arguments);
        let block = self.lower_block(&node.statements);
        self.hir.actions.insert_with_key(|id| ActionDef {
            id,
            span: Span::point(node.locator),
            ident,
            args,
            block,
        });
    }

    fn lower_action_arg(&mut self, node: &'ctx ast::FieldDefinition) -> ActionArg<'ctx> {
        let ident = self.lower_ident(&node.identifier);
        let ty = self.lower_vtype(&node.field_type);
        ActionArg {
            id: ActionArgId::default(), // TODO
            span: Span::dummy(),
            ident,
            ty,
        }
    }

    fn lower_finish_func_arg(&mut self, node: &'ctx ast::FieldDefinition) -> FinishFuncArgId {
        let ident = self.lower_ident(&node.identifier);
        let ty = self.lower_vtype(&node.field_type);
        self.hir
            .finish_func_args
            .insert_with_key(|id| FinishFuncArg {
                id,
                span: Span::dummy(),
                ident,
                ty,
            })
    }

    fn lower_func_arg(&mut self, node: &'ctx ast::FieldDefinition) -> FuncArgId {
        let ident = self.lower_ident(&node.identifier);
        let ty = self.lower_vtype(&node.field_type);
        self.hir.func_args.insert_with_key(|id| FuncArg {
            id,
            span: Span::dummy(),
            ident,
            ty,
        })
    }

    fn lower_cmd(&mut self, node: &'ctx AstNode<ast::CommandDefinition>) {
        let ident = self.lower_ident(&node.identifier);
        let fields: Vec<CmdFieldId> = self.lower_list::<_, _, CmdField, _>(&node.fields);
        let seal = self.lower_block(&node.seal);
        let open = self.lower_block(&node.open);
        let policy = self.lower_block(&node.policy);
        let recall = self.lower_block(&node.recall);
        self.hir.cmds.insert_with_key(|id| CmdDef {
            id,
            span: Span::point(node.locator),
            ident,
            fields,
            seal,
            open,
            policy,
            recall,
        });
    }

    fn lower_cmd_field(
        &mut self,
        node: &'ctx ast::StructItem<ast::FieldDefinition>,
    ) -> CmdField<'ctx> {
        let kind = match node {
            ast::StructItem::Field(field) => {
                let ident = self.lower_ident(&field.identifier);
                let ty = self.lower_vtype(&field.field_type);
                CmdFieldKind::Field { ident, ty }
            }
            ast::StructItem::StructRef(struct_ref) => {
                let ident = self.lower_ident(struct_ref);
                CmdFieldKind::StructRef(ident)
            }
        };
        CmdField {
            id: CmdFieldId::default(), // TODO
            span: Span::dummy(),
            kind,
        }
    }

    fn lower_effect(&mut self, e: &'ctx AstNode<ast::EffectDefinition>) {
        let ident = self.lower_ident(&e.identifier);
        let items = self.lower_list::<_, _, EffectFieldId, _>(&e.items);
        self.hir.effects.insert_with_key(|id| EffectDef {
            id,
            span: Span::point(e.locator),
            ident,
            items,
        });
    }

    fn lower_effect_field(
        &mut self,
        node: &'ctx ast::StructItem<ast::EffectFieldDefinition>,
    ) -> EffectFieldId {
        let kind = match node {
            ast::StructItem::Field(field) => {
                let ident = self.lower_ident(&field.identifier);
                let ty = self.lower_vtype(&field.field_type);
                EffectFieldKind::Field { ident, ty }
            }
            ast::StructItem::StructRef(struct_ref) => {
                let ident = self.lower_ident(struct_ref);
                EffectFieldKind::StructRef(ident)
            }
        };
        self.hir.effect_fields.insert_with_key(|id| EffectField {
            id,
            span: Span::dummy(),
            kind,
        })
    }

    fn lower_enum(&mut self, e: &'ctx AstNode<ast::EnumDefinition>) {
        let ident = self.lower_ident(&e.identifier);
        let variants = self.lower_list(&e.variants);
        self.hir.enums.insert_with_key(|id| {
            self.arena.alloc(EnumDef {
                id,
                span: Span::point(e.locator),
                ident,
                variants,
            })
        });
    }

    fn lower_fact(&mut self, f: &'ctx AstNode<ast::FactDefinition>) {
        let ident = self.lower_ident(&f.identifier);
        let keys = self.lower_list(&f.key);
        let vals = self.lower_list(&f.value);
        self.hir.facts.insert_with_key(|id| FactDef {
            id,
            span: Span::point(f.locator),
            ident,
            keys,
            vals,
        });
    }

    fn lower_fact_key(&mut self, node: &'ctx ast::FieldDefinition) -> FactKey<'ctx> {
        let ident = self.lower_ident(&node.identifier);
        let ty = self.lower_vtype(&node.field_type);
        FactKey {
            id: FactKeyId::default(), // TODO
            span: Span::dummy(),
            ident,
            ty,
        }
    }

    fn lower_fact_val(&mut self, node: &'ctx ast::FieldDefinition) -> FactVal<'ctx> {
        let ident = self.lower_ident(&node.identifier);
        let ty = self.lower_vtype(&node.field_type);
        FactVal {
            id: FactValId::default(), // TODO
            span: Span::dummy(),
            ident,
            ty,
        }
    }

    fn lower_finish_func(&mut self, f: &'ctx AstNode<ast::FinishFunctionDefinition>) {
        let ident = self.lower_ident(&f.identifier);
        let args: Vec<FinishFuncArgId> = self.lower_list(&f.arguments);
        let block = self.lower_block(&f.statements);
        self.hir.finish_funcs.insert_with_key(|id| FinishFuncDef {
            id,
            span: Span::point(f.locator),
            ident,
            args,
            block,
        });
    }

    fn lower_func(&mut self, f: &'ctx AstNode<ast::FunctionDefinition>) {
        let ident = self.lower_ident(&f.identifier);
        let args = self.lower_list(&f.arguments);
        let result = self.lower_vtype(&f.return_type);
        let block = self.lower_block(&f.statements);
        self.hir.funcs.insert_with_key(|id| FuncDef {
            id,
            span: Span::point(f.locator),
            ident,
            args,
            result,
            block,
        });
    }

    fn lower_global(&mut self, g: &'ctx AstNode<ast::GlobalLetStatement>) {
        let ident = self.lower_ident(&g.identifier);
        let expr = self.lower_expr(&g.expression);
        self.hir.global_lets.insert_with_key(|id| GlobalLetDef {
            id,
            span: Span::point(g.locator),
            ident,
            expr,
        });
    }

    fn lower_struct(&mut self, s: &'ctx AstNode<ast::StructDefinition>) {
        let ident = self.lower_ident(&s.identifier);
        let items: Vec<StructFieldId> = self.lower_list::<_, _, StructFieldId, _>(&s.items);
        self.hir.structs.insert_with_key(|id| StructDef {
            id,
            span: Span::point(s.locator),
            ident,
            items,
        });
    }

    fn lower_struct_field(
        &mut self,
        node: &'ctx ast::StructItem<ast::FieldDefinition>,
    ) -> StructFieldId {
        let kind = match node {
            ast::StructItem::Field(field) => {
                let ident = self.lower_ident(&field.identifier);
                let ty = self.lower_vtype(&field.field_type);
                StructFieldKind::Field { ident, ty }
            }
            ast::StructItem::StructRef(struct_ref) => {
                let ident = self.lower_ident(struct_ref);
                StructFieldKind::StructRef(ident)
            }
        };
        self.hir.struct_fields.insert_with_key(|id| StructField {
            id,
            span: Span::dummy(),
            kind,
        })
    }

    fn lower_ffi_imports(&mut self, ast: &'ctx Policy) {
        for import in &ast.ffi_imports {
            let module = self.lower_ident(import);
            self.hir.ffi_imports.insert_with_key(|id| FfiImportDef {
                id,
                span: Span::dummy(),
                module,
            });
        }
    }

    fn lower_ffi_modules(&mut self, ffi_modules: &'ctx [ModuleSchema<'ctx>]) {
        for module in ffi_modules {
            let ident = self.lower_ident(&module.name);

            let functions = module
                .functions
                .iter()
                .map(|f| {
                    let ident = self.lower_ident(&f.name);
                    let args = self.lower_list(f.args);
                    let return_type = self.lower_ffi_type(&f.return_type);
                    self.hir.ffi_funcs.insert_with_key(|id| FfiFuncDef {
                        id,
                        span: Span::dummy(),
                        ident,
                        args,
                        return_type,
                    })
                })
                .collect();

            let structs = module
                .structs
                .iter()
                .map(|s| {
                    let struct_name = self.lower_ident(&s.name);
                    let fields = self.lower_list(s.fields);
                    self.hir.ffi_structs.insert_with_key(|id| FfiStructDef {
                        id,
                        span: Span::dummy(),
                        name: struct_name,
                        fields,
                    })
                })
                .collect();

            let enums = module
                .enums
                .iter()
                .map(|e| {
                    let enum_name = self.lower_ident(&e.name);
                    let variants = self.lower_list(e.variants);
                    self.hir.ffi_enums.insert_with_key(|id| FfiEnumDef {
                        id,
                        span: Span::dummy(),
                        name: enum_name,
                        variants,
                    })
                })
                .collect();

            self.hir.ffi_modules.insert_with_key(|id| FfiModuleDef {
                id,
                span: Span::dummy(),
                ident,
                functions,
                structs,
                enums,
            });
        }
    }

    /// Lowers an FFI type to a VType.
    fn lower_ffi_type(&mut self, ffi_type: &'ctx ffi::Type<'ctx>) -> VTypeId {
        let kind = match ffi_type {
            ffi::Type::Int => VTypeKind::Int,
            ffi::Type::Bool => VTypeKind::Bool,
            ffi::Type::String => VTypeKind::String,
            ffi::Type::Bytes => VTypeKind::Bytes,
            ffi::Type::Id => VTypeKind::Id,
            ffi::Type::Struct(name) => VTypeKind::Struct(self.lower_ident(name)),
            ffi::Type::Enum(name) => VTypeKind::Enum(self.lower_ident(name)),
            ffi::Type::Optional(inner) => {
                let inner_type = self.lower_ffi_type(inner);
                VTypeKind::Optional(inner_type)
            }
        };
        self.hir.types.insert_with_key(|id| VType {
            id,
            span: Span::dummy(),
            kind,
        })
    }
}

#[derive(Copy, Clone, Debug)]
struct Discard;

impl<T> FromIterator<T> for Discard {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        iter.into_iter().for_each(drop);
        Discard
    }
}

/// Implemented by types that can lower themselves into HIR.
trait Lower<T> {
    type Result;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result;
}

impl<A1, A2, L1, L2> Lower<(L1, L2)> for (A1, A2)
where
    A1: Lower<L1>,
    A2: Lower<L2>,
{
    type Result = (A1::Result, A2::Result);
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        (self.0.lower(ctx), self.1.lower(ctx))
    }
}

impl<T, U> Lower<U> for &T
where
    T: Lower<U>,
{
    type Result = T::Result;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        (*self).lower(ctx)
    }
}

impl<T, U> Lower<U> for Box<T>
where
    T: Lower<U>,
{
    type Result = T::Result;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        self.as_ref().lower(ctx)
    }
}

impl<T, U> Lower<Option<U>> for Option<T>
where
    T: Lower<U>,
{
    type Result = Option<T::Result>;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        self.as_ref().map(|v| v.lower(ctx))
    }
}

impl Lower<Ident> for ast::Identifier {
    type Result = IdentId;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_ident(self)
    }
}

impl<'ctx> Lower<&'ctx VType<'ctx>> for ast::VType {
    type Result = &'ctx VType<'ctx>;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_vtype(self)
    }
}

impl<'ctx> Lower<&'ctx Expr<'ctx>> for ast::Expression {
    type Result = &'ctx Expr<'ctx>;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_expr(self)
    }
}

impl<'ctx> Lower<Stmt<'ctx>> for AstNode<ast::Statement> {
    type Result = Stmt<'ctx>;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_stmt(self)
    }
}

impl<'ctx> Lower<&'ctx Block<'ctx>> for Vec<AstNode<ast::Statement>> {
    type Result = &'ctx Block<'ctx>;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_block(self)
    }
}

impl<'ctx> Lower<ActionDef<'ctx>> for AstNode<ast::ActionDefinition> {
    type Result = ();
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_action(self)
    }
}

impl<'ctx> Lower<&'ctx MatchPattern<'ctx>> for ast::MatchPattern {
    type Result = MatchPattern<'ctx>;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        self.arena.alloc(match self {
            ast::MatchPattern::Default => MatchPattern::Default,
            ast::MatchPattern::Values(values) => MatchPattern::Values(ctx.lower_list(values)),
        })
    }
}

impl<'ctx> Lower<MatchArm<'ctx>> for ast::MatchArm {
    type Result = MatchArm<'ctx>;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        MatchArm {
            pattern: self.pattern.lower(ctx),
            block: ctx.lower_block(&self.statements),
        }
    }
}

impl<'ctx> Lower<&'ctx FactLiteral<'ctx>> for ast::FactLiteral {
    type Result = &'ctx FactLiteral<'ctx>;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.arena.alloc(FactLiteral {
            ident: ctx.lower_ident(&self.identifier),
            keys: ctx.lower_list(&self.key_fields),
            vals: ctx.lower_list(self.value_fields.iter().flatten()),
        })
    }
}

impl<'ctx> Lower<&'ctx FactField<'ctx>> for ast::FactField {
    type Result = &'ctx FactField<'ctx>;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        self.arena.alloc(match self {
            ast::FactField::Expression(expr) => FactField::Expr(ctx.lower_expr(expr)),
            ast::FactField::Bind => FactField::Bind,
        })
    }
}

impl<'ctx> Lower<FactKey<'ctx>> for ast::FieldDefinition {
    type Result = FactKey<'ctx>;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_fact_key(self)
    }
}

impl<'ctx> Lower<FactVal<'ctx>> for ast::FieldDefinition {
    type Result = FactVal<'ctx>;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_fact_val(self)
    }
}

impl<'ctx> Lower<FinishFuncArg<'ctx>> for ast::FieldDefinition {
    type Result = FinishFuncArgId;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_finish_func_arg(self)
    }
}

impl<'ctx> Lower<FuncArg<'ctx>> for ast::FieldDefinition {
    type Result = FuncArgId;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_func_arg(self)
    }
}

impl<'ctx> Lower<ActionArg<'ctx>> for ast::FieldDefinition {
    type Result = ActionArgId;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_action_arg(self)
    }
}

impl<'ctx> Lower<CmdField<'ctx>> for ast::StructItem<ast::FieldDefinition> {
    type Result = CmdFieldId;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_cmd_field(self)
    }
}

impl<'ctx> Lower<IfBranch<'ctx>> for (ast::Expression, Vec<AstNode<ast::Statement>>) {
    type Result = IfBranch<'ctx>;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        IfBranch {
            expr: ctx.lower_expr(&self.0),
            block: ctx.lower_block(&self.1),
        }
    }
}

impl<'ctx> Lower<StructFieldExpr<'ctx>> for (ast::Identifier, ast::Expression) {
    type Result = StructFieldExpr<'ctx>;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        StructFieldExpr {
            ident: ctx.lower_ident(&self.0),
            expr: self.1.lower(ctx),
        }
    }
}

impl<'ctx> Lower<FactFieldExpr<'ctx>> for (ast::Identifier, ast::FactField) {
    type Result = FactFieldExpr<'ctx>;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        FactFieldExpr {
            ident: ctx.lower_ident(&self.0),
            expr: self.1.lower(ctx),
        }
    }
}

impl Lower<FactCountType> for ast::FactCountType {
    type Result = FactCountType;
    fn lower<'ast>(&'ast self, _ctx: &mut LowerCtx<'ast>) -> Self::Result {
        match self {
            ast::FactCountType::UpTo => FactCountType::UpTo,
            ast::FactCountType::AtLeast => FactCountType::AtLeast,
            ast::FactCountType::AtMost => FactCountType::AtMost,
            ast::FactCountType::Exactly => FactCountType::Exactly,
        }
    }
}

impl<'ctx> Lower<MatchExprArm<'ctx>> for AstNode<ast::MatchExpressionArm> {
    type Result = MatchExprArm<'ctx>;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        MatchExprArm {
            pattern: self.pattern.lower(ctx),
            expr: ctx.lower_expr(&self.expression),
        }
    }
}

impl<'ctx> Lower<FieldDef<'ctx>> for ffi::Arg<'_> {
    type Result = FieldDef<'ctx>;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        FieldDef {
            ident: ctx.lower_ident(&self.name),
            ty: ctx.lower_ffi_type(&self.vtype),
        }
    }
}

#[derive(Copy, Clone, Debug)]
struct StmtInfo {
    returns: bool,
}

impl<'hir> Visitor<'hir> for StmtInfo {
    type Result = ();
    fn visit_expr(&mut self, expr: &'hir Expr<'hir>) -> Self::Result {
        self.returns |= expr.returns;
    }
    fn visit_block(&mut self, block: &'hir Block<'hir>) -> Self::Result {
        self.returns |= block.returns;
    }
    fn visit_stmt(&mut self, stmt: &'hir Stmt<'hir>) -> Self::Result {
        self.returns |= stmt.returns;
    }
}

fn find_stmt_info(hir: &Hir<'_>, kind: &StmtKind<'_>) -> StmtInfo {
    if let StmtKind::Return(_) = kind {
        return StmtInfo { returns: true };
    }

    let mut info = StmtInfo { returns: false };

    // NB: `walk_stmt_kind` does not call `walker.recurse`, so
    // max depth = 0 is correct.
    hir.walker()
        .with_max_depth(0)
        .walk_stmt_kind(kind, &mut info);
    info
}

#[derive(Copy, Clone, Debug)]
struct ExprInfo {
    pure: Pure,
    returns: bool,
}

impl<'hir> Visitor<'hir> for ExprInfo {
    type Result = ();
    fn visit_expr(&mut self, expr: &'hir Expr<'hir>) -> Self::Result {
        self.pure &= expr.pure;
        self.returns |= expr.returns;
    }
    fn visit_block(&mut self, block: &'hir Block<'hir>) -> Self::Result {
        self.returns |= block.returns;
    }
    fn visit_stmt(&mut self, stmt: &'hir Stmt<'hir>) -> Self::Result {
        self.returns |= stmt.returns;
    }
}

fn find_expr_info(hir: &Hir<'_>, kind: &ExprKind<'_>) -> ExprInfo {
    let mut info = ExprInfo {
        pure: Pure::Yes,
        returns: false,
    };

    // NB: `walk_expr_kind` does not call `walker.recurse`, so
    // max depth = 0 is correct.
    hir.walker()
        .with_max_depth(0)
        .walk_expr_kind(kind, &mut info);
    info
}
