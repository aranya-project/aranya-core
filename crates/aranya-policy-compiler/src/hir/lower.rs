//! Lowers [`Policy`] items into the HIR.

use aranya_policy_ast::{self as ast, AstNode, Policy};
use aranya_policy_module::ffi::{self, ModuleSchema};

use super::{
    types::{
        ActionArg, ActionArgId, ActionCall, ActionDef, ActionSig, BinOp, Block, BlockId, CheckStmt,
        CmdDef, CmdField, CmdFieldId, CmdFieldKind, Create, DebugAssert, Delete, EffectDef,
        EffectField, EffectFieldId, EffectFieldKind, Emit, EnumDef, EnumRef, Expr, ExprId,
        ExprKind, FactCountType, FactDef, FactField, FactFieldExpr, FactKey, FactKeyId,
        FactLiteral, FactVal, FactValId, FfiEnumDef, FfiFuncDef, FfiImportDef, FfiModuleDef,
        FfiStructDef, FieldDef, FinishFuncArg, FinishFuncArgId, FinishFuncDef, FinishFuncSig,
        ForeignFunctionCall, FuncArg, FuncArgId, FuncDef, FuncSig, FunctionCall, GlobalLetDef, Hir,
        Ident, IdentId, IdentInterner, IfBranch, IfStmt, Intrinsic, LetStmt, Lit, LitKind, MapStmt,
        MatchArm, MatchExpr, MatchExprArm, MatchPattern, MatchStmt, NamedStruct, Publish, Pure,
        ReturnStmt, Span, Stmt, StmtId, StmtKind, StructDef, StructField, StructFieldExpr,
        StructFieldId, StructFieldKind, Ternary, TextInterner, UnaryOp, Update, VType, VTypeId,
        VTypeKind,
    },
    visit::{self, Visitor},
};
use crate::ast::Item;

#[derive(Debug)]
pub(crate) struct LowerCtx<'ctx> {
    pub hir: Hir,
    pub idents: &'ctx mut IdentInterner,
    pub text: &'ctx mut TextInterner,
}

impl LowerCtx<'_> {
    pub(crate) fn lower_item(&mut self, item: &Item<'_>) {
        match item {
            Item::Action(node) => self.lower_action(node),
            Item::Cmd(node) => self.lower_cmd(node),
            Item::Effect(node) => self.lower_effect(node),
            Item::Enum(node) => self.lower_enum(node),
            Item::Fact(node) => self.lower_fact(node),
            Item::FinishFunc(node) => self.lower_finish_func(node),
            Item::Func(node) => self.lower_func(node),
            Item::GlobalLet(node) => self.lower_global(node),
            Item::Struct(node) => self.lower_struct(node),
            Item::FfiFunc(_node) => { /* TODO */ }
            Item::FfiEnum(_node) => { /* TODO */ }
            Item::FfiStruct(_node) => { /* TODO */ }
        }
    }

    /// Lowers a list.
    fn lower_list<I, U, R>(&mut self, list: I) -> R
    where
        I: IntoIterator<Item: Lower<U>>,
        R: FromIterator<<I::Item as Lower<U>>::Result>,
    {
        list.into_iter().map(|item| item.lower(self)).collect()
    }

    /// Lowers an [`ast::Identifier`].
    fn lower_ident(&mut self, ident: &ast::Identifier) -> IdentId {
        let ident = self.idents.intern(ident.clone());
        self.hir.idents.insert_with_key(|id| Ident {
            id,
            span: Span::dummy(),
            xref: ident,
        })
    }

    /// Lowers a [`ast::VType`].
    fn lower_vtype(&mut self, vtype: &ast::VType) -> VTypeId {
        let kind = match vtype {
            ast::VType::String => VTypeKind::String,
            ast::VType::Bytes => VTypeKind::Bytes,
            ast::VType::Int => VTypeKind::Int,
            ast::VType::Bool => VTypeKind::Bool,
            ast::VType::Id => VTypeKind::Id,
            ast::VType::Struct(v) => VTypeKind::Struct(self.lower_ident(v)),
            ast::VType::Enum(v) => VTypeKind::Enum(self.lower_ident(v)),
            ast::VType::Optional(v) => VTypeKind::Optional(self.lower_vtype(v)),
        };
        self.hir.types.insert_with_key(|id| VType {
            id,
            span: Span::dummy(),
            kind,
        })
    }

    /// Lowers an [`ast::Expression`].
    fn lower_expr(&mut self, expr: &ast::Expression) -> ExprId {
        let kind = match expr {
            ast::Expression::Int(v) => ExprKind::Lit(Lit {
                kind: LitKind::Int(*v),
            }),
            ast::Expression::String(v) => {
                let text = self.text.intern(v.clone());
                ExprKind::Lit(Lit {
                    kind: LitKind::String(text),
                })
            }
            ast::Expression::Bool(v) => ExprKind::Lit(Lit {
                kind: LitKind::Bool(*v),
            }),
            ast::Expression::Optional(v) => ExprKind::Lit(Lit {
                kind: LitKind::Optional(v.lower(self)),
            }),
            ast::Expression::NamedStruct(v) => ExprKind::Lit(Lit {
                kind: LitKind::NamedStruct(NamedStruct {
                    ident: self.lower_ident(&v.identifier),
                    fields: self.lower_list::<_, StructFieldExpr, _>(&v.fields),
                }),
            }),
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
                ExprKind::Binary(BinOp::Add, self.lower_expr(lhs), self.lower_expr(rhs))
            }
            ast::Expression::Subtract(lhs, rhs) => {
                ExprKind::Binary(BinOp::Sub, self.lower_expr(lhs), self.lower_expr(rhs))
            }
            ast::Expression::And(lhs, rhs) => {
                ExprKind::Binary(BinOp::And, self.lower_expr(lhs), self.lower_expr(rhs))
            }
            ast::Expression::Or(lhs, rhs) => {
                ExprKind::Binary(BinOp::Or, self.lower_expr(lhs), self.lower_expr(rhs))
            }
            ast::Expression::Dot(expr, ident) => {
                ExprKind::Dot(self.lower_expr(expr), self.lower_ident(ident))
            }
            ast::Expression::Equal(lhs, rhs) => {
                ExprKind::Binary(BinOp::Eq, self.lower_expr(lhs), self.lower_expr(rhs))
            }
            ast::Expression::NotEqual(lhs, rhs) => {
                ExprKind::Binary(BinOp::Neq, self.lower_expr(lhs), self.lower_expr(rhs))
            }
            ast::Expression::GreaterThan(lhs, rhs) => {
                ExprKind::Binary(BinOp::Gt, self.lower_expr(lhs), self.lower_expr(rhs))
            }
            ast::Expression::LessThan(lhs, rhs) => {
                ExprKind::Binary(BinOp::Lt, self.lower_expr(lhs), self.lower_expr(rhs))
            }
            ast::Expression::GreaterThanOrEqual(lhs, rhs) => {
                ExprKind::Binary(BinOp::GtEq, self.lower_expr(lhs), self.lower_expr(rhs))
            }
            ast::Expression::LessThanOrEqual(lhs, rhs) => {
                ExprKind::Binary(BinOp::LtEq, self.lower_expr(lhs), self.lower_expr(rhs))
            }
            ast::Expression::Negative(expr) => ExprKind::Unary(UnaryOp::Neg, self.lower_expr(expr)),
            ast::Expression::Not(expr) => ExprKind::Unary(UnaryOp::Not, self.lower_expr(expr)),
            ast::Expression::Unwrap(expr) => {
                ExprKind::Unary(UnaryOp::Unwrap, self.lower_expr(expr))
            }
            ast::Expression::CheckUnwrap(expr) => {
                ExprKind::Unary(UnaryOp::CheckUnwrap, self.lower_expr(expr))
            }
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
        self.hir.exprs.insert_with_key(|id| Expr {
            id,
            span: Span::dummy(),
            kind,
            pure,
            returns,
        })
    }

    /// Lowers a [`ast::Statement`].
    fn lower_stmt(&mut self, stmt: &AstNode<ast::Statement>) -> StmtId {
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
                branches: self.lower_list::<_, IfBranch, _>(&v.branches),
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
                to: self.lower_list::<_, FactFieldExpr, _>(&v.to),
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
        self.hir.stmts.insert_with_key(|id| Stmt {
            id,
            span: Span::point(stmt.locator),
            kind,
            returns,
        })
    }

    /// Lowers a block.
    fn lower_block(&mut self, block: &Vec<AstNode<ast::Statement>>) -> BlockId {
        // Use the span from the first statement if available.
        let span = block
            .first()
            .map(|stmt| Span::point(stmt.locator))
            .unwrap_or_else(Span::dummy);

        let stmts = self.lower_stmts(block);
        // TODO(eric): Figure this out while lowering the block.
        let returns = stmts.iter().any(|&id| self.hir.stmts[id].returns);

        self.hir.blocks.insert_with_key(|id| Block {
            id,
            span,
            stmts,
            expr: None,
            returns,
        })
    }

    fn lower_stmts(&mut self, stmts: &Vec<AstNode<ast::Statement>>) -> Vec<StmtId> {
        self.lower_list(stmts)
    }

    fn lower_action(&mut self, node: &AstNode<ast::ActionDefinition>) {
        let ident = self.lower_ident(&node.identifier);
        let args = self.lower_list::<_, ActionArg, _>(&node.arguments);
        let block = self.lower_block(&node.statements);
        self.hir.actions.insert_with_key(|id| ActionDef {
            id,
            span: Span::point(node.locator),
            ident,
            sig: ActionSig { args },
            block,
        });
    }

    fn lower_action_arg(&mut self, node: &ast::FieldDefinition) -> ActionArgId {
        let ident = self.lower_ident(&node.identifier);
        let ty = self.lower_vtype(&node.field_type);
        self.hir.action_args.insert_with_key(|id| ActionArg {
            id,
            span: Span::dummy(),
            ident,
            ty,
        })
    }

    fn lower_cmd(&mut self, node: &AstNode<ast::CommandDefinition>) {
        let ident = self.lower_ident(&node.identifier);
        let fields = self.lower_list::<_, CmdField, _>(&node.fields);
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

    fn lower_cmd_field(&mut self, node: &ast::StructItem<ast::FieldDefinition>) -> CmdFieldId {
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
        self.hir.cmd_fields.insert_with_key(|id| CmdField {
            id,
            span: Span::dummy(),
            kind,
        })
    }

    fn lower_effect(&mut self, e: &AstNode<ast::EffectDefinition>) {
        let ident = self.lower_ident(&e.identifier);
        let items = self.lower_list(&e.items);
        self.hir.effects.insert_with_key(|id| EffectDef {
            id,
            span: Span::point(e.locator),
            ident,
            items,
        });
    }

    fn lower_effect_field(
        &mut self,
        node: &ast::StructItem<ast::EffectFieldDefinition>,
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

    fn lower_enum(&mut self, e: &AstNode<ast::EnumDefinition>) {
        let ident = self.lower_ident(&e.identifier);
        let variants = self.lower_list(&e.variants);
        self.hir.enums.insert_with_key(|id| EnumDef {
            id,
            span: Span::point(e.locator),
            ident,
            variants,
        });
    }

    fn lower_fact(&mut self, f: &AstNode<ast::FactDefinition>) {
        let ident = self.lower_ident(&f.identifier);
        let keys = self.lower_list::<_, FactKey, _>(&f.key);
        let vals = self.lower_list::<_, FactVal, _>(&f.value);
        self.hir.facts.insert_with_key(|id| FactDef {
            id,
            span: Span::point(f.locator),
            ident,
            keys,
            vals,
        });
    }

    fn lower_fact_key(&mut self, node: &ast::FieldDefinition) -> FactKeyId {
        let ident = self.lower_ident(&node.identifier);
        let ty = self.lower_vtype(&node.field_type);
        self.hir.fact_keys.insert_with_key(|id| FactKey {
            id,
            span: Span::dummy(),
            ident,
            ty,
        })
    }

    fn lower_fact_val(&mut self, node: &ast::FieldDefinition) -> FactValId {
        let ident = self.lower_ident(&node.identifier);
        let ty = self.lower_vtype(&node.field_type);
        self.hir.fact_vals.insert_with_key(|id| FactVal {
            id,
            span: Span::dummy(),
            ident,
            ty,
        })
    }

    fn lower_finish_func(&mut self, f: &AstNode<ast::FinishFunctionDefinition>) {
        let ident = self.lower_ident(&f.identifier);
        let args = self.lower_list::<_, FinishFuncArg, _>(&f.arguments);
        let block = self.lower_block(&f.statements);
        self.hir.finish_funcs.insert_with_key(|id| FinishFuncDef {
            id,
            span: Span::point(f.locator),
            ident,
            sig: FinishFuncSig { args },
            block,
        });
    }

    fn lower_finish_func_arg(&mut self, node: &ast::FieldDefinition) -> FinishFuncArgId {
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

    fn lower_func(&mut self, f: &AstNode<ast::FunctionDefinition>) {
        let ident = self.lower_ident(&f.identifier);
        let args = self.lower_list::<_, FuncArg, _>(&f.arguments);
        let result = self.lower_vtype(&f.return_type);
        let block = self.lower_block(&f.statements);
        self.hir.funcs.insert_with_key(|id| FuncDef {
            id,
            span: Span::point(f.locator),
            ident,
            sig: FuncSig { args, result },
            block,
        });
    }

    fn lower_func_arg(&mut self, node: &ast::FieldDefinition) -> FuncArgId {
        let ident = self.lower_ident(&node.identifier);
        let ty = self.lower_vtype(&node.field_type);
        self.hir.func_args.insert_with_key(|id| FuncArg {
            id,
            span: Span::dummy(),
            ident,
            ty,
        })
    }

    fn lower_global(&mut self, g: &AstNode<ast::GlobalLetStatement>) {
        let ident = self.lower_ident(&g.identifier);
        let expr = self.lower_expr(&g.expression);
        self.hir.global_lets.insert_with_key(|id| GlobalLetDef {
            id,
            span: Span::point(g.locator),
            ident,
            expr,
        });
    }

    fn lower_struct(&mut self, s: &AstNode<ast::StructDefinition>) {
        let ident = self.lower_ident(&s.identifier);
        let items = self.lower_list::<_, StructField, _>(&s.items);
        self.hir.structs.insert_with_key(|id| StructDef {
            id,
            span: Span::point(s.locator),
            ident,
            items,
        });
    }

    fn lower_struct_field(
        &mut self,
        node: &ast::StructItem<ast::FieldDefinition>,
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

    fn lower_ffi_imports(&mut self, ast: &Policy) {
        for import in &ast.ffi_imports {
            let module = self.lower_ident(import);
            self.hir.ffi_imports.insert_with_key(|id| FfiImportDef {
                id,
                span: Span::dummy(),
                module,
            });
        }
    }

    fn lower_ffi_modules(&mut self, ffi_modules: &[ModuleSchema<'_>]) {
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
                    let ident = self.lower_ident(&s.name);
                    let fields = self.lower_list(s.fields);
                    self.hir.ffi_structs.insert_with_key(|id| FfiStructDef {
                        id,
                        span: Span::dummy(),
                        ident,
                        fields,
                    })
                })
                .collect();

            let enums = module
                .enums
                .iter()
                .map(|e| {
                    let ident = self.lower_ident(&e.name);
                    let variants = self.lower_list(e.variants);
                    self.hir.ffi_enums.insert_with_key(|id| FfiEnumDef {
                        id,
                        span: Span::dummy(),
                        ident,
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
    fn lower_ffi_type(&mut self, ffi_type: &ffi::Type<'_>) -> VTypeId {
        let kind = match ffi_type {
            ffi::Type::Int => VTypeKind::Int,
            ffi::Type::Bool => VTypeKind::Bool,
            ffi::Type::String => VTypeKind::String,
            ffi::Type::Bytes => VTypeKind::Bytes,
            ffi::Type::Id => VTypeKind::Id,
            ffi::Type::Struct(name) => VTypeKind::Struct(self.lower_ident(name)),
            ffi::Type::Enum(name) => VTypeKind::Enum(self.lower_ident(name)),
            ffi::Type::Optional(inner) => VTypeKind::Optional(self.lower_ffi_type(inner)),
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
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result;
}

impl<A1, A2, L1, L2> Lower<(L1, L2)> for (A1, A2)
where
    A1: Lower<L1>,
    A2: Lower<L2>,
{
    type Result = (A1::Result, A2::Result);
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        (self.0.lower(ctx), self.1.lower(ctx))
    }
}

impl<T, U> Lower<U> for &T
where
    T: Lower<U>,
{
    type Result = T::Result;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        (*self).lower(ctx)
    }
}

impl<T, U> Lower<U> for Box<T>
where
    T: Lower<U>,
{
    type Result = T::Result;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        self.as_ref().lower(ctx)
    }
}

impl<T, U> Lower<Option<U>> for Option<T>
where
    T: Lower<U>,
{
    type Result = Option<T::Result>;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        self.as_ref().map(|v| v.lower(ctx))
    }
}

impl Lower<Ident> for ast::Identifier {
    type Result = IdentId;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        ctx.lower_ident(self)
    }
}

impl Lower<VType> for ast::VType {
    type Result = VTypeId;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        ctx.lower_vtype(self)
    }
}

impl Lower<Expr> for ast::Expression {
    type Result = ExprId;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        ctx.lower_expr(self)
    }
}

impl Lower<Stmt> for AstNode<ast::Statement> {
    type Result = StmtId;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        ctx.lower_stmt(self)
    }
}

impl Lower<Block> for Vec<AstNode<ast::Statement>> {
    type Result = BlockId;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        ctx.lower_block(self)
    }
}

impl Lower<ActionDef> for AstNode<ast::ActionDefinition> {
    type Result = ();
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        ctx.lower_action(self)
    }
}

impl Lower<EffectField> for ast::StructItem<ast::EffectFieldDefinition> {
    type Result = EffectFieldId;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        ctx.lower_effect_field(self)
    }
}

impl Lower<MatchPattern> for ast::MatchPattern {
    type Result = MatchPattern;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        match self {
            ast::MatchPattern::Default => MatchPattern::Default,
            ast::MatchPattern::Values(values) => MatchPattern::Values(ctx.lower_list(values)),
        }
    }
}

impl Lower<MatchArm> for ast::MatchArm {
    type Result = MatchArm;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        MatchArm {
            pattern: self.pattern.lower(ctx),
            block: ctx.lower_block(&self.statements),
        }
    }
}

impl Lower<FactLiteral> for ast::FactLiteral {
    type Result = FactLiteral;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        FactLiteral {
            ident: ctx.lower_ident(&self.identifier),
            keys: ctx.lower_list::<_, FactFieldExpr, _>(&self.key_fields),
            vals: ctx.lower_list::<_, FactFieldExpr, _>(self.value_fields.iter().flatten()),
        }
    }
}

impl Lower<FactField> for ast::FactField {
    type Result = FactField;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        match self {
            ast::FactField::Expression(expr) => FactField::Expr(ctx.lower_expr(expr)),
            ast::FactField::Bind => FactField::Bind,
        }
    }
}

impl Lower<FactKey> for ast::FieldDefinition {
    type Result = FactKeyId;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        ctx.lower_fact_key(self)
    }
}

impl Lower<FactVal> for ast::FieldDefinition {
    type Result = FactValId;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        ctx.lower_fact_val(self)
    }
}

impl Lower<FinishFuncArg> for ast::FieldDefinition {
    type Result = FinishFuncArgId;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        ctx.lower_finish_func_arg(self)
    }
}

impl Lower<FuncArg> for ast::FieldDefinition {
    type Result = FuncArgId;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        ctx.lower_func_arg(self)
    }
}

impl Lower<ActionArg> for ast::FieldDefinition {
    type Result = ActionArgId;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        ctx.lower_action_arg(self)
    }
}

impl Lower<CmdField> for ast::StructItem<ast::FieldDefinition> {
    type Result = CmdFieldId;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        ctx.lower_cmd_field(self)
    }
}

impl Lower<IfBranch> for (ast::Expression, Vec<AstNode<ast::Statement>>) {
    type Result = IfBranch;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        IfBranch {
            expr: ctx.lower_expr(&self.0),
            block: ctx.lower_block(&self.1),
        }
    }
}

impl Lower<StructFieldExpr> for (ast::Identifier, ast::Expression) {
    type Result = StructFieldExpr;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        StructFieldExpr {
            ident: ctx.lower_ident(&self.0),
            expr: self.1.lower(ctx),
        }
    }
}

impl Lower<StructField> for ast::StructItem<ast::FieldDefinition> {
    type Result = StructFieldId;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        ctx.lower_struct_field(self)
    }
}

impl Lower<FactFieldExpr> for (ast::Identifier, ast::FactField) {
    type Result = FactFieldExpr;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        FactFieldExpr {
            ident: ctx.lower_ident(&self.0),
            expr: self.1.lower(ctx),
        }
    }
}

impl Lower<FactCountType> for ast::FactCountType {
    type Result = FactCountType;
    fn lower(&self, _ctx: &mut LowerCtx<'_>) -> Self::Result {
        match self {
            ast::FactCountType::UpTo => FactCountType::UpTo,
            ast::FactCountType::AtLeast => FactCountType::AtLeast,
            ast::FactCountType::AtMost => FactCountType::AtMost,
            ast::FactCountType::Exactly => FactCountType::Exactly,
        }
    }
}

impl Lower<MatchExprArm> for AstNode<ast::MatchExpressionArm> {
    type Result = MatchExprArm;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
        MatchExprArm {
            pattern: self.pattern.lower(ctx),
            expr: ctx.lower_expr(&self.expression),
        }
    }
}

impl Lower<FieldDef> for ffi::Arg<'_> {
    type Result = FieldDef;
    fn lower(&self, ctx: &mut LowerCtx<'_>) -> Self::Result {
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

fn find_stmt_info(hir: &Hir, kind: &StmtKind) -> StmtInfo {
    if let StmtKind::Return(_) = kind {
        return StmtInfo { returns: true };
    }

    struct StmtInfoVisitor<'hir> {
        hir: &'hir Hir,
        info: StmtInfo,
    }
    impl<'hir> Visitor<'hir> for StmtInfoVisitor<'hir> {
        type Result = ();
        fn hir(&self) -> &'hir Hir {
            self.hir
        }
        fn visit_expr(&mut self, expr: &'hir Expr) -> Self::Result {
            self.info.returns |= expr.returns;
        }
        fn visit_block(&mut self, block: &'hir Block) -> Self::Result {
            self.info.returns |= block.returns;
        }
        fn visit_stmt(&mut self, stmt: &'hir Stmt) -> Self::Result {
            self.info.returns |= stmt.returns;
        }
        fn visit_stmt_kind(&mut self, kind: &'hir StmtKind) -> Self::Result {
            visit::walk_stmt_kind(self, kind)
        }
    }
    let mut visitor = StmtInfoVisitor {
        hir,
        info: StmtInfo { returns: false },
    };
    visitor.visit_stmt_kind(kind);
    visitor.info
}

#[derive(Copy, Clone, Debug)]
struct ExprInfo {
    pure: Pure,
    returns: bool,
}

fn find_expr_info(hir: &Hir, kind: &ExprKind) -> ExprInfo {
    struct ExprInfoVisitor<'hir> {
        hir: &'hir Hir,
        info: ExprInfo,
    }
    impl<'hir> Visitor<'hir> for ExprInfoVisitor<'hir> {
        type Result = ();
        fn hir(&self) -> &'hir Hir {
            self.hir
        }
        fn visit_expr(&mut self, expr: &'hir Expr) -> Self::Result {
            self.info.pure &= expr.pure;
            self.info.returns |= expr.returns;
        }
        fn visit_expr_kind(&mut self, expr: &'hir ExprKind) -> Self::Result {
            visit::walk_expr_kind(self, expr);
        }
        fn visit_block(&mut self, block: &'hir Block) -> Self::Result {
            self.info.returns |= block.returns;
        }
        fn visit_stmt(&mut self, stmt: &'hir Stmt) -> Self::Result {
            self.info.returns |= stmt.returns;
        }
    }

    let mut visitor = ExprInfoVisitor {
        hir,
        info: ExprInfo {
            pure: Pure::Yes,
            returns: false,
        },
    };
    visitor.visit_expr_kind(kind);
    visitor.info
}
