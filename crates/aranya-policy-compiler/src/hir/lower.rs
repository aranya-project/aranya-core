//! Lowers [`Policy`] items into the HIR.

use std::borrow::Cow;

use aranya_policy_ast::{self as ast, AstNode, Policy};
use aranya_policy_module::ffi::{self, ModuleSchema};

use crate::hir::{
    arena::AstNodes,
    hir::{
        ActionArg, ActionArgId, ActionCall, ActionDef, ActionId, Block, BlockId, CheckStmt, CmdDef,
        CmdField, CmdFieldId, CmdFieldKind, CmdId, Create, DebugAssert, Delete, EffectDef,
        EffectField, EffectFieldId, EffectFieldKind, Emit, EnumDef, EnumReference, Expr, ExprId,
        ExprKind, FactCountType, FactDef, FactField, FactKey, FactKeyId, FactLiteral, FactVal,
        FactValId, FfiEnumDef, FfiFuncDef, FfiImportDef, FfiModuleDef, FfiStructDef, FinishFuncArg,
        FinishFuncArgId, FinishFuncDef, ForeignFunctionCall, FuncArg, FuncArgId, FuncDef,
        FunctionCall, GlobalLetDef, Hir, Ident, IdentId, IfBranch, IfStmt, InternalFunction,
        LetStmt, MapStmt, MatchArm, MatchPattern, MatchStmt, NamedStruct, Publish, ReturnStmt,
        Span, Stmt, StmtId, StmtKind, StructDef, StructField, StructFieldId, StructFieldKind, Update,
        VType, VTypeId, VTypeKind,
    },
};

#[derive(Clone, Default, Debug)]
pub(crate) struct LowerCtx<'ast> {
    pub ast: Hir,
    pub arena: AstNodes<'ast>,
}

impl<'ast> LowerCtx<'ast> {
    pub(crate) fn build(ast: &'ast Policy, ffi_modules: &'ast [ModuleSchema<'ast>]) -> Self {
        let mut p = LowerCtx {
            ..Default::default()
        };
        p.lower_ffi_imports(ast);
        p.lower_ffi_modules(ffi_modules);
        p.lower_actions(ast);
        p.lower_cmds(ast);
        p.lower_effects(ast);
        p.lower_enums(ast);
        p.lower_facts(ast);
        p.lower_finish_funcs(ast);
        p.lower_funcs(ast);
        p.lower_globals(ast);
        p.lower_structs(ast);
        p
    }

    fn lower<T, U>(&mut self, item: &'ast T) -> T::Result
    where
        T: Lower<U>,
    {
        item.lower(self)
    }

    /// Lowers a list.
    fn lower_list<I, T, U, R>(&mut self, list: I) -> R
    where
        I: IntoIterator<Item = &'ast T>,
        T: Lower<U> + 'ast,
        R: FromIterator<T::Result>,
    {
        list.into_iter().map(|item| item.lower(self)).collect()
    }

    /// Lowers an [`ast::Identifier`].
    fn lower_ident(&mut self, ident: &'ast ast::Identifier) -> IdentId {
        let id = self.ast.idents.insert_with_key(|id| Ident {
            id,
            span: Span::dummy(), // Identifiers don't have their own span in the AST
            ident: ident.clone(),
        });
        self.arena.idents.insert(id, Cow::Borrowed(ident));
        id
    }

    /// Lowers a [`ast::VType`].
    fn lower_vtype(&mut self, vtype: &'ast ast::VType) -> VTypeId {
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
        let id = self.ast.types.insert_with_key(|id| VType { 
            id, 
            span: Span::dummy(), // Types don't have their own span in the AST
            kind 
        });
        self.arena.types.insert(id, Cow::Borrowed(vtype));
        id
    }

    /// Lowers an [`ast::Expression`].
    fn lower_expr(&mut self, expr: &'ast ast::Expression) -> ExprId {
        let kind = match expr {
            ast::Expression::Int(v) => ExprKind::Int(*v),
            ast::Expression::String(v) => ExprKind::String(v.clone()),
            ast::Expression::Bool(v) => ExprKind::Bool(*v),
            ast::Expression::Optional(v) => ExprKind::Optional(v.lower(self)),
            ast::Expression::NamedStruct(v) => ExprKind::NamedStruct(NamedStruct {
                ident: self.lower_ident(&v.identifier),
                fields: self.lower_list::<_, _, (IdentId, ExprId), _>(&v.fields),
            }),
            ast::Expression::InternalFunction(v) => match v {
                ast::InternalFunction::Query(fact) => {
                    ExprKind::InternalFunction(InternalFunction::Query(fact.lower(self)))
                }
                ast::InternalFunction::Exists(fact) => {
                    ExprKind::InternalFunction(InternalFunction::Exists(fact.lower(self)))
                }
                ast::InternalFunction::FactCount(count_type, limit, fact) => {
                    ExprKind::InternalFunction(InternalFunction::FactCount(
                        count_type.lower(self),
                        *limit,
                        fact.lower(self),
                    ))
                }
                ast::InternalFunction::If(cond, then_expr, else_expr) => {
                    ExprKind::InternalFunction(InternalFunction::If(
                        self.lower_expr(cond),
                        self.lower_expr(then_expr),
                        self.lower_expr(else_expr),
                    ))
                }
                ast::InternalFunction::Serialize(expr) => {
                    ExprKind::InternalFunction(InternalFunction::Serialize(self.lower_expr(expr)))
                }
                ast::InternalFunction::Deserialize(expr) => {
                    ExprKind::InternalFunction(InternalFunction::Deserialize(self.lower_expr(expr)))
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
            ast::Expression::EnumReference(v) => ExprKind::EnumReference(EnumReference {
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
            ast::Expression::Match(match_expr) => {
                ExprKind::Match(self.lower_expr(&match_expr.scrutinee))
            }
        };
        let id = self.ast.exprs.insert_with_key(|id| Expr { 
            id, 
            span: Span::dummy(), // Expressions don't have direct spans in the AST
            kind 
        });
        self.arena.exprs.insert(id, Cow::Borrowed(expr));
        id
    }

    /// Lowers a [`ast::Statement`].
    fn lower_stmt(&mut self, stmt: &'ast AstNode<ast::Statement>) -> StmtId {
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
                branches: self.lower_list::<_, _, IfBranch, _>(&v.branches),
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
                exor: self.lower_expr(v),
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
        let id = self.ast.stmts.insert_with_key(|id| Stmt { 
            id, 
            span: Span::point(stmt.locator),
            kind 
        });
        self.arena.stmts.insert(id, Cow::Borrowed(stmt));
        id
    }

    /// Lowers a block.
    fn lower_block(&mut self, block: &'ast Vec<AstNode<ast::Statement>>) -> BlockId {
        let stmts = self.lower_stmts(block);
        // Use the span from the first statement if available, otherwise dummy
        let span = block.first()
            .map(|stmt| Span::point(stmt.locator))
            .unwrap_or_else(Span::dummy);
        let id = self.ast.blocks.insert_with_key(|id| Block { 
            id, 
            span,
            stmts 
        });
        self.arena.blocks.insert(id, Cow::Borrowed(block));
        id
    }

    fn lower_stmts(&mut self, stmts: &'ast Vec<AstNode<ast::Statement>>) -> Vec<StmtId> {
        self.lower_list(stmts)
    }

    fn lower_actions(&mut self, ast: &'ast Policy) {
        self.lower_list::<_, _, ActionDef, Discard>(&ast.actions);
    }

    fn lower_action(&mut self, node: &'ast AstNode<ast::ActionDefinition>) -> ActionId {
        let ident = self.lower_ident(&node.identifier);
        let args: Vec<ActionArgId> = self.lower_list::<_, _, ActionArg, _>(&node.arguments);
        let block = self.lower_block(&node.statements);
        let id = self.ast.actions.insert_with_key(|id| ActionDef {
            id,
            span: Span::point(node.locator),
            ident,
            args,
            block,
        });
        self.arena.actions.insert(id, Cow::Borrowed(node));
        id
    }

    fn lower_action_arg(&mut self, node: &'ast ast::FieldDefinition) -> ActionArgId {
        let ident = self.lower_ident(&node.identifier);
        let ty = self.lower_vtype(&node.field_type);
        let id = self
            .ast
            .action_args
            .insert_with_key(|id| ActionArg { 
                id, 
                span: Span::dummy(), // FieldDefinitions don't have spans in the AST
                ident, 
                ty 
            });
        self.arena.action_args.insert(id, Cow::Borrowed(node));
        id
    }

    fn lower_fact_key(&mut self, node: &'ast ast::FieldDefinition) -> FactKeyId {
        let ident = self.lower_ident(&node.identifier);
        let ty = self.lower_vtype(&node.field_type);
        let id = self
            .ast
            .fact_keys
            .insert_with_key(|id| FactKey { 
                id, 
                span: Span::dummy(), // FieldDefinitions don't have spans in the AST
                ident, 
                ty 
            });
        self.arena.fact_keys.insert(id, Cow::Borrowed(node));
        id
    }

    fn lower_fact_val(&mut self, node: &'ast ast::FieldDefinition) -> FactValId {
        let ident = self.lower_ident(&node.identifier);
        let ty = self.lower_vtype(&node.field_type);
        let id = self
            .ast
            .fact_vals
            .insert_with_key(|id| FactVal { 
                id, 
                span: Span::dummy(), // FieldDefinitions don't have spans in the AST
                ident, 
                ty 
            });
        self.arena.fact_vals.insert(id, Cow::Borrowed(node));
        id
    }

    fn lower_finish_func_arg(&mut self, node: &'ast ast::FieldDefinition) -> FinishFuncArgId {
        let ident = self.lower_ident(&node.identifier);
        let ty = self.lower_vtype(&node.field_type);
        let id = self
            .ast
            .finish_func_args
            .insert_with_key(|id| FinishFuncArg { 
                id, 
                span: Span::dummy(), // FieldDefinitions don't have spans in the AST
                ident, 
                ty 
            });
        self.arena.finish_func_args.insert(id, Cow::Borrowed(node));
        id
    }

    fn lower_func_arg(&mut self, node: &'ast ast::FieldDefinition) -> FuncArgId {
        let ident = self.lower_ident(&node.identifier);
        let ty = self.lower_vtype(&node.field_type);
        let id = self
            .ast
            .func_args
            .insert_with_key(|id| FuncArg { 
                id, 
                span: Span::dummy(), // FieldDefinitions don't have spans in the AST
                ident, 
                ty 
            });
        self.arena.func_args.insert(id, Cow::Borrowed(node));
        id
    }

    fn lower_cmd(&mut self, node: &'ast AstNode<ast::CommandDefinition>) -> CmdId {
        let ident = self.lower_ident(&node.identifier);
        let fields: Vec<CmdFieldId> = self.lower_list::<_, _, CmdField, _>(&node.fields);
        let seal = self.lower_block(&node.seal);
        let open = self.lower_block(&node.open);
        let policy = self.lower_block(&node.policy);
        let recall = self.lower_block(&node.recall);
        let id = self.ast.cmds.insert_with_key(|id| CmdDef {
            id,
            span: Span::point(node.locator),
            ident,
            fields,
            seal,
            open,
            policy,
            recall,
        });
        self.arena.cmds.insert(id, Cow::Borrowed(node));
        id
    }

    fn lower_cmd_field(&mut self, node: &'ast ast::StructItem<ast::FieldDefinition>) -> CmdFieldId {
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
        let id = self
            .ast
            .cmd_fields
            .insert_with_key(|id| CmdField { 
                id, 
                span: Span::dummy(), // StructItem doesn't have span in the AST
                kind 
            });
        self.arena.cmd_fields.insert(id, Cow::Borrowed(node));
        id
    }

    fn lower_effect_field(
        &mut self,
        node: &'ast ast::StructItem<ast::EffectFieldDefinition>,
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
        let id = self
            .ast
            .effect_fields
            .insert_with_key(|id| EffectField { 
                id, 
                span: Span::dummy(), // StructItem doesn't have span in the AST
                kind 
            });
        self.arena.effect_fields.insert(id, Cow::Borrowed(node));
        id
    }

    fn lower_struct_field(
        &mut self,
        node: &'ast ast::StructItem<ast::FieldDefinition>,
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
        let id = self
            .ast
            .struct_fields
            .insert_with_key(|id| StructField { 
                id, 
                span: Span::dummy(), // StructItem doesn't have span in the AST
                kind 
            });
        self.arena.struct_fields.insert(id, Cow::Borrowed(node));
        id
    }

    fn lower_cmds(&mut self, ast: &'ast Policy) {
        for c in &ast.commands {
            self.lower_cmd(c);
        }
    }

    fn lower_effects(&mut self, ast: &'ast Policy) {
        for e in &ast.effects {
            let ident = self.lower_ident(&e.identifier);
            let items = self.lower_list::<_, _, EffectFieldId, _>(&e.items);
            let id = self
                .ast
                .effects
                .insert_with_key(|id| EffectDef { 
                    id, 
                    span: Span::point(e.locator),
                    ident, 
                    items 
                });
            self.arena.effects.insert(id, Cow::Borrowed(e));
        }
    }

    fn lower_enums(&mut self, ast: &'ast Policy) {
        for e in &ast.enums {
            let ident = self.lower_ident(&e.identifier);
            // Lower enum variants as identifiers
            let variants: Vec<IdentId> = e.variants.iter().map(|v| self.lower_ident(v)).collect();
            let id = self.ast.enums.insert_with_key(|id| EnumDef {
                id,
                span: Span::point(e.locator),
                ident,
                variants,
            });
            self.arena.enums.insert(id, Cow::Borrowed(e));
        }
    }

    fn lower_facts(&mut self, ast: &'ast Policy) {
        for f in &ast.facts {
            let ident = self.lower_ident(&f.identifier);
            let keys: Vec<FactKeyId> = self.lower_list::<_, _, FactKey, _>(&f.key);
            let vals: Vec<FactValId> = self.lower_list::<_, _, FactVal, _>(&f.value);
            let id = self.ast.facts.insert_with_key(|id| FactDef {
                id,
                span: Span::point(f.locator),
                ident,
                keys,
                vals,
            });
            self.arena.facts.insert(id, Cow::Borrowed(f));
        }
    }

    fn lower_finish_funcs(&mut self, ast: &'ast Policy) {
        for f in &ast.finish_functions {
            let ident = self.lower_ident(&f.identifier);
            let args: Vec<FinishFuncArgId> =
                self.lower_list::<_, _, FinishFuncArg, _>(&f.arguments);
            let block = self.lower_block(&f.statements);
            let id = self.ast.finish_funcs.insert_with_key(|id| FinishFuncDef {
                id,
                span: Span::point(f.locator),
                ident,
                args,
                block,
            });
            self.arena.finish_funcs.insert(id, Cow::Borrowed(f));
        }
    }

    fn lower_funcs(&mut self, ast: &'ast Policy) {
        for f in &ast.functions {
            let ident = self.lower_ident(&f.identifier);
            let args: Vec<FuncArgId> = self.lower_list::<_, _, FuncArg, _>(&f.arguments);
            let result = self.lower_vtype(&f.return_type);
            let block = self.lower_block(&f.statements);
            let id = self.ast.funcs.insert_with_key(|id| FuncDef {
                id,
                span: Span::point(f.locator),
                ident,
                args,
                result,
                block,
            });
            self.arena.funcs.insert(id, Cow::Borrowed(f));
        }
    }

    fn lower_globals(&mut self, ast: &'ast Policy) {
        for g in &ast.global_lets {
            let ident = self.lower_ident(&g.identifier);
            let expr = self.lower_expr(&g.expression);
            let id = self
                .ast
                .global_lets
                .insert_with_key(|id| GlobalLetDef { 
                    id, 
                    span: Span::point(g.locator),
                    ident, 
                    expr 
                });
            self.arena.global_lets.insert(id, Cow::Borrowed(g));
        }
    }

    fn lower_structs(&mut self, ast: &'ast Policy) {
        for s in &ast.structs {
            let ident = self.lower_ident(&s.identifier);
            let items: Vec<StructFieldId> = self.lower_list::<_, _, StructFieldId, _>(&s.items);
            let id = self
                .ast
                .structs
                .insert_with_key(|id| StructDef { 
                    id, 
                    span: Span::point(s.locator),
                    ident, 
                    items 
                });
            self.arena.structs.insert(id, Cow::Borrowed(s));
        }
    }

    fn lower_ffi_imports(&mut self, ast: &'ast Policy) {
        for import in &ast.ffi_imports {
            let module = self.lower_ident(import);
            self.ast
                .ffi_imports
                .insert_with_key(|id| FfiImportDef { 
                    id, 
                    span: Span::dummy(), // FFI imports don't have spans in the AST
                    module 
                });
        }
    }

    fn lower_ffi_modules(&mut self, ffi_modules: &'ast [ModuleSchema<'ast>]) {
        for module in ffi_modules {
            let name = self.lower_ident(&module.name);

            // Lower FFI functions
            let mut functions = Vec::new();
            for func in module.functions {
                let func_name = self.lower_ident(&func.name);
                let mut args = Vec::new();
                for arg in func.args {
                    let arg_name = self.lower_ident(&arg.name);
                    let arg_type = self.lower_ffi_type(&arg.vtype);
                    args.push((arg_name, arg_type));
                }
                let return_type = self.lower_ffi_type(&func.return_type);
                let func_id = self.ast.ffi_funcs.insert_with_key(|id| FfiFuncDef {
                    id,
                    span: Span::dummy(), // FFI functions don't have spans in the AST
                    name: func_name,
                    args,
                    return_type,
                });
                functions.push(func_id);
            }

            // Lower FFI structs
            let mut structs = Vec::new();
            for ffi_struct in module.structs {
                let struct_name = self.lower_ident(&ffi_struct.name);
                let mut fields = Vec::new();
                for field in ffi_struct.fields {
                    let field_name = self.lower_ident(&field.name);
                    let field_type = self.lower_ffi_type(&field.vtype);
                    fields.push((field_name, field_type));
                }
                let struct_id = self.ast.ffi_structs.insert_with_key(|id| FfiStructDef {
                    id,
                    span: Span::dummy(), // FFI structs don't have spans in the AST
                    name: struct_name,
                    fields,
                });
                structs.push(struct_id);
            }

            // Lower FFI enums
            let mut enums = Vec::new();
            for ffi_enum in module.enums {
                let enum_name = self.lower_ident(&ffi_enum.name);
                let variants = ffi_enum
                    .variants
                    .iter()
                    .map(|v| self.lower_ident(v))
                    .collect();
                let enum_id = self.ast.ffi_enums.insert_with_key(|id| FfiEnumDef {
                    id,
                    span: Span::dummy(), // FFI enums don't have spans in the AST
                    name: enum_name,
                    variants,
                });
                enums.push(enum_id);
            }

            self.ast.ffi_modules.insert_with_key(|id| FfiModuleDef {
                id,
                span: Span::dummy(), // FFI modules don't have span in the AST
                name,
                functions,
                structs,
                enums,
            });
        }
    }

    /// Lowers an FFI type to a VType.
    fn lower_ffi_type(&mut self, ffi_type: &'ast ffi::Type<'ast>) -> VTypeId {
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
        self.ast.types.insert_with_key(|id| VType { 
            id, 
            span: Span::dummy(), // FFI types don't have spans in the AST
            kind 
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

impl Lower<VType> for ast::VType {
    type Result = VTypeId;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_vtype(self)
    }
}

impl Lower<Expr> for ast::Expression {
    type Result = ExprId;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_expr(self)
    }
}

impl Lower<Stmt> for AstNode<ast::Statement> {
    type Result = StmtId;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_stmt(self)
    }
}

impl Lower<Block> for Vec<AstNode<ast::Statement>> {
    type Result = BlockId;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_block(self)
    }
}

impl Lower<ActionDef> for AstNode<ast::ActionDefinition> {
    type Result = ActionId;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_action(self)
    }
}

impl Lower<MatchPattern> for ast::MatchPattern {
    type Result = MatchPattern;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        match self {
            ast::MatchPattern::Default => MatchPattern::Default,
            ast::MatchPattern::Values(values) => MatchPattern::Values(ctx.lower_list(values)),
        }
    }
}

impl Lower<MatchArm> for ast::MatchArm {
    type Result = MatchArm;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        MatchArm {
            pattern: self.pattern.lower(ctx),
            block: ctx.lower_block(&self.statements),
        }
    }
}

impl Lower<FactLiteral> for ast::FactLiteral {
    type Result = FactLiteral;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        FactLiteral {
            ident: ctx.lower_ident(&self.identifier),
            keys: ctx.lower_list::<_, _, (IdentId, FactField), _>(&self.key_fields),
            vals: ctx
                .lower_list::<_, _, (IdentId, FactField), _>(self.value_fields.iter().flatten()),
        }
    }
}

impl Lower<FactField> for ast::FactField {
    type Result = FactField;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        match self {
            ast::FactField::Expression(expr) => FactField::Expr(ctx.lower_expr(expr)),
            ast::FactField::Bind => FactField::Bind,
        }
    }
}

impl Lower<FactKey> for ast::FieldDefinition {
    type Result = FactKeyId;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_fact_key(self)
    }
}

impl Lower<FactVal> for ast::FieldDefinition {
    type Result = FactValId;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_fact_val(self)
    }
}

impl Lower<FinishFuncArg> for ast::FieldDefinition {
    type Result = FinishFuncArgId;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_finish_func_arg(self)
    }
}

impl Lower<FuncArg> for ast::FieldDefinition {
    type Result = FuncArgId;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_func_arg(self)
    }
}

impl Lower<ActionArg> for ast::FieldDefinition {
    type Result = ActionArgId;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_action_arg(self)
    }
}

impl Lower<CmdField> for ast::StructItem<ast::FieldDefinition> {
    type Result = CmdFieldId;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_cmd_field(self)
    }
}

impl Lower<IfBranch> for (ast::Expression, Vec<AstNode<ast::Statement>>) {
    type Result = IfBranch;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        IfBranch {
            expr: ctx.lower_expr(&self.0),
            block: ctx.lower_block(&self.1),
        }
    }
}

impl Lower<(IdentId, ExprId)> for (ast::Identifier, ast::Expression) {
    type Result = (IdentId, ExprId);
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        (ctx.lower_ident(&self.0), ctx.lower_expr(&self.1))
    }
}

impl Lower<(IdentId, FactField)> for (ast::Identifier, ast::FactField) {
    type Result = (IdentId, FactField);
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        (ctx.lower_ident(&self.0), self.1.lower(ctx))
    }
}

impl Lower<EffectFieldId> for ast::StructItem<ast::EffectFieldDefinition> {
    type Result = EffectFieldId;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_effect_field(self)
    }
}

impl Lower<StructFieldId> for ast::StructItem<ast::FieldDefinition> {
    type Result = StructFieldId;
    fn lower<'ast>(&'ast self, ctx: &mut LowerCtx<'ast>) -> Self::Result {
        ctx.lower_struct_field(self)
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
