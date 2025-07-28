use std::borrow::Cow;

use aranya_policy_ast::{self as ast, AstNode};
use serde::{Deserialize, Serialize};
use slotmap::SecondaryMap;

use crate::hir::hir::{
    ActionArgId, ActionId, BlockId, CmdFieldId, CmdId, EffectFieldId, EffectId, EnumId, ExprId,
    FactId, FactKeyId, FactValId, FinishFuncArgId, FinishFuncId, FuncArgId, FuncId, GlobalId,
    IdentId, StmtId, StructFieldId, StructId, VTypeId,
};

/// An arena of AST nodes.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct AstNodes<'ast> {
    pub actions: SecondaryMap<ActionId, Cow<'ast, AstNode<ast::ActionDefinition>>>,
    pub action_args: SecondaryMap<ActionArgId, Cow<'ast, ast::FieldDefinition>>,
    pub cmds: SecondaryMap<CmdId, Cow<'ast, AstNode<ast::CommandDefinition>>>,
    pub cmd_fields: SecondaryMap<CmdFieldId, Cow<'ast, ast::StructItem<ast::FieldDefinition>>>,
    pub effects: SecondaryMap<EffectId, Cow<'ast, AstNode<ast::EffectDefinition>>>,
    pub effect_fields:
        SecondaryMap<EffectFieldId, Cow<'ast, ast::StructItem<ast::EffectFieldDefinition>>>,
    pub enums: SecondaryMap<EnumId, Cow<'ast, AstNode<ast::EnumDefinition>>>,
    pub facts: SecondaryMap<FactId, Cow<'ast, AstNode<ast::FactDefinition>>>,
    pub fact_keys: SecondaryMap<FactKeyId, Cow<'ast, ast::FieldDefinition>>,
    pub fact_vals: SecondaryMap<FactValId, Cow<'ast, ast::FieldDefinition>>,
    pub finish_funcs: SecondaryMap<FinishFuncId, Cow<'ast, AstNode<ast::FinishFunctionDefinition>>>,
    pub finish_func_args: SecondaryMap<FinishFuncArgId, Cow<'ast, ast::FieldDefinition>>,
    pub funcs: SecondaryMap<FuncId, Cow<'ast, AstNode<ast::FunctionDefinition>>>,
    pub func_args: SecondaryMap<FuncArgId, Cow<'ast, ast::FieldDefinition>>,
    pub global_lets: SecondaryMap<GlobalId, Cow<'ast, AstNode<ast::GlobalLetStatement>>>,
    pub structs: SecondaryMap<StructId, Cow<'ast, AstNode<ast::StructDefinition>>>,
    pub struct_fields:
        SecondaryMap<StructFieldId, Cow<'ast, ast::StructItem<ast::FieldDefinition>>>,
    pub stmts: SecondaryMap<StmtId, Cow<'ast, AstNode<ast::Statement>>>,
    pub exprs: SecondaryMap<ExprId, Cow<'ast, ast::Expression>>,
    pub idents: SecondaryMap<IdentId, Cow<'ast, ast::Identifier>>,
    pub blocks: SecondaryMap<BlockId, Cow<'ast, Vec<AstNode<ast::Statement>>>>,
    pub types: SecondaryMap<VTypeId, Cow<'ast, ast::VType>>,
}
