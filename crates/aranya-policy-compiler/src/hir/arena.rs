use aranya_policy_ast::{self as ast, AstNode};
use buggy::Bug;
use slotmap::SecondaryMap;

use crate::hir::hir::{
    ActionArgId, ActionId, BlockId, CmdFieldId, CmdId, EffectFieldId, EffectId, EnumId, ExprId,
    FactId, FactKeyId, FactValId, FinishFuncArgId, FinishFuncId, FuncArgId, FuncId, GlobalId,
    IdentId, StmtId, StructFieldId, StructId, VTypeId,
};

/// An arena of AST nodes.
#[derive(Clone, Default, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct AstNodes<'ast> {
    pub actions: SecondaryMap<ActionId, &'ast AstNode<ast::ActionDefinition>>,
    pub action_args: SecondaryMap<ActionArgId, &'ast ast::FieldDefinition>,
    pub cmds: SecondaryMap<CmdId, &'ast AstNode<ast::CommandDefinition>>,
    pub cmd_fields: SecondaryMap<CmdFieldId, &'ast ast::StructItem<ast::FieldDefinition>>,
    pub effects: SecondaryMap<EffectId, &'ast AstNode<ast::EffectDefinition>>,
    pub effect_fields:
        SecondaryMap<EffectFieldId, &'ast ast::StructItem<ast::EffectFieldDefinition>>,
    pub enums: SecondaryMap<EnumId, &'ast AstNode<ast::EnumDefinition>>,
    pub facts: SecondaryMap<FactId, &'ast AstNode<ast::FactDefinition>>,
    pub fact_keys: SecondaryMap<FactKeyId, &'ast ast::FieldDefinition>,
    pub fact_vals: SecondaryMap<FactValId, &'ast ast::FieldDefinition>,
    pub finish_funcs: SecondaryMap<FinishFuncId, &'ast AstNode<ast::FinishFunctionDefinition>>,
    pub finish_func_args: SecondaryMap<FinishFuncArgId, &'ast ast::FieldDefinition>,
    pub funcs: SecondaryMap<FuncId, &'ast AstNode<ast::FunctionDefinition>>,
    pub func_args: SecondaryMap<FuncArgId, &'ast ast::FieldDefinition>,
    pub global_lets: SecondaryMap<GlobalId, &'ast AstNode<ast::GlobalLetStatement>>,
    pub structs: SecondaryMap<StructId, &'ast AstNode<ast::StructDefinition>>,
    pub struct_fields: SecondaryMap<StructFieldId, &'ast ast::StructItem<ast::FieldDefinition>>,
    pub stmts: SecondaryMap<StmtId, &'ast AstNode<ast::Statement>>,
    pub exprs: SecondaryMap<ExprId, &'ast ast::Expression>,
    pub idents: SecondaryMap<IdentId, &'ast ast::Identifier>,
    pub blocks: SecondaryMap<BlockId, &'ast Vec<AstNode<ast::Statement>>>,
    pub types: SecondaryMap<VTypeId, &'ast ast::VType>,
}

// impl<'ast> AstNodes<'ast> {
//     /// Retrieves a particular node.
//     pub fn get<Id: NodeId>(&self, id: Id) -> Result<Id::Node<'ast>, LookupError> {
//         let id = id.into_item_id();
//         let v = *self.nodes.get(id).ok_or(InvalidId(()))?;
//         let item = v.try_into().assume("`id` is of the correct type")?;
//         Ok(item)
//     }
// }

/// An error that occurs when retrieving an AST node.
#[derive(Clone, Debug, thiserror::Error)]
pub enum LookupError {
    /// An internal bug occurred.
    #[error("internal bug: {0}")]
    Bug(#[from] Bug),

    /// The [`NodeId`] is invalid for this [`Nodes`] arena.
    #[error("{0}")]
    InvalidId(#[from] InvalidId),
}

/// The [`Id`] is unknown.
#[derive(Clone, Debug, thiserror::Error)]
#[error("invalid `Id`")]
pub struct InvalidId(());
