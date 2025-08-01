use std::borrow::Cow;

use aranya_policy_ast::{self as ast, AstNode};
use aranya_policy_module::ffi;
use slotmap::SlotMap;

/// Creates an index of the AST.
pub(crate) fn index<'ast>(
    ast: &'ast ast::Policy,
    schemas: &'ast [ffi::ModuleSchema<'ast>],
) -> Index<'ast> {
    macro_rules! collect {
        ($($field:expr),+ $(,)?) => {{
            let mut items = SlotMap::with_key();
            $(for item in $field {
                items.insert(item.into());
            })+
            items
        }};
    }
    let items = collect! {
        &ast.actions,
        &ast.commands,
        &ast.effects,
        &ast.enums,
        &ast.facts,
        &ast.finish_functions,
        &ast.functions,
        &ast.global_lets,
        schemas.iter().flat_map(|s| s.enums),
        schemas.iter().flat_map(|s| s.functions),
        schemas.iter().flat_map(|s| s.structs),
    };
    Index { items }
}

#[derive(Clone, Debug)]
pub(crate) struct Index<'ast> {
    pub(crate) items: SlotMap<ItemId, Item<'ast>>,
}

impl<'ast: 'a, 'a> IntoIterator for &'a Index<'ast> {
    type Item = (ItemId, &'a Item<'ast>);
    type IntoIter = slotmap::basic::Iter<'a, ItemId, Item<'ast>>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

impl<'ast> IntoIterator for Index<'ast> {
    type Item = (ItemId, Item<'ast>);
    type IntoIter = slotmap::basic::IntoIter<ItemId, Item<'ast>>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

macro_rules! item_impl {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident<'ast> {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident(Cow<'ast, $ty:ty>),
            )+
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq)]
        pub(crate) enum $name<'ast> {
            $(
                $(#[$variant_meta])*
                $variant(Cow<'ast, $ty>),
            )+
        }
        $(impl<'ast> From<&'ast $ty> for $name<'ast> {
            fn from(value: &'ast $ty) -> Self {
                $name::$variant(Cow::Borrowed(value))
            }
        })+
    };
}

item_impl! {
    /// An AST item.
    pub(crate) enum Item<'ast> {
        Action(Cow<'ast, AstNode<ast::ActionDefinition>>),
        Cmd(Cow<'ast, AstNode<ast::CommandDefinition>>),
        Effect(Cow<'ast, AstNode<ast::EffectDefinition>>),
        Enum(Cow<'ast, AstNode<ast::EnumDefinition>>),
        Fact(Cow<'ast, AstNode<ast::FactDefinition>>),
        FfiEnum(Cow<'ast, ffi::Enum<'ast>>),
        FfiFunc(Cow<'ast, ffi::Func<'ast>>),
        FfiStruct(Cow<'ast, ffi::Struct<'ast>>),
        FinishFunc(Cow<'ast, AstNode<ast::FinishFunctionDefinition>>),
        Func(Cow<'ast, AstNode<ast::FunctionDefinition>>),
        GlobalLet(Cow<'ast, AstNode<ast::GlobalLetStatement>>),
        Struct(Cow<'ast, AstNode<ast::StructDefinition>>),
    }
}

slotmap::new_key_type! {
    /// Uniquely identifies an [`Item`].
    pub(crate) struct ItemId;
}
