use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::{
    ItemConst, ItemEnum, ItemFn, ItemImpl, ItemStruct, ItemType, ItemUnion, ItemUse, Result,
    parse::{Parse, ParseStream},
};

/// An item that can appear inside a C API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Item {
    /// `const FOO: u16 = ...`;
    Const(ItemConst),
    /// `enum Foo { ...  }`.
    Enum(ItemEnum),
    /// `fn foo() { ... }`.
    Fn(ItemFn),
    /// `impl Bar for Foo { ... }`.
    Impl(ItemImpl),
    /// Something else.
    Other(syn::Item),
    /// `struct Foo { ... }`.
    Struct(ItemStruct),
    /// `type Foo = ...`.
    Type(ItemType),
    /// `union Foo { ... }`.
    Union(ItemUnion),
    /// `use crate::Foo;`.
    Use(ItemUse),
}

macro_rules! from_impl {
    ($($from:ty => $variant:ident),+ $(,)?) => {
        $(
            impl From<$from> for Item {
                fn from(v: $from) -> Self {
                    Self::$variant(v)
                }
            }
        )+
    };
}
from_impl! {
    ItemConst => Const,
    ItemEnum => Enum,
    ItemImpl => Impl,
    ItemStruct => Struct,
    ItemType => Type,
    ItemUnion => Union,
    ItemUse => Use,
}

impl From<syn::Item> for Item {
    fn from(item: syn::Item) -> Self {
        match item {
            syn::Item::Const(v) => Self::Const(v),
            syn::Item::Enum(v) => Self::Enum(v),
            syn::Item::Fn(v) => Self::Fn(v),
            syn::Item::Impl(v) => Self::Impl(v),
            syn::Item::Struct(v) => Self::Struct(v),
            syn::Item::Type(v) => Self::Type(v),
            syn::Item::Union(v) => Self::Union(v),
            syn::Item::Use(v) => Self::Use(v),
            other => Self::Other(other),
        }
    }
}

impl Parse for Item {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let item = input.parse::<syn::Item>()?;
        Ok(item.into())
    }
}

impl ToTokens for Item {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            Self::Const(v) => v.to_tokens(tokens),
            Self::Enum(v) => v.to_tokens(tokens),
            Self::Fn(v) => v.to_tokens(tokens),
            Self::Impl(v) => v.to_tokens(tokens),
            Self::Struct(v) => v.to_tokens(tokens),
            Self::Type(v) => v.to_tokens(tokens),
            Self::Union(v) => v.to_tokens(tokens),
            Self::Use(v) => v.to_tokens(tokens),
            Self::Other(v) => v.to_tokens(tokens),
        }
    }
}
