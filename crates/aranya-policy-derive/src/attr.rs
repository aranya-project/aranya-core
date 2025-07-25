//! Attribute support is largely borrowed from serde.

use std::fmt;

use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::{
    Error, Expr, ExprLit, Ident, Lit, LitStr, Path, meta::ParseNestedMeta, spanned::Spanned,
};

/// An attribute name,
#[derive(Copy, Clone)]
pub(crate) struct Symbol(pub(crate) &'static str);

impl PartialEq<Symbol> for Ident {
    fn eq(&self, word: &Symbol) -> bool {
        self == word.0
    }
}

impl PartialEq<Symbol> for &Ident {
    fn eq(&self, word: &Symbol) -> bool {
        *self == word.0
    }
}

impl PartialEq<Symbol> for Path {
    fn eq(&self, word: &Symbol) -> bool {
        self.is_ident(word.0)
    }
}

impl PartialEq<Symbol> for &Path {
    fn eq(&self, word: &Symbol) -> bool {
        self.is_ident(word.0)
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An attribute.
pub(crate) struct Attr<T> {
    name: Symbol,
    tokens: TokenStream,
    value: Option<T>,
}

impl<T> Attr<T> {
    /// Creates a new, unset attribute.
    pub fn none(name: Symbol) -> Self {
        Self {
            name,
            tokens: TokenStream::new(),
            value: None,
        }
    }

    /// Sets the attribute's value.
    pub fn set<A: ToTokens>(&mut self, obj: A, value: T) -> syn::Result<()> {
        let tokens = obj.into_token_stream();
        if self.value.is_some() {
            Err(Error::new(
                tokens.span(),
                format!("duplicate value: {}", self.name),
            ))
        } else {
            self.tokens = tokens;
            self.value = Some(value);
            Ok(())
        }
    }

    /// Returns the inner value.
    pub fn get(self) -> Option<T> {
        self.value
    }
}

pub(crate) fn get_lit_str(name: Symbol, meta: &ParseNestedMeta<'_>) -> syn::Result<LitStr> {
    get_lit_str2(name, name, meta)
}

fn get_lit_str2(
    name: Symbol,
    meta_item_name: Symbol,
    meta: &ParseNestedMeta<'_>,
) -> syn::Result<LitStr> {
    let expr: Expr = meta.value()?.parse()?;
    let mut value = &expr;
    while let Expr::Group(e) = value {
        value = &e.expr;
    }
    if let Expr::Lit(ExprLit {
        lit: Lit::Str(lit), ..
    }) = value
    {
        let suffix = lit.suffix();
        if !suffix.is_empty() {
            Err(Error::new(
                lit.span(),
                format!("unexpected suffix `{}` on string literal", suffix),
            ))
        } else {
            Ok(lit.clone())
        }
    } else {
        Err(Error::new(
            expr.span(),
            format!(
                "expected {} attribute to be a string: `{} = \"...\"`",
                name, meta_item_name
            ),
        ))
    }
}
