//! Attribute support.

use std::{fmt, iter::Iterator};

use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::{Error, Ident, Path, spanned::Spanned as _};

/// An attribute name,
#[derive(Copy, Clone)]
pub struct Symbol(pub &'static str);

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
        PartialEq::eq(&self, word)
    }
}

impl PartialEq<Symbol> for &Path {
    fn eq(&self, word: &Symbol) -> bool {
        Iterator::eq(
            self.segments.iter().map(|seg| &seg.ident),
            word.0.split("::"),
        )
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An attribute.
pub struct Attr<T> {
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
