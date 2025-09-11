//! Taken from [`cxx`].
//!
//! [`cxx`]: https://github.com/dtolnay/cxx/blob/afd4aa3f3d4e5d5e9a3a41d09df3408f5f86a469/syntax/doc.rs

use std::fmt;

use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::LitStr;

/// A collection of `#[doc]` attributes.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub(crate) struct Doc {
    pub hidden: bool,
    fragments: Vec<LitStr>,
}

impl Doc {
    /// Creates an empty `Doc`.
    pub const fn new() -> Self {
        Self {
            hidden: false,
            fragments: Vec::new(),
        }
    }

    /// Adds a `#[doc]` attribute.
    pub fn push(&mut self, lit: LitStr) {
        // Skip `/// cbindgen:blah` comments.
        if !lit.value().trim().starts_with("cbindgen:") {
            self.fragments.push(lit);
        }
    }
}

impl<'a> IntoIterator for &'a mut Doc {
    type Item = &'a mut LitStr;
    type IntoIter = <&'a mut Vec<LitStr> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.fragments.iter_mut()
    }
}

impl fmt::Display for Doc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for lit in &self.fragments {
            writeln!(f, "{}", lit.value())?;
        }
        Ok(())
    }
}

impl ToTokens for Doc {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let fragments = &self.fragments;
        tokens.extend(quote! { #(#[doc = #fragments])* });
        if self.hidden {
            tokens.extend(quote! { #[doc(hidden)] });
        }
    }
}
