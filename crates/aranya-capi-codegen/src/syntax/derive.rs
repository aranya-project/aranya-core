use std::hash::Hash;

use proc_macro2::{Span, TokenStream};
use quote::{ToTokens, quote, quote_spanned};
use syn::{
    Ident, Path, Token,
    parse::{ParseStream, Result},
};

use crate::ctx::Ctx;

/// The `#[derive(...)]` attribute.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub(crate) struct Derives(Vec<Derive>);

impl Derives {
    /// Creates an empty `Derives`.
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Reports whether it has the [`DeriveTrait`].
    pub fn contains(&self, what: DeriveTrait) -> bool {
        self.0.iter().any(|d| d.what == what)
    }

    pub(super) fn parse(ctx: &Ctx, input: ParseStream<'_>) -> Result<Self> {
        let paths = input.parse_terminated(Path::parse_mod_style, Token![,])?;
        let mut derives = Vec::new();
        for path in paths {
            if let Some(ident) = path.get_ident() {
                if let Some(derive) = Derive::from(ident) {
                    derives.push(derive);
                    continue;
                }
            }
            ctx.error(path, "unsupported derive trait");
        }
        Ok(Self(derives))
    }

    pub(super) fn append(&mut self, mut other: Self) {
        self.0.append(&mut other.0)
    }
}

impl ToTokens for Derives {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let traits = self.0.iter().filter_map(|d| {
            if d.passthrough() {
                let what = &d.what;
                Some(quote!(#[derive(#what)]))
            } else {
                None
            }
        });
        tokens.extend(traits)
    }
}

/// The `#[derive(...)]` attribute.
#[derive(Clone, Debug)]
pub(crate) struct Derive {
    pub what: DeriveTrait,
    pub span: Span,
}

impl Derive {
    fn from(ident: &Ident) -> Option<Self> {
        let what = match ident.to_string().as_str() {
            "Init" => DeriveTrait::Init,
            "Cleanup" => DeriveTrait::Cleanup,
            "ErrorCode" => DeriveTrait::ErrorCode,
            "Copy" => DeriveTrait::Copy,
            "Clone" => DeriveTrait::Clone,
            "Debug" => DeriveTrait::Debug,
            "Default" => DeriveTrait::Default,
            "Eq" => DeriveTrait::Eq,
            "PartialEq" => DeriveTrait::PartialEq,
            _ => return None,
        };
        let span = ident.span();
        Some(Self { what, span })
    }

    /// Should this be passed through to the compiler?
    pub const fn passthrough(&self) -> bool {
        self.what.passthrough()
    }
}

impl Eq for Derive {}
impl PartialEq for Derive {
    fn eq(&self, other: &Self) -> bool {
        self.what == other.what
    }
}

impl PartialEq<DeriveTrait> for Derive {
    fn eq(&self, other: &DeriveTrait) -> bool {
        self.what == *other
    }
}

impl ToTokens for Derive {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let what = &self.what;
        tokens.extend(quote_spanned! {self.span=>
            #what
        })
    }
}

/// A trait being derived.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub(crate) enum DeriveTrait {
    /// Derive `fn foo_init(...)`.
    Init,
    /// Derive `fn foo_cleanup(...)`.
    Cleanup,

    /// Derive a `capi::ErrorCode` impl.
    ErrorCode,

    // `core` traits
    Copy,
    Clone,
    Debug,
    Default,
    Eq,
    PartialEq,
}

impl DeriveTrait {
    /// Should this be passed through to the compiler?
    pub const fn passthrough(self) -> bool {
        match self {
            Self::Init | Self::Cleanup => false,
            Self::ErrorCode
            | Self::Copy
            | Self::Clone
            | Self::Default
            | Self::Debug
            | Self::Eq
            | Self::PartialEq => true,
        }
    }
}

impl ToTokens for DeriveTrait {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        use DeriveTrait::*;
        tokens.extend(match self {
            Init => quote!(::aranya_capi_core::Init),
            Cleanup => quote!(::aranya_capi_core::Cleanup),
            ErrorCode => quote!(::aranya_capi_core::ErrorCode),
            Copy => quote!(::core::marker::Copy),
            Clone => quote!(::core::clone::Clone),
            Default => quote!(::core::default::Default),
            Debug => quote!(::core::fmt::Debug),
            Eq => quote!(::core::cmp::Eq),
            PartialEq => quote!(::core::cmp::PartialEq),
        })
    }
}
