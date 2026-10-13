use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::{
    Error, Ident, LitInt,
    parse::{Parse, ParseStream, Result},
};

use crate::{
    attr::{Attr, Symbol},
    ctx::Ctx,
    util::KeyValPair,
};

/// The `#[capi::opaque(size = 42, align = 12)]` attribute.
///
/// It can only be applied to aliases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Opaque {
    /// The size in bytes of the type.
    pub size: LitInt,
    /// The alignment in bytes of the type.
    pub align: LitInt,
    /// Path to the `capi` crate.
    pub capi: Option<Ident>,
}

impl Opaque {
    pub(super) fn parse(ctx: Option<&Ctx>, input: ParseStream<'_>) -> Result<Self> {
        mod kw {
            syn::custom_keyword!(size);
            syn::custom_keyword!(align);
            syn::custom_keyword!(capi);
        }
        const SIZE: Symbol = Symbol("size");
        const ALIGN: Symbol = Symbol("align");
        const CAPI: Symbol = Symbol("capi");

        let mut size = Attr::none(ALIGN);
        let mut align = Attr::none(SIZE);
        let mut capi = Attr::none(CAPI);

        while !input.is_empty() {
            let lookahead = input.lookahead1();
            if lookahead.peek(kw::size) {
                let KeyValPair { key, val } = input.parse::<KeyValPair<kw::size, LitInt>>()?;
                size.set(key, val)?;
            } else if lookahead.peek(kw::align) {
                let KeyValPair { key, val } = input.parse::<KeyValPair<kw::align, LitInt>>()?;
                align.set(key, val)?;
            } else if lookahead.peek(kw::capi) {
                let KeyValPair { key, val } = input.parse::<KeyValPair<kw::capi, Ident>>()?;
                capi.set(key, val)?;
            } else {
                return Err(lookahead.error());
            }
        }

        let size = size.get().ok_or(Error::new(
            input.span(),
            format!("missing `{SIZE}` argument"),
        ))?;
        let align = align.get().ok_or(Error::new(
            input.span(),
            format!("missing `{ALIGN}` argument"),
        ))?;
        let capi = capi.get().or_else(|| ctx.map(|ctx| ctx.capi.clone()));
        Ok(Self { size, align, capi })
    }
}

impl Parse for Opaque {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        Self::parse(None, input)
    }
}

impl ToTokens for Opaque {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let size = &self.size;
        let align = &self.align;
        let capi = &self.capi;
        // TODO(eric): `capi`?
        tokens.extend(quote! {
            #[#capi::opaque(size = #size, align = #align)]
        });
    }
}
