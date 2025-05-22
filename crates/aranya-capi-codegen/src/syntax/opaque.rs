use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{
    parse::{Parse, ParseStream, Result},
    Error, Ident, LitBool, LitInt,
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
    /// Whether this attribute is in generated code.
    ///
    /// Will be enabled on generated aliases.
    /// Determines whether to wrap in `Opaque` or apply `cfg(cbindgen)` def.
    pub generated: bool,
}

impl Opaque {
    pub(super) fn parse(ctx: Option<&Ctx>, input: ParseStream<'_>) -> Result<Self> {
        mod kw {
            syn::custom_keyword!(size);
            syn::custom_keyword!(align);
            syn::custom_keyword!(capi);
            syn::custom_keyword!(generated);
        }
        const SIZE: Symbol = Symbol("size");
        const ALIGN: Symbol = Symbol("align");
        const CAPI: Symbol = Symbol("capi");
        const GENERATED: Symbol = Symbol("generated");

        let mut size = Attr::none(ALIGN);
        let mut align = Attr::none(SIZE);
        let mut capi = Attr::none(CAPI);
        let mut generated = Attr::none(GENERATED);

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
            } else if lookahead.peek(kw::generated) {
                let KeyValPair { key, val } =
                    input.parse::<KeyValPair<kw::generated, LitBool>>()?;
                generated.set(key, val)?;
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
        let generated = generated.get().is_some_and(|a| a.value);
        Ok(Self {
            size,
            align,
            capi,
            generated,
        })
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
        let generated = self.generated;
        // TODO(eric): `capi`?
        tokens.extend(quote! {
            #[#capi::opaque(size = #size, align = #align, generated = #generated)]
        })
    }
}
