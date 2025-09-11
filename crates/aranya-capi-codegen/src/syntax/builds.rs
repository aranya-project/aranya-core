use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::{
    Error, Ident,
    parse::{Parse, ParseStream, Result},
};

/// The `#[capi::builds(TYPE)]` attribute.
///
/// It can only be applied to structs or aliases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Builds {
    /// The name of the type being built.
    pub ty: Ident,
}

impl Builds {
    pub(super) fn parse(input: ParseStream<'_>) -> Result<Self> {
        let ty = input.parse()?;
        if !input.is_empty() {
            return Err(Error::new(input.span(), "unexpected data"));
        }
        Ok(Self { ty })
    }
}

impl Parse for Builds {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        Self::parse(input)
    }
}

impl ToTokens for Builds {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let ty = &self.ty;
        tokens.extend(quote! {
            #[capi::builds(#ty)]
        });
    }
}
