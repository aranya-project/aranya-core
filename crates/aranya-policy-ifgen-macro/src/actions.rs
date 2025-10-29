use proc_macro2::TokenStream;
use quote::quote;
use syn::{ItemEnum, spanned::Spanned as _};

use crate::common::get_derive;

mod kw {
    syn::custom_keyword!(interface);
}

struct Attrs {
    interface: syn::Path,
}

impl syn::parse::Parse for Attrs {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        input.parse::<kw::interface>()?;
        input.parse::<syn::Token![=]>()?;
        let value = input.parse::<syn::Path>()?;
        Ok(Self { interface: value })
    }
}

pub(super) fn parse(attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let Attrs { interface } = syn::parse2(attr)?;

    let act: ItemEnum = syn::parse2(item)?;

    let ident = &act.ident;

    let variants = act.variants.iter().map(|v| &v.ident).collect::<Vec<_>>();
    let subtypes = act
        .variants
        .iter()
        .map(|v| match &v.fields {
            syn::Fields::Unnamed(tuple) => {
                if tuple.unnamed.len() != 1 {
                    return Err(syn::Error::new(tuple.span(), "expected single field"));
                }
                Ok(&tuple.unnamed.first().expect("unreachable").ty)
            }
            _ => Err(syn::Error::new(v.fields.span(), "expected tuple struct")),
        })
        .collect::<syn::Result<Vec<_>>>()?;

    let derive = get_derive();

    Ok(quote! {
        #derive
        #act

        impl ::aranya_policy_ifgen::Actionable for #ident {
            type Interface = #interface;

            fn with_action<R>(self, f: impl for<'a> FnOnce(::aranya_policy_ifgen::VmAction<'a>) -> R) -> R {
                match self {
                    #(
                        Self::#variants(v) => ::aranya_policy_ifgen::Actionable::with_action(v, f),
                    )*
                }
            }
        }

        #(
        impl ::core::convert::From<#subtypes> for #ident {
            fn from(act: #subtypes) -> Self {
                Self::#variants(act)
            }
        }
        )*
    })
}
