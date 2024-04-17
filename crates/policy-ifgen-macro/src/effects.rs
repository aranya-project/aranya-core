use proc_macro2::TokenStream;
use quote::quote;
use syn::ItemEnum;

use crate::common::get_derive;

pub(super) fn parse(_attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let enumeration: ItemEnum = syn::parse2(item)?;

    let ident = &enumeration.ident;

    let idents = enumeration.variants.iter().map(|v| &v.ident);
    let names = enumeration.variants.iter().map(|v| v.ident.to_string());

    let derive = get_derive();

    Ok(quote! {
        #derive
        #enumeration

        impl ::core::convert::TryFrom<::policy_ifgen::VmEffect> for #ident {
            type Error = ::policy_ifgen::EffectsParseError;
            fn try_from((name, fields): ::policy_ifgen::VmEffect) -> ::core::result::Result<Self, Self::Error> {
                match name.as_str() {
                    #(
                        #names => fields.try_into().map(Self::#idents),
                    )*
                    _ => ::core::result::Result::Err(::policy_ifgen::EffectsParseError::UnknownEffectName),
                }
            }
        }
    })
}
