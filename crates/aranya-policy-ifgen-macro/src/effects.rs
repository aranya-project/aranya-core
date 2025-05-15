use proc_macro2::TokenStream;
use quote::quote;
use syn::{ext::IdentExt as _, ItemEnum};

use crate::common::get_derive;

pub(super) fn parse(_attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let enumeration: ItemEnum = syn::parse2(item)?;

    let ident = &enumeration.ident;

    let idents = enumeration
        .variants
        .iter()
        .map(|v| &v.ident)
        .collect::<Vec<_>>();
    let names = enumeration
        .variants
        .iter()
        .map(|v| v.ident.unraw().to_string())
        .collect::<Vec<_>>();

    let derive = get_derive();

    Ok(quote! {
        #derive
        #enumeration

        impl #ident {
            /// Gives the name of the effect.
            pub fn name(&self) -> &'static ::core::primitive::str {
                match self {
                    #(
                        Self::#idents{..} => #names,
                    )*
                }
            }
        }

        impl ::core::convert::TryFrom<::aranya_policy_ifgen::VmEffect> for #ident {
            type Error = ::aranya_policy_ifgen::EffectsParseError;
            fn try_from(eff: ::aranya_policy_ifgen::VmEffect) -> ::core::result::Result<Self, Self::Error> {
                match eff.name.as_str() {
                    #(
                        #names => eff.fields.try_into().map(Self::#idents),
                    )*
                    _ => ::core::result::Result::Err(::aranya_policy_ifgen::EffectsParseError::UnknownEffectName),
                }
            }
        }
    })
}
