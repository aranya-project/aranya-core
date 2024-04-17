use proc_macro2::TokenStream;
use quote::quote;
use syn::{spanned::Spanned, ItemStruct};

use crate::common::get_derive;

pub(super) fn parse(_attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let strukt: ItemStruct = syn::parse2(item)?;

    let ident = &strukt.ident;

    let field_idents = strukt
        .fields
        .iter()
        .map(|f| {
            f.ident
                .as_ref()
                .ok_or_else(|| syn::Error::new(f.span(), "tuple structs not allowed"))
        })
        .collect::<syn::Result<Vec<_>>>()?;
    let field_names = field_idents.iter().map(|f| f.to_string());

    let derive = get_derive();

    Ok(quote! {
        #derive
        #strukt

        impl ::core::convert::TryFrom<::policy_ifgen::Fields> for #ident {
            type Error = ::policy_ifgen::EffectsParseError;
            fn try_from(value: ::policy_ifgen::Fields) -> ::core::result::Result<Self, Self::Error> {
                let fields = &mut value
                    .into_iter()
                    .map(|kv| kv.into())
                    .collect::<::policy_ifgen::FieldMap>();
                let parsed = Self { #(
                    #field_idents:
                        fields.remove(#field_names)
                            .ok_or(::policy_ifgen::EffectsParseError::MissingField)?
                            .try_into()
                            .map_err(|_| ::policy_ifgen::EffectsParseError::FieldTypeMismatch)?,
                )* };
                if !fields.is_empty() {
                    return ::core::result::Result::Err(::policy_ifgen::EffectsParseError::ExtraFields);
                }
                ::core::result::Result::Ok(parsed)
            }
        }
    })
}
