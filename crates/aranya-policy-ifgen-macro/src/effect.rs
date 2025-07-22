use proc_macro2::TokenStream;
use quote::quote;
use syn::{ItemStruct, ext::IdentExt as _, spanned::Spanned};

use crate::common::get_derive;

pub(super) fn parse(_attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let strukt: ItemStruct = syn::parse2(item)?;

    let ident = &strukt.ident;
    let name = ident.unraw().to_string();

    let field_idents = strukt
        .fields
        .iter()
        .map(|f| {
            f.ident
                .as_ref()
                .ok_or_else(|| syn::Error::new(f.span(), "tuple structs not allowed"))
        })
        .collect::<syn::Result<Vec<_>>>()?;
    let field_names = field_idents.iter().map(|f| f.unraw().to_string());

    let derive = get_derive();

    Ok(quote! {
        #derive
        #strukt

        impl #ident {
            /// Gives the name of the effect.
            pub fn name(&self) -> &'static ::core::primitive::str {
                #name
            }
        }

        impl ::core::convert::TryFrom<::aranya_policy_ifgen::Fields> for #ident {
            type Error = ::aranya_policy_ifgen::EffectsParseError;
            fn try_from(value: ::aranya_policy_ifgen::Fields) -> ::core::result::Result<Self, Self::Error> {
                let fields = &mut value
                    .into_iter()
                    .map(|kv| kv.into())
                    .collect::<::aranya_policy_ifgen::FieldMap>();
                let parsed = Self { #(
                    #field_idents:
                        ::aranya_policy_ifgen::TryFromValue::try_from_value(
                            fields.remove(#field_names)
                                .ok_or(::aranya_policy_ifgen::EffectsParseError::MissingField)?,
                        )
                        .map_err(|_| ::aranya_policy_ifgen::EffectsParseError::FieldTypeMismatch)?,
                )* };
                if !fields.is_empty() {
                    return ::core::result::Result::Err(::aranya_policy_ifgen::EffectsParseError::ExtraFields);
                }
                ::core::result::Result::Ok(parsed)
            }
        }
    })
}
