use proc_macro2::TokenStream;
use quote::quote;
use syn::{spanned::Spanned, ItemStruct};

use crate::common::get_derive;

pub(super) fn parse(_attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let strukt: ItemStruct = syn::parse2(item)?;

    let ident = &strukt.ident;
    let name = ident.to_string();

    let field_idents = strukt
        .fields
        .iter()
        .map(|f| {
            f.ident
                .as_ref()
                .ok_or_else(|| syn::Error::new(f.span(), "tuple structs not allowed"))
        })
        .collect::<syn::Result<Vec<_>>>()?;
    let field_names = field_idents
        .iter()
        .map(|f| f.to_string())
        .collect::<Vec<_>>();

    let derive = get_derive();

    Ok(quote! {
        #derive
        #strukt

        impl ::core::convert::TryFrom<::policy_ifgen::Value> for #ident {
            type Error = ::policy_ifgen::StructParseError;
            fn try_from(value: ::policy_ifgen::Value) -> ::core::result::Result<Self, Self::Error> {
                let ::policy_ifgen::Value::Struct(mut s) = value else {
                    return ::core::result::Result::Err(::policy_ifgen::StructParseError::InvalidType);
                };

                if s.name != #name {
                    return ::core::result::Result::Err(::policy_ifgen::StructParseError::NameMismatch);
                }

                let parsed = Self { #(
                    #field_idents:
                        s.fields.remove(#field_names)
                            .ok_or(::policy_ifgen::StructParseError::MissingField)?
                            .try_into()
                            .map_err(|_| ::policy_ifgen::StructParseError::FieldTypeMismatch)?,
                )* };
                if !s.fields.is_empty() {
                    return ::core::result::Result::Err(::policy_ifgen::StructParseError::ExtraFields);
                }
                ::core::result::Result::Ok(parsed)
            }
        }

        impl ::core::convert::From<#ident> for ::policy_ifgen::Value {
            fn from(s: #ident) -> Self {
                let mut fields = ::policy_ifgen::FieldMap::new();
                #(
                    fields.insert(#field_names.into(), s.#field_idents.into());
                )*
                Self::Struct(::policy_ifgen::Struct {
                    name: #name.into(),
                    fields,
                })
            }
        }
    })
}
