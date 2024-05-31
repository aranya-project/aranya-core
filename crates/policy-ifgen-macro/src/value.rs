use proc_macro2::TokenStream;
use quote::quote;
use syn::{spanned::Spanned, Fields, Item, ItemEnum, ItemStruct};

use crate::common::get_derive;

pub(super) fn parse(_attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    match syn::parse2(item)? {
        Item::Struct(strukt) => handle_struct(strukt),
        Item::Enum(enumeration) => handle_enum(enumeration),
        item => Err(syn::Error::new(item.span(), "expected struct or enum")),
    }
}

fn handle_struct(strukt: ItemStruct) -> syn::Result<TokenStream> {
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
            type Error = ::policy_ifgen::ValueConversionError;
            fn try_from(value: ::policy_ifgen::Value) -> ::core::result::Result<Self, Self::Error> {
                let ::policy_ifgen::Value::Struct(mut s) = value else {
                    return ::core::result::Result::Err(::policy_ifgen::ValueConversionError::InvalidType);
                };

                if s.name != #name {
                    return ::core::result::Result::Err(::policy_ifgen::ValueConversionError::InvalidType);
                }

                let parsed = Self { #(
                    #field_idents:
                        ::policy_ifgen::TryFromValue::try_from_value(
                            s.fields.remove(#field_names)
                                .ok_or_else(|| ::policy_ifgen::ValueConversionError::InvalidStructMember(
                                    #field_names.into(),
                                ))?,
                        )?,
                )* };
                if let Some((key, _)) = s.fields.pop_first() {
                    return ::core::result::Result::Err(::policy_ifgen::ValueConversionError::InvalidStructMember(key));
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

fn handle_enum(enumeration: ItemEnum) -> syn::Result<TokenStream> {
    let ident = &enumeration.ident;

    for variant in &enumeration.variants {
        if !matches!(variant.fields, Fields::Unit) {
            return Err(syn::Error::new(
                variant.fields.span(),
                "enum variant fields not allowed",
            ));
        }
    }

    let len = i64::try_from(enumeration.variants.len()).expect("too many variants");

    let var_idents: Vec<_> = enumeration.variants.iter().map(|f| &f.ident).collect();
    let var_vals: Vec<_> = (0..len).collect();

    let derive = get_derive();

    Ok(quote! {
        #derive
        #enumeration

        impl ::core::convert::TryFrom<::policy_ifgen::Value> for #ident {
            type Error = ::policy_ifgen::ValueConversionError;
            fn try_from(value: ::policy_ifgen::Value) -> ::core::result::Result<Self, Self::Error> {
                let ::policy_ifgen::Value::Int(val) = value else {
                    return ::core::result::Result::Err(::policy_ifgen::ValueConversionError::InvalidType);
                };

                match val {
                    #(
                        #var_vals => ::core::result::Result::Ok(Self::#var_idents),
                    )*
                    _ => ::core::result::Result::Err(::policy_ifgen::ValueConversionError::OutOfRange),
                }
            }
        }

        impl ::core::convert::From<#ident> for ::policy_ifgen::Value {
            fn from(e: #ident) -> Self {
                match e {
                    #(
                        #ident::#var_idents => ::policy_ifgen::Value::Int(#var_vals),
                    )*
                }
            }
        }
    })
}
