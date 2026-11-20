use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{DataEnum, DataStruct, DeriveInput, spanned::Spanned as _};

pub(crate) fn parse(item: TokenStream) -> syn::Result<TokenStream> {
    let input: DeriveInput = syn::parse2(item)?;
    match &input.data {
        syn::Data::Struct(data) => impl_struct(&input, data),
        syn::Data::Enum(data) => impl_enum(&input, data),
        syn::Data::Union(_) => Err(syn::Error::new(input.span(), "unions are not supported")),
    }
}

fn impl_struct(input: &DeriveInput, data: &DataStruct) -> syn::Result<TokenStream> {
    let name = &input.ident;
    let name_str = name.to_string();

    let field_names = data
        .fields
        .iter()
        .map(|f| {
            f.ident
                .as_ref()
                .ok_or_else(|| syn::Error::new(f.span(), "Expected named field"))
        })
        .collect::<syn::Result<Vec<_>>>()?;

    let field_locals = field_names
        .iter()
        .map(|name| format_ident!("__field_{name}"))
        .collect::<Vec<_>>();

    let field_types = data.fields.iter().map(|f| &f.ty);

    let vm: syn::Path = syn::parse_quote!(::aranya_policy_vm);

    Ok(quote! {
        #[automatically_derived]
        impl ::core::convert::From<#name> for #vm::Value {
            fn from(__value: #name) -> Self {
                #vm::Value::from(#vm::Struct::from(__value))
            }
        }

        #[automatically_derived]
        impl ::core::convert::From<#name> for #vm::Struct {
            fn from(__value: #name) -> Self {
                #vm::Struct::new(
                    #vm::ident!(stringify!(#name)),
                    &[
                        #(#vm::KVPair::new(
                            #vm::ident!(stringify!(#field_names)),
                            __value.#field_names.into(),
                        )),*,
                    ],
                )
            }
        }


        #[automatically_derived]
        impl ::core::convert::TryFrom<#vm::Value> for #name {
            type Error = #vm::ValueConversionError;

            fn try_from(mut __value: #vm::Value) -> ::core::result::Result<Self, Self::Error> {
                let #vm::Value::Struct(__struct) = &mut __value else {
                    return ::core::result::Result::Err(
                        #vm::ValueConversionError::invalid_type(
                            ::core::concat!("Struct ", #name_str),
                            __value.type_name(),
                            "TryFrom"
                        ));
                };
                if __struct.name != ::core::stringify!(#name) {
                    return ::core::result::Result::Err(
                        #vm::ValueConversionError::invalid_type(
                            ::core::concat!("Struct ", #name_str),
                            __value.type_name(),
                            "name doesn't match"
                        ));
                }
                #(
                    let #field_locals = __struct.fields.remove(::core::stringify!(#field_names))
                        .ok_or(#vm::ValueConversionError::InvalidStructMember(
                                #vm::ident!(stringify!(#field_names)),
                        ))?;
                )*
                if !__struct.fields.is_empty() {
                    return ::core::result::Result::Err(#vm::ValueConversionError::BadState);
                }
                ::core::result::Result::Ok(#name {
                    #(
                        #field_names: #vm::TryFromValue::try_from_value(#field_locals)?
                    ),*
                })
            }
        }

        #[automatically_derived]
        impl #vm::ffi::Typed for #name {
            const TYPE: #vm::ffi::Type<'static> = #vm::ffi::Type::Struct(#vm::ident!(#name_str));
        }

        #[automatically_derived]
        impl #name {
            const SCHEMA: #vm::ffi::Struct<'static> =
                #vm::ffi::Struct {
                    name: #vm::ident!(#name_str),
                    fields: &[#(
                        #vm::ffi::Arg {
                            name: #vm::ident!(stringify!(#field_names)),
                            vtype: <#field_types as #vm::ffi::Typed>::TYPE,
                        },
                    )*],
                };
        }
    })
}

fn impl_enum(input: &DeriveInput, data: &DataEnum) -> syn::Result<TokenStream> {
    let name = &input.ident;
    let name_str = name.to_string();

    let variants = data
        .variants
        .iter()
        .map(|variant| {
            assert!(variant.fields.is_empty());
            &variant.ident
        })
        .collect::<Vec<_>>();

    let var_const_names: Vec<_> = variants
        .iter()
        .map(|id| format_ident!("__{name}__{id}"))
        .collect();

    let vm: syn::Path = syn::parse_quote!(::aranya_policy_vm);

    Ok(quote! {
        #[automatically_derived]
        impl ::core::convert::From<#name> for #vm::Value {
            fn from(__value: #name) -> Self {
                #vm::Value::Enum(
                    #vm::ident!(#name_str),
                    __value as i64,
                )
            }
        }

        #[automatically_derived]
        impl ::core::convert::TryFrom<#vm::Value> for #name {
            type Error = #vm::ValueConversionError;

            fn try_from(mut __value: #vm::Value) -> ::core::result::Result<Self, Self::Error> {
                let #vm::Value::Enum(__name, __variant) = &__value else {
                    return ::core::result::Result::Err(#vm::ValueConversionError::invalid_type(
                        ::core::concat!("Enum ", #name_str), __value.type_name(), "try_from"
                    ));
                };

                if __name != #name_str {
                    return ::core::result::Result::Err(#vm::ValueConversionError::invalid_type(
                        ::core::concat!("Enum ", #name_str),
                        __value.type_name(),
                        "enum names don't match",
                    ));
                }

                #( const #var_const_names: i64 = #name::#variants as i64; )*

                match *__variant {
                    #(
                        #var_const_names => ::core::result::Result::Ok(Self::#variants),
                    )*
                    _ => ::core::result::Result::Err(#vm::ValueConversionError::OutOfRange),
                }
            }
        }

        #[automatically_derived]
        impl #vm::ffi::Typed for #name {
            const TYPE: #vm::ffi::Type<'static> = #vm::ffi::Type::Enum(#vm::ident!(#name_str));
        }

        #[automatically_derived]
        impl #name {
            const SCHEMA: #vm::ffi::Enum<'static> =
                #vm::ffi::Enum {
                    name: #vm::ident!(#name_str),
                    variants: &[#(
                        #vm::ident!(stringify!(#variants)),
                    )*],
                };
        }
    })
}
