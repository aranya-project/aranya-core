use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{DataStruct, DeriveInput, spanned::Spanned as _};

pub(crate) fn parse(item: TokenStream) -> syn::Result<TokenStream> {
    let input: DeriveInput = syn::parse2(item)?;
    match &input.data {
        syn::Data::Struct(data) => impl_struct(&input, data),
        syn::Data::Enum(_) => Err(syn::Error::new(input.span(), "enums are not yet supported")),
        syn::Data::Union(_) => Err(syn::Error::new(input.span(), "unions are not supported")),
    }
}

fn impl_struct(input: &DeriveInput, data: &DataStruct) -> syn::Result<TokenStream> {
    let name = &input.ident;
    let name_str = name.to_string();
    let (names, fields) = data
        .fields
        .iter()
        .map(|f| {
            let name = f
                .ident
                .as_ref()
                .ok_or_else(|| syn::Error::new(f.span(), "Expected named field"))?;
            let field = format_ident!("__field_{name}");
            Ok((name, field))
        })
        .collect::<syn::Result<(Vec<_>, Vec<_>)>>()?;

    let vm: syn::Path = syn::parse_quote!(::aranya_policy_vm);

    Ok(quote! {
        #[automatically_derived]
        impl ::core::convert::From<#name> for #vm::Value {
            fn from(__value: #name) -> Self {
                let __struct = #vm::Struct::new(
                    #vm::ident!(stringify!(#name)),
                    &[
                        #(#vm::KVPair::new(
                            #vm::ident!(stringify!(#names)),
                            __value.#names.into(),
                        )),*,
                    ],
                );
                __struct.into()
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
                    let #fields = __struct.fields.remove(::core::stringify!(#names))
                        .ok_or(#vm::ValueConversionError::InvalidStructMember(
                                #vm::ident!(stringify!(#names)),
                        ))?;
                )*
                if !__struct.fields.is_empty() {
                    return ::core::result::Result::Err(#vm::ValueConversionError::BadState);
                }
                ::core::result::Result::Ok(#name {
                    #(
                        #names: #vm::TryFromValue::try_from_value(#fields)?
                    ),*
                })
            }
        }

        #[automatically_derived]
        impl #vm::ffi::Typed for #name {
            const TYPE: #vm::ffi::Type<'static> = #vm::ffi::Type::Struct(#vm::ident!(#name_str));
        }
    })
}
