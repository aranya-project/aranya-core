use proc_macro2::TokenStream;
use quote::quote;
use syn::{ItemStruct, parse_quote};

use crate::common::get_derive;

mod kw {
    syn::custom_keyword!(interface);
    syn::custom_keyword!(error);
}

struct Attrs {
    interface: syn::Path,
    error: Option<syn::Path>,
}

impl syn::parse::Parse for Attrs {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        input.parse::<kw::interface>()?;
        input.parse::<syn::Token![=]>()?;
        let interface = input.parse::<syn::Path>()?;

        let error = if input.peek(kw::error) {
            input.parse::<kw::error>()?;
            input.parse::<syn::Token![=]>()?;
            Some(input.parse::<syn::Path>()?)
        } else {
            None
        };

        Ok(Self { interface, error })
    }
}

pub(super) fn parse(attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let Attrs { interface, error } = syn::parse2(attr)?;

    let act: ItemStruct = syn::parse2(item)?;

    let ident = &act.ident;

    let field_idents = act.fields.iter().map(|f| &f.ident).collect::<Vec<_>>();
    let field_types = act.fields.iter().map(|f| &f.ty).collect::<Vec<_>>();

    let derive = get_derive();

    let error = error.unwrap_or_else(|| parse_quote!(core::convert::Infallible));

    Ok(quote! {
        #derive
        #act

        impl aranya_policy_ifgen::Actionable for #ident {
            type Interface = #interface;
            type Error = #error;
            fn with_action<R>(self, f: impl for<'a> FnOnce(aranya_policy_ifgen::VmAction<'a>) -> R) -> R {
                f(aranya_policy_ifgen::vm_action!(
                    #ident( #(self.#field_idents),* )
                ))
            }
        }

        pub fn #ident( #(#field_idents: #field_types),* ) -> #ident {
            #ident { #(#field_idents),* }
        }
    })
}
