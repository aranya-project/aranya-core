use proc_macro2::TokenStream;
use quote::quote;
use syn::ItemStruct;

use crate::common::get_derive;

pub(super) fn parse(_attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let strukt: ItemStruct = syn::parse2(item)?;

    let derive = get_derive();

    Ok(quote! {
        #derive
        #strukt

        // TODO(jdygert): Value conversions
    })
}
