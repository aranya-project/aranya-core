use proc_macro2::TokenStream;
use quote::quote;

pub(crate) fn get_serde() -> TokenStream {
    if cfg!(feature = "serde") {
        quote! { ::policy_ifgen::serde::Serialize, ::policy_ifgen::serde::Deserialize, }
    } else {
        quote! {}
    }
}

pub(crate) fn get_derive() -> TokenStream {
    let serde = get_serde();
    quote! {
        #[derive(
            Clone,
            Debug,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            #serde
        )]
    }
}
