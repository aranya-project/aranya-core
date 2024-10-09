use proc_macro2::TokenStream;
use quote::quote;

pub(crate) fn get_serde() -> TokenStream {
    if cfg!(feature = "serde") {
        quote! { ::aranya_policy_ifgen::serde::Serialize, ::aranya_policy_ifgen::serde::Deserialize, }
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
            Hash,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            #serde
        )]
    }
}
