use proc_macro2::TokenStream;
use quote::quote;

pub(crate) fn get_derive() -> TokenStream {
    if cfg!(feature = "serde") {
        // `#[serde(crate = "...")]` redirects the path serde's derive emits in
        // generated impls, so consumers don't need a direct `serde` dependency.
        quote! {
            #[derive(
                Clone,
                Debug,
                Hash,
                PartialEq,
                Eq,
                PartialOrd,
                Ord,
                aranya_policy_ifgen::serde::Serialize,
                aranya_policy_ifgen::serde::Deserialize,
            )]
            #[serde(crate = "aranya_policy_ifgen::serde")]
        }
    } else {
        quote! {
            #[derive(
                Clone,
                Debug,
                Hash,
                PartialEq,
                Eq,
                PartialOrd,
                Ord,
            )]
        }
    }
}
