use proc_macro::TokenStream;
use syn::Error;

mod imp;

#[proc_macro]
pub fn validate_text(item: TokenStream) -> TokenStream {
    imp::validate_text(item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

#[proc_macro]
pub fn validate_identifier(item: TokenStream) -> TokenStream {
    imp::validate_identifier(item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}
