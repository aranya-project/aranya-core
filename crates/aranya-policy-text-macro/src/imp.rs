use macro_string::MacroString;
use proc_macro2::TokenStream;
use quote::ToTokens as _;
use syn::spanned::Spanned as _;

pub fn validate_text(item: TokenStream) -> syn::Result<TokenStream> {
    let MacroString(text) = syn::parse2(item.clone())?;
    if text.as_bytes().contains(&0) {
        return Err(syn::Error::new(item.span(), "text contains nul byte"));
    }
    Ok(text.into_token_stream())
}

pub fn validate_identifier(item: TokenStream) -> syn::Result<TokenStream> {
    let MacroString(text) = syn::parse2(item.clone())?;
    let mut bytes = text.bytes();
    if !bytes.next().is_some_and(|b| b.is_ascii_alphabetic()) {
        return Err(syn::Error::new(
            item.span(),
            "identifier must start with [a-zA-Z]",
        ));
    }
    for b in bytes {
        if !(b.is_ascii_alphanumeric() || b == b'_') {
            return Err(syn::Error::new(
                item.span(),
                "identifier must follow with [a-zA-Z0-9_]",
            ));
        }
    }
    Ok(item)
}
