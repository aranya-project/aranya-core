use macro_string::MacroString;
use proc_macro2::TokenStream;
use quote::ToTokens as _;

pub fn validate_text(item: MacroString) -> syn::Result<TokenStream> {
    let text = item.eval()?;
    if text.as_bytes().contains(&0) {
        return Err(item.error("text contains nul byte"));
    }
    Ok(text.into_token_stream())
}

pub fn validate_identifier(item: MacroString) -> syn::Result<TokenStream> {
    let text = item.eval()?;
    let mut bytes = text.bytes();
    if !bytes.next().is_some_and(|b| b.is_ascii_alphabetic()) {
        return Err(item.error("identifier must start with [a-zA-Z]"));
    }
    for b in bytes {
        if !(b.is_ascii_alphanumeric() || b == b'_') {
            return Err(item.error("identifier must follow with [a-zA-Z0-9_]"));
        }
    }
    Ok(text.into_token_stream())
}
