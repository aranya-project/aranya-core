//! Proc macros for the `aranya-capi-core` crate.

mod error;
mod opaque;

use syn::Error;

/// See `aranya_capi_core`.
#[proc_macro_derive(ErrorCode, attributes(capi))]
pub fn error_code(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    error::derive(item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// See `aranya_capi_core`.
#[proc_macro_attribute]
pub fn opaque(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    opaque::opaque(attr.into(), item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

// Dummy macros.

/// See `aranya_capi_core`.
#[proc_macro_attribute]
pub fn builds(
    _attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    item
}

/// See `aranya_capi_core`.
#[proc_macro_attribute]
#[doc(hidden)]
pub fn derive(
    _attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    item
}

/// See `aranya_capi_core`.
#[proc_macro_attribute]
#[doc(hidden)]
pub fn generated(
    _attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    item
}

/// See `aranya_capi_core`.
#[proc_macro_attribute]
#[doc(hidden)]
pub fn no_ext_error(
    _attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    item
}
