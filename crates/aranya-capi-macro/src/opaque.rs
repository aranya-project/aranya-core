use aranya_capi_codegen::syntax::Opaque;
use proc_macro2::TokenStream;
use quote::quote;
use syn::{Error, Item, Path, parse::Result, parse_quote};
use tracing::info;

pub(super) fn opaque(attr: TokenStream, item: TokenStream) -> Result<TokenStream> {
    info!("parsing `#[capi::opaque(...)]` attribute");

    let Opaque {
        size,
        align,
        capi,
        generated,
    } = syn::parse2::<Opaque>(attr)?;

    let capi: Path = capi
        .map(Into::into)
        .unwrap_or_else(|| parse_quote!(::aranya_capi_core));

    let item = syn::parse2::<Item>(item)?;
    let Item::Type(mut definition) = item else {
        // TODO(jdygert): Allow structs again?
        return Err(Error::new_spanned(
            item,
            "`#[capi::opaque]` can only be applied to `type` aliases",
        ));
    };
    let name = definition.ident.clone();

    // Generated alias already has opaque wrapper on underlying type.
    // Otherwise, wrap in `Opaque`.
    if !generated {
        let old = definition.ty;
        definition.ty = parse_quote! { #capi::opaque::Opaque<#size, #align, #old> };
    }

    let code = quote! {
        #definition

        #[allow(clippy::assertions_on_constants)]
        const _: () = {
            // Size.
            const _: () = {
                const GOT: usize = #size;
                const ACTUAL: usize = ::core::mem::size_of::<#name>();
                const MSG: &str = #capi::internal::const_format::formatcp!("bad size: {GOT} != {ACTUAL}");
                // NB: We use `core::assert!` instead of `const_format::assertcp!`
                // because the latter clobbers our spans.
                ::core::assert!(GOT == ACTUAL, "{}", MSG);
            };
            // Alignment.
            const _: () = {
                const GOT: usize = #align;
                const ACTUAL: usize = ::core::mem::align_of::<#name>();
                const MSG: &str = #capi::internal::const_format::formatcp!("bad alignment: {GOT} != {ACTUAL}");
                // NB: We use `core::assert!` instead of `const_format::assertcp!`
                // because the latter clobbers our spans.
                ::core::assert!(GOT == ACTUAL, "{}", MSG);
            };
        };
    };
    Ok(code)
}
