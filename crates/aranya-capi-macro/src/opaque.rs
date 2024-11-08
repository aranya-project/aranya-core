use aranya_capi_codegen::syntax::Opaque;
use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse::Result, parse_quote, Error, Item, Path};
use tracing::info;

pub(super) fn opaque(attr: TokenStream, item: TokenStream) -> Result<TokenStream> {
    info!("parsing `#[capi::opaque(...)]` attribute");

    let Opaque { size, align, capi } = syn::parse2::<Opaque>(attr)?;

    let capi: Path = capi
        .map(Into::into)
        .unwrap_or_else(|| parse_quote!(::aranya_capi_core));

    let item = syn::parse2::<Item>(item)?;
    let (vis, name, attrs) = match &item {
        Item::Struct(s) => (&s.vis, &s.ident, &s.attrs),
        Item::Type(t) => (&t.vis, &t.ident, &t.attrs),
        item => {
            return Err(Error::new_spanned(
                item,
                "`#[capi::opaque]` can only be applied to `struct`s",
            ))
        }
    };

    let attrs = attrs
        .iter()
        .filter(|attr| attr.path().is_ident("doc") || attr.path().is_ident("cfg"));

    let code = quote! {
        #[cfg(cbindgen)]
        #[repr(C, align(#align))]
        #(#attrs)*
        #vis struct #name {
            /// This field only exists for size purposes. It is
            /// UNDEFINED BEHAVIOR to read from or write to it.
            /// @private
            __for_size_only: [u8; #size],
        }

        #[cfg(not(cbindgen))]
        #item

        #[allow(clippy::assertions_on_constants)]
        #[allow(clippy::modulo_one)]
        const _: () = {
            // Size.
            const _: () = {
                const GOT: usize = #size;
                const MIN: usize = ::core::mem::size_of::<#name>();
                const MSG: &str = #capi::internal::const_format::formatcp!("size too small: {GOT} < {MIN}");
                // NB: We use `core::assert!` instead of
                // `const_format::assertcp!` because the latter
                // clobbers our spans.
                ::core::assert!(GOT >= MIN, "{}", MSG);
            };
            // Alignment.
            const _: () = {
                const GOT: usize = #align;
                const MIN: usize = ::core::mem::align_of::<#name>();
                const MSG: &str = #capi::internal::const_format::formatcp!("alignment too small: {GOT} < {MIN}");
                // NB: We use `core::assert!` instead of
                // `const_format::assertcp!` because the latter
                // clobbers our spans.
                ::core::assert!(GOT >= MIN && GOT % MIN == 0, "{}", MSG);
            };
        };
    };
    Ok(code)
}
