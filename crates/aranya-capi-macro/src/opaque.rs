use aranya_capi_codegen::syntax::Opaque;
use proc_macro2::TokenStream;
use quote::quote;
use syn::{Attribute, Error, Item, Path, parse::Result, parse_quote};
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
    let Item::Type(mut t) = item else {
        // TODO(jdygert): Allow structs again?
        return Err(Error::new_spanned(
            item,
            "`#[capi::opaque]` can only be applied to `type` aliases",
        ));
    };
    let name = t.ident.clone();

    let definition = if generated {
        let vis = &t.vis;

        let attrs: Vec<Attribute> = t
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("doc") || attr.path().is_ident("cfg"))
            .cloned()
            .collect();

        quote! {
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
            #t
        }
    } else {
        let old = t.ty;
        t.ty = parse_quote! { #capi::opaque::Opaque<#size, #align, #old> };

        quote! { #t }
    };

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
