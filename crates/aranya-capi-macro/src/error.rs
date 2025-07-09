use std::ffi::CString;

use aranya_capi_codegen::{
    IdentExt, KeyValPair,
    attr::{Attr, Symbol},
    syntax::Repr,
};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{
    Error, Ident, ItemEnum, LitCStr, LitStr, Path,
    parse::{Parse, ParseStream, Result},
    parse_quote,
};
use tracing::info;

pub(super) fn derive(item: TokenStream) -> Result<TokenStream> {
    info!("deriving `ErrorCode`");

    let item = syn::parse2::<ItemEnum>(item)?;

    let repr = {
        let mut reprs: Vec<_> = item
            .attrs
            .iter()
            .filter_map(|a| {
                if !a.path().is_ident("repr") {
                    None
                } else {
                    Some(a.parse_args::<Repr>())
                }
            })
            .collect::<Result<_>>()?;
        if reprs.len() > 1 {
            return Err(Error::new_spanned(
                &item,
                "found more than one `#[repr(...)]` attribute",
            ));
        }
        let repr = reprs.remove(0).to_str();
        format_ident!("{}", repr)
    };

    let mut vars = Vec::new(); // variant names
    let mut msgs = Vec::new(); // `#[capi(msg = ...)]`

    fn mangle(ident: &Ident) -> Ident {
        format_ident!(
            "__ERROR_CODE_{}",
            ident.to_screaming_snake_case(),
            span = ident.span()
        )
    }

    let mut success = None;
    for v in &item.variants {
        vars.push(&v.ident);

        let mut msg = None;
        for attr in &v.attrs {
            if !attr.path().is_ident("capi") {
                continue;
            }
            let vattr = attr.parse_args::<VariantAttr>()?;
            if vattr.success {
                if success.is_some() {
                    return Err(Error::new_spanned(
                        attr,
                        "duplicate `#[capi(success)]` attribute",
                    ));
                }
                success = Some(v);
            }
            if vattr.msg.is_some() {
                if msg.is_some() {
                    return Err(Error::new_spanned(
                        attr,
                        "duplicate `#[capi(msg)]` attribute",
                    ));
                }
                msg = vattr.msg;
            }
        }
        if let Some(msg) = msg {
            let span = msg.span();
            let text = {
                let mut bytes = msg.value().into_bytes();
                bytes.push(0);
                CString::from_vec_with_nul(bytes)
                    .map_err(|err| Error::new_spanned(msg, format!("invalid msg: {err}")))?
            };
            msgs.push(LitCStr::new(&text, span));
        } else {
            return Err(Error::new_spanned(
                v,
                "missing `#[capi(msg = \"...\")]` attribute",
            ));
        }
    }
    let Some(success) = success.map(|v| &v.ident) else {
        return Err(Error::new_spanned(
            &item,
            "missing `#[capi(success)]` attribute",
        ));
    };

    let consts = item.variants.iter().map(|v| {
        let ident = &v.ident;
        let mangled = mangle(ident);
        quote! {
            const #mangled: <Self as ::aranya_capi_core::ErrorCode>::Repr =
                Self::#ident as <Self as ::aranya_capi_core::ErrorCode>::Repr;
        }
    });

    let cases = item.variants.iter().map(|v| {
        let ident = &v.ident;
        let mangled = mangle(ident);
        quote! {
            Self::#mangled => Self::#ident
        }
    });

    let capi: Path = parse_quote!(::aranya_capi_core);
    let name = &item.ident;
    let code = quote! {
        const _: () = {
            #[automatically_derived]
            impl #name {
                #(#consts)*
            }

            #[automatically_derived]
            impl #capi::ErrorCode for #name {
                const SUCCESS: #name = #name::#success;

                type Repr = #repr;

                fn try_from_repr(repr: Self::Repr) -> ::core::option::Option<Self> {
                    let v = match repr {
                        #(#cases),*,
                        _ => return ::core::option::Option::None
                    };
                    ::core::option::Option::Some(v)
                }

                fn to_cstr(self) -> &'static ::core::ffi::CStr {
                    match self {
                        #(
                            Self::#vars => #msgs
                        ),*
                    }
                }
            }
        };
    };
    aranya_capi_codegen::dump(&code, "/tmp/derive-error-code.rs");
    Ok(code)
}

struct VariantAttr {
    success: bool,
    msg: Option<LitStr>,
}

impl Parse for VariantAttr {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        mod kw {
            syn::custom_keyword!(msg);
            syn::custom_keyword!(success);
        }

        const MSG: Symbol = Symbol("msg");
        const SUCCESS: Symbol = Symbol("success");

        let mut msg = Attr::none(MSG);
        let mut success = Attr::none(SUCCESS);

        while !input.is_empty() {
            let lookahead = input.lookahead1();
            if lookahead.peek(kw::msg) {
                let KeyValPair { key, val } = input.parse::<KeyValPair<kw::msg, LitStr>>()?;
                msg.set(key, val)?;
            } else if lookahead.peek(kw::success) {
                let key = input.parse::<kw::success>()?;
                success.set(key, true)?;
            } else {
                return Err(lookahead.error());
            }
        }

        Ok(Self {
            success: success.get().unwrap_or_default(),
            msg: msg.get(),
        })
    }
}
