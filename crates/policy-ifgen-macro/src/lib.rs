use std::path::{Path, PathBuf};

use anyhow::Context;
use policy_ifgen_core::generate_code;
use policy_lang::lang::parse_policy_document;
use quote::quote;
use syn::LitStr;

#[proc_macro]
pub fn interface(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let path: LitStr = match syn::parse(input) {
        Ok(v) => v,
        Err(e) => return e.into_compile_error().into(),
    };

    let policy = match read_doc(path.value().as_ref()) {
        Ok(v) => v,
        Err(e) => {
            return syn::Error::new(proc_macro::Span::call_site().into(), format!("{e:?}"))
                .into_compile_error()
                .into();
        }
    };

    let code = generate_code(&policy);

    // Wrap in module so we can use `#![allow(...)]`
    quote! {
        pub use __interface::*;
        mod __interface {
            #code
        }
    }
    .into()
}

fn read_doc(relpath: &Path) -> anyhow::Result<policy_lang::ast::Policy> {
    let root = std::env::var_os("CARGO_MANIFEST_DIR").context("bad CARGO_MANIFEST_DIR")?;
    let mut path = PathBuf::from(root);
    path.push(relpath);
    let path = path.as_path();

    let doc = std::fs::read_to_string(path).with_context(|| format!("could not read {path:?}"))?;
    let policy = parse_policy_document(&doc).context("error in policy doc")?;

    Ok(policy)
}
