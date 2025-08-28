use std::{env, fs, path::Path};

use anyhow::Context as _;
use aranya_capi_codegen::Config;
use quote::format_ident;
use syn::parse_quote;
use tracing_subscriber::{EnvFilter, prelude::*};

fn main() -> anyhow::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(cbindgen)");

    // Enable `cfg(cbindgen)` when running cbindgen so we can manipulate it.
    if env::var("_CBINDGEN_IS_RUNNING").is_ok() {
        println!("cargo::rustc-cfg=cbindgen");
    }

    let appender = tracing_appender::rolling::hourly("/tmp/aranya-capi-codegen-test", "prefix.log");
    let layer = tracing_subscriber::fmt::layer().with_writer(appender);
    tracing_subscriber::registry()
        .with(layer)
        .with(EnvFilter::from_env("ARANYA_CAPI_CODEGEN_TEST"))
        .init();

    let in_path = Path::new("src/defs.rs");
    println!("cargo:rerun-if-changed={}", in_path.display());
    let source = fs::read_to_string(in_path)
        .with_context(|| format!("unable to read file `{}`", in_path.display()))?;
    let cfg = Config {
        err_ty: parse_quote!(Error),
        ext_err_ty: parse_quote!(ExtError),
        ty_prefix: format_ident!("Prefix"),
        fn_prefix: format_ident!("prefix_"),
        defs: parse_quote!(crate::defs),
        target: env::var("TARGET")?,
    };
    let tokens = cfg
        .generate(&source)
        .inspect_err(|err| err.display(in_path, &source))?;
    let data = aranya_capi_codegen::format(&tokens);
    fs::write("src/generated.rs", &data)?;
    Ok(())
}
