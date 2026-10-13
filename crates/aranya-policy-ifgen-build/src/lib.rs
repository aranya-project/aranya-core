//! Generate typed policy interfaces from policy source code.

#![warn(missing_docs)]

use std::{fs, path::Path};

use anyhow::{Context as _, Result};
use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::parse_policy_document;

mod imp;
pub use imp::generate_code;

/// Read policy from `input` and write Rust interface to `output`.
pub fn generate(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    ifgen: Option<&str>,
) -> Result<()> {
    generate_(input.as_ref(), output.as_ref(), ifgen)
}

fn generate_(input: &Path, output: &Path, ifgen: Option<&str>) -> Result<()> {
    let policy_source = fs::read_to_string(input).with_context(|| format!("reading {input:?}"))?;
    let policy_ast = parse_policy_document(&policy_source)?;
    let target = Compiler::new(&policy_ast)
        .debug(true)
        .stub_ffi(true)
        .compile_interface()?;
    let ifgen_path = ifgen
        .map(syn::parse_str::<syn::Path>)
        .transpose()
        .with_context(|| format!("invalid ifgen path: {ifgen:?}"))?;
    let rust_code = generate_code(&target, ifgen_path.as_ref());

    fs::write(output, rust_code).with_context(|| format!("writing to {output:?}"))?;

    Ok(())
}
