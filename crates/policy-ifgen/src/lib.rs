use std::{fs, path::Path};

use anyhow::{Context, Result};
use policy_ifgen_core::generate_code;
use policy_lang::lang::parse_policy_document;

/// Read policy from `input` and write Rust interface to `output`.
pub fn generate(input: impl AsRef<Path>, output: impl AsRef<Path>) -> Result<()> {
    generate_(input.as_ref(), output.as_ref())
}

fn generate_(input: &Path, output: &Path) -> Result<()> {
    let policy_source = fs::read_to_string(input).with_context(|| format!("reading {input:?}"))?;

    let policy_doc = parse_policy_document(&policy_source)?;
    let rust_tt = syn::parse2(generate_code(&policy_doc))?;
    let rust_formatted = prettyplease::unparse(&rust_tt);

    fs::write(output, rust_formatted).with_context(|| format!("writing to {output:?}"))?;

    Ok(())
}
