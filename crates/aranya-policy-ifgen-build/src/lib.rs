//! Generate typed policy interfaces from policy source code.

#![warn(missing_docs)]

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result};
use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::parse_policy_document;

mod imp;
pub use imp::generate_code;

/// Builder for generating a typed Rust interface from a policy document.
///
/// ```no_run
/// aranya_policy_ifgen_build::InterfaceGeneratorBuilder::new("src/policy.md", "src/policy.rs")
///     .generate()
///     .unwrap();
/// ```
#[derive(Debug, Clone)]
#[must_use]
pub struct InterfaceGeneratorBuilder {
    input: PathBuf,
    output: PathBuf,
    ifgen: Option<String>,
}

impl InterfaceGeneratorBuilder {
    /// Creates a [`InterfaceGeneratorBuilder`] that reads policy from `input` and writes the
    /// generated Rust interface to `output`.
    pub fn new(input: impl AsRef<Path>, output: impl AsRef<Path>) -> Self {
        Self {
            input: input.as_ref().to_path_buf(),
            output: output.as_ref().to_path_buf(),
            ifgen: None,
        }
    }

    /// Sets the Rust path used to import `aranya_policy_ifgen` in the generated
    /// code. Use this when consumers re-export the crate (e.g.
    /// `aranya_core::ifgen`).
    pub fn ifgen(mut self, ifgen: impl Into<String>) -> Self {
        self.ifgen = Some(ifgen.into());
        self
    }

    /// Reads the policy and writes the generated Rust interface.
    pub fn generate(self) -> Result<()> {
        let policy_source = fs::read_to_string(&self.input)
            .with_context(|| format!("reading {:?}", self.input))?;
        let policy_ast = parse_policy_document(&policy_source)?;
        let target = Compiler::new(&policy_ast)
            .debug(true)
            .stub_ffi(true)
            .compile_interface()?;
        let ifgen_path = self
            .ifgen
            .as_deref()
            .map(syn::parse_str::<syn::Path>)
            .transpose()
            .with_context(|| format!("invalid ifgen path: {:?}", self.ifgen.as_deref()))?;
        let rust_code = generate_code(&target, ifgen_path.as_ref());

        fs::write(&self.output, rust_code)
            .with_context(|| format!("writing to {:?}", self.output))?;

        Ok(())
    }
}
