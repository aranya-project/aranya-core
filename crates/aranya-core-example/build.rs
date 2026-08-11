use anyhow::{Context as _, Result};

fn main() -> Result<()> {
    let policy_md = "src/policy.md";
    let policy_rs = "src/policy.rs";
    println!("cargo:rerun-if-changed={policy_md}");

    aranya_policy_ifgen_build::InterfaceGeneratorBuilder::new(policy_md, policy_rs)
        .ifgen("aranya_core::ifgen")
        .generate()
        .context("generating policy interface")?;

    Ok(())
}
