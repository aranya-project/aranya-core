use anyhow::{Context as _, Result};

fn main() -> Result<()> {
    let policy_md = "src/policy.md";
    let policy_rs = "src/policy.rs";
    println!("cargo:rerun-if-changed={policy_md}");

    aranya_policy_ifgen_build::generate(policy_md, policy_rs, Some("aranya_core::ifgen"))
        .context("generating policy interface")?;

    Ok(())
}
