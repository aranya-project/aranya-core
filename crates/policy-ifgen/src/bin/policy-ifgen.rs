use std::path::PathBuf;

use clap::Parser;

// TODO(jdygert): Better cli. Currently MVP for testing.

/// Generate interface code from a policy document.
#[derive(Parser)]
struct Args {
    /// Path to policy markdown document
    policy_doc: PathBuf,
    /// Path to write generated Rust code
    output: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    policy_ifgen::generate(&args.policy_doc, &args.output)
}
