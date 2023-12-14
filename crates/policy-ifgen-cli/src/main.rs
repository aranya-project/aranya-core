use std::{fs, path::PathBuf};

use clap::Parser;
use policy_ifgen_core::generate_code;
use policy_lang::lang::parse_policy_document;

// TODO(jdygert): Better cli. Currently MVP for testing.

/// Generate interface code from a policy document.
#[derive(Parser)]
struct Args {
    /// Path to policy markdown document
    policy_doc: PathBuf,
    /// Path to write generated Rust code
    output: PathBuf,
}

fn main() {
    let args = Args::parse();
    let doc = fs::read_to_string(args.policy_doc).expect("could not read policy doc");
    let policy = parse_policy_document(&doc).expect("could not parse policy doc");
    let code = syn::parse2(generate_code(&policy)).expect("could not parse generated code");
    let formatted = prettyplease::unparse(&code);
    std::fs::write(args.output, formatted).expect("could not write output");
}
