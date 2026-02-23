#![allow(clippy::unwrap_used)]

use std::{io::Write as _, path::Path};

use aranya_policy_compiler::Compiler;
use aranya_policy_ifgen_build::generate_code;
use aranya_policy_lang::lang::parse_policy_document;

fn dotest(name: &str) {
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");

    let mut mint = goldenfile::Mint::new(&data);

    let doc = std::fs::read_to_string(data.join(format!("{name}.md"))).unwrap();
    let doc = parse_policy_document(&doc).unwrap();

    let target = Compiler::new(&doc).compile_interface().unwrap();
    let rust_code = generate_code(&target);

    let mut file = mint.new_goldenfile(format!("{name}.rs")).unwrap();
    write!(file, "{rust_code}").unwrap();
}

// Regenerate interface files with `UPDATE_GOLDENFILES=1 cargo test -p aranya-policy-ifgen --tests`

#[test]
fn tictactoe() {
    dotest("tictactoe");
}

#[test]
fn structs() {
    dotest("structs");
}

#[test]
fn constants() {
    dotest("constants");
}
