#![allow(clippy::unwrap_used)]

use std::{io::Write, path::Path};

use policy_ifgen_build::generate_code;
use policy_lang::lang::parse_policy_document;

fn dotest(name: &str) {
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");

    let mut mint = goldenfile::Mint::new(&data);

    let doc = std::fs::read_to_string(data.join(format!("{name}.md"))).unwrap();
    let doc = parse_policy_document(&doc).unwrap();

    let rust_code = generate_code(&doc);

    let mut file = mint.new_goldenfile(format!("{name}.rs")).unwrap();
    write!(file, "{rust_code}").unwrap();
}

#[test]
fn tictactoe() {
    dotest("tictactoe");
}

#[test]
fn ttc() {
    dotest("ttc");
}
