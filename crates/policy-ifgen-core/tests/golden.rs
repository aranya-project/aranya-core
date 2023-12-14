#![allow(clippy::unwrap_used)]

use std::{io::Write, path::Path};

use policy_ifgen_core::generate_code;
use policy_lang::lang::parse_policy_document;

fn dotest(name: &str) {
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");

    let mut mint = goldenfile::Mint::new(&data);

    let doc = std::fs::read_to_string(data.join(format!("{name}.md"))).unwrap();
    let doc = parse_policy_document(&doc).unwrap();

    let code = generate_code(&doc);
    let parsed = syn::parse2(code).unwrap();
    let body = prettyplease::unparse(&parsed);

    let mut file = mint.new_goldenfile(format!("{name}.rs")).unwrap();
    write!(file, "{body}").unwrap();
}

#[test]
fn tictactoe() {
    dotest("tictactoe");
}

#[test]
fn ttc() {
    dotest("ttc");
}
