#![allow(clippy::unwrap_used)]

use std::path::Path;

use aranya_policy_compiler::Compiler;
use aranya_policy_ifgen_build::generate_code;
use aranya_policy_lang::lang::parse_policy_document;
use snapbox::assert_data_eq;

fn dotest(name: &str) {
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");

    let doc = std::fs::read_to_string(data.join(format!("{name}.md"))).unwrap();
    let doc = parse_policy_document(&doc).unwrap();

    let target = Compiler::new(&doc).compile_interface().unwrap();

    let rust_code = generate_code(&target, None);
    assert_data_eq!(
        rust_code,
        snapbox::Data::read_from(&data.join(format!("{name}.rs")), None).raw()
    );

    let ifgen_path: syn::Path = syn::parse_quote!(aranya_core::ifgen);
    let rust_code = generate_code(&target, Some(&ifgen_path));
    assert_data_eq!(
        rust_code,
        snapbox::Data::read_from(&data.join(format!("{name}_aranya_core.rs")), None).raw()
    );
}

// Regenerate interface files with `SNAPSHOTS=overwrite cargo test -p aranya-policy-ifgen --test golden`
// Or use `Update Tests (Snapbox)` rust-analyzer CodeLens button at top of file.

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
