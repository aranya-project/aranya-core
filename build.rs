extern crate cbindgen;

use std::env;

fn main() {
    let want_build = env::var("WANT_BUILD").is_ok();
    if !want_build {
        return;
    }
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    cbindgen::generate(crate_dir)
        .expect("Unable to generate bindings")
        .write_to_file("flow.h");
}
