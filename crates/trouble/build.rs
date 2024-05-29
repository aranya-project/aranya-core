use rustc_version::{version_meta, Channel};

fn main() {
    println!("cargo::rustc-check-cfg=cfg(error_in_core)");

    let meta = version_meta().expect("could not get compiler version");
    if let Channel::Nightly | Channel::Dev = meta.channel {
        println!("cargo::rustc-cfg=error_in_core")
    }
}
