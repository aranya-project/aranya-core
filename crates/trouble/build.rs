use rustc_version::{version_meta, Channel};

fn main() {
    println!("cargo::rustc-check-cfg=cfg(error_in_core, use_core_error)");

    let meta = version_meta().expect("could not get compiler version");

    assert_eq!(meta.semver.major, 1);

    if let Channel::Nightly | Channel::Dev = meta.channel {
        if meta.semver.minor < 81 {
            println!("cargo::rustc-cfg=error_in_core")
        }
    }

    if meta.semver.minor >= 81 {
        println!("cargo::rustc-cfg=use_core_error")
    }
}
