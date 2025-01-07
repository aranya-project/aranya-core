fn main() {
    println!("cargo::rustc-check-cfg=cfg(fips)");
    println!("cargo::rustc-check-cfg=cfg(test_fips)");
}
