fn main() {
    println!("cargo::rustc-check-cfg=cfg(crypto_derive_debug)");
}
