# Policy Interface Generation

Generate typed Rust interface from policy code.

## CLI Usage

```sh
cargo run --bin policy-ifgen -- src/policy.md src/policy.rs
```

## Build script usage

```toml
# Cargo.toml

[build-dependencies]
policy-ifgen = { ... }
```

```rust
// build.rs

fn main() {
    println!("cargo:rerun-if-changed=src/policy.md");
    policy_ifgen::generate("src/policy.md", "src/policy.rs").unwrap();
}
```

```rust
// src/lib.rs

#[rustfmt::skip]
mod policy;
```
