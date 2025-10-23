# Policy Interface Generation

Generate typed Rust interface from policy code.

## Quickstart

```toml
# Cargo.toml

[dependencies]
aranya-policy-ifgen = { ... }

[build-dependencies]
aranya-policy-ifgen-build = { ... }
```

```rust
// build.rs

fn main() {
    println!("cargo:rerun-if-changed=src/policy.md");
    aranya_policy_ifgen_build::generate("src/policy.md", "src/policy.rs").unwrap();
}
```

```rust
// src/lib.rs

mod policy;

impl aranya_policy_ifgen::Actor for MyActor { ... }

fn do_the_thing(actor: &MyActor) -> Result<(), aranya_runtime::ClientError> {
    use policy::ActorExt;
    actor.some_action(42, "my string")
}
```
