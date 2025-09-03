# aranya-policy-compiler

The Aranya Policy Compiler is a core component of the Aranya project that compiles policies written in the Aranya Policy Language into executable policy modules.

## Overview

The compiler reads policy source code, often stored in a Markdown file, and emits bytecode that can be executed by the Aranya Policy VM.

## Usage

### As a Library

```rust
use aranya_policy_compiler::{Compiler, validate};
use aranya_policy_lang::lang::parse_policy_document;
use aranya_policy_vm::VM;

// Parse policy source code
let policy_str = std::fs::read_to_string("policy.md")?;
let policy = parse_policy_document(&policy_str)?;

// Compile to module
let compiler = Compiler::new(&policy);
let module = compiler.compile()?;

// Validate the compiled module
if !validate(&module) {
    eprintln!("Module validation failed");
}

// Execute a policy action
let mut vm = VM::new();
vm.load_module(module)?;
let result = vm.call_action("my_action", &args)?;
println!("Action result: {:?}", result);
```

### As a Command-Line Tool

The crate also provides a command-line interface through the `policy-compiler` binary:

```bash
# Compile a policy file
policy-compiler input.md -o output.pmod

# Compile without validation
policy-compiler input.md --no-validate

# Compile with FFI stubbing for testing
policy-compiler input.md --stub-ffi
```
