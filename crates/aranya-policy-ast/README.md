# aranya-policy-ast

The Abstract Syntax Tree (AST) for the Aranya Policy Language.

## Overview

This crate provides the data structures that represent the parsed form of Aranya Policy Language source code. It defines the AST nodes for all language constructs including policies, facts, actions, effects, expressions, statements, and type definitions.

The AST is the intermediate representation used by the Aranya Policy Language compiler and other tools that need to analyze or transform policy code.

## Usage

```rust
use aranya_policy_ast::Version;
use aranya_policy_lang::lang::parse_policy_str;
use aranya_policy_compiler::Compiler;

// Create a new policy AST
let policy = parse_policy_str("policy code", Version::V2)?;

// Compile AST into module
let module = Compiler::new(&policy).compile()?;

```

## Features

- **`std`** - Enable standard library support (default: disabled)
- **`proptest`** - Enable property testing support for AST nodes

## Serialization

All AST types support serialization through:
- **Serde** - For JSON/YAML serialization
- **rkyv** - For efficient binary serialization with zero-copy deserialization

## No-std Support

This crate supports `no_std` environments by default, using `alloc` for dynamic allocations. Enable the `std` feature for full standard library support.

