//! Compile-check that goldenfiles generated with `Some("aranya_core::ifgen")`
//! actually compile through the `aranya-core` re-export.

#![allow(dead_code)]

#[path = "data/tictactoe_aranya_core.rs"]
mod tictactoe;

#[path = "data/structs_aranya_core.rs"]
mod structs;

#[path = "data/constants_aranya_core.rs"]
mod constants;
