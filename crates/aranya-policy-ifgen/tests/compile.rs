//! Each goldenfile is compiled against the current ifgen surface. If
//! the generator, the macros, or the runtime-side exports drift out
//! of alignment, these fail.

#[allow(dead_code)]
#[path = "data/tictactoe.rs"]
mod tictactoe;

#[allow(dead_code)]
#[path = "data/structs.rs"]
mod structs;

#[allow(dead_code)]
#[path = "data/constants.rs"]
mod constants;
