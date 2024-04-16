//! Interface for simulating or testing Aranya.
//!
//! The Aranya Model is a library which provides APIs to construct one or more clients, execute actions on the clients, sync between clients, and gather performance metrics about the operations performed.

#![cfg_attr(docs, feature(doc_cfg))]
#![warn(clippy::arithmetic_side_effects)]

pub mod model;

pub use crate::model::*;

#[cfg(test)]
mod tests;
