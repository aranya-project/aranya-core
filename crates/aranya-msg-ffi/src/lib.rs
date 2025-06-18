//! Message Encryption FFI for Aranya.
//!
//! # Design
//!
//! This module provides FFI functions for encrypting and decrypting
//! messages using Aranya's group key system. It handles:
//!
//! - Group key generation and management
//! - Message encryption/decryption operations
//! - Secure key sharing between devices
//!
//! The functions in this module are designed to be called from
//! Aranya policy code via the policy VM's FFI system.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest)), no_std)]
#![warn(missing_docs)]

mod error;
mod ffi;
pub mod testing;
mod tests;

pub use ffi::*;
