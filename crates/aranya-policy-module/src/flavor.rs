//! Data definitions specifying command flavors.

use aranya_policy_ast::Identifier;

pub use crate::ffi::{Enum, Struct, Type};

/// Flavor specifications.
pub struct Flavors<'a> {
    /// The default flavor when none is specified.
    pub default: Flavor<'a>,
    /// Flavors by name.
    pub flavors: &'a [(Identifier, Flavor<'a>)],
}

/// A specification of action/command flavor.
pub struct Flavor<'a> {
    /// The envelope or extra context passed to policy/recall.
    pub envelope: Struct<'a>,
}
