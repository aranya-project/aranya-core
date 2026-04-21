use aranya_policy_ast::Identifier;
use serde::{Deserialize, Serialize};

/// Describes the module contract so that this module can be validated against the expected
/// contract.
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct ModuleContract {
    /// FFI module names
    // TODO(chip): extend this to full schema, not just the name
    pub ffis: Vec<Identifier>,
    // TODO(chip): catalog every other public-facing thing in a module - actions, effects, and
    // exported types
}
