//! Types specific to the policy interface. This really should be defined in
//! `aranya-policy-compiler`, but the required `Named` machinery only exists here.

use aranya_policy_ast::{self as ast, Ident, Param, Persistence};
use serde::{Deserialize, Serialize};

use crate::{ConstValue, named::named};

/// A cut-down version of [`ast::ActionDefinition`] used for the policy interface.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct ActionDefinition {
    /// The name of the action.
    pub name: Ident,
    /// The persistence of the action.
    pub persistence: Persistence,
    /// The parameters of the action.
    pub params: Vec<Param>,
}
named!(ActionDefinition);

impl From<ast::ActionDefinition> for ActionDefinition {
    fn from(value: ast::ActionDefinition) -> Self {
        Self {
            name: value.identifier,
            persistence: value.persistence,
            params: value.arguments,
        }
    }
}

/// A command definition.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct CommandDefinition {
    /// The name of the command.
    pub name: Ident,
    /// The persistence of the command.
    pub persistence: Persistence,
    /// The attributes of the command.
    pub attributes: Vec<Attribute>,
    /// The fields of the command.
    pub fields: Vec<Param>,
}
named!(CommandDefinition);

/// A command attribute.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct Attribute {
    /// The name of the attribute.
    pub name: Ident,
    /// The value of the attribute.
    pub value: ConstValue,
}
named!(Attribute);
