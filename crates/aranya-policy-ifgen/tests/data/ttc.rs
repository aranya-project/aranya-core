//! This code is @generated by `policy-ifgen`. DO NOT EDIT.
#![allow(clippy::duplicated_attributes)]
#![allow(clippy::enum_variant_names)]
#![allow(missing_docs)]
#![allow(non_snake_case)]
#![allow(unused_imports)]
extern crate alloc;
use alloc::vec::Vec;
use aranya_policy_ifgen::{
    macros::{actions, effect, effects, value},
    ClientError, Id, Value, Text,
};
/// Enum of policy effects that can occur in response to a policy action.
#[effects]
pub enum Effect {
    TtcTeamCreated(TtcTeamCreated),
    OwnerAdded(OwnerAdded),
    AdminAdded(AdminAdded),
    OperatorAdded(OperatorAdded),
    SatelliteAdded(SatelliteAdded),
    OwnerRemoved(OwnerRemoved),
    AdminRemoved(AdminRemoved),
    OperatorRemoved(OperatorRemoved),
    SatelliteRemoved(SatelliteRemoved),
    AfcLabelCreated(AfcLabelCreated),
    AfcLabelAssigned(AfcLabelAssigned),
    AfcLabelRevoked(AfcLabelRevoked),
    AfcBidiChannelCreated(AfcBidiChannelCreated),
}
/// TtcTeamCreated policy effect.
#[effect]
pub struct TtcTeamCreated {
    pub name: Text,
    pub owner_id: Id,
}
/// OwnerAdded policy effect.
#[effect]
pub struct OwnerAdded {
    pub device_id: Id,
    pub name: Text,
    pub ident_pk: Vec<u8>,
    pub sign_pk: Vec<u8>,
    pub enc_pk: Vec<u8>,
}
/// AdminAdded policy effect.
#[effect]
pub struct AdminAdded {
    pub device_id: Id,
    pub name: Text,
    pub ident_pk: Vec<u8>,
    pub sign_pk: Vec<u8>,
    pub enc_pk: Vec<u8>,
}
/// OperatorAdded policy effect.
#[effect]
pub struct OperatorAdded {
    pub device_id: Id,
    pub name: Text,
    pub ident_pk: Vec<u8>,
    pub sign_pk: Vec<u8>,
    pub enc_pk: Vec<u8>,
}
/// SatelliteAdded policy effect.
#[effect]
pub struct SatelliteAdded {
    pub device_id: Id,
    pub name: Text,
    pub ident_pk: Vec<u8>,
    pub sign_pk: Vec<u8>,
    pub enc_pk: Vec<u8>,
}
/// OwnerRemoved policy effect.
#[effect]
pub struct OwnerRemoved {
    pub device_id: Id,
}
/// AdminRemoved policy effect.
#[effect]
pub struct AdminRemoved {
    pub device_id: Id,
}
/// OperatorRemoved policy effect.
#[effect]
pub struct OperatorRemoved {
    pub device_id: Id,
}
/// SatelliteRemoved policy effect.
#[effect]
pub struct SatelliteRemoved {
    pub device_id: Id,
}
/// AfcLabelCreated policy effect.
#[effect]
pub struct AfcLabelCreated {
    pub name: Text,
    pub label: i64,
}
/// AfcLabelAssigned policy effect.
#[effect]
pub struct AfcLabelAssigned {
    pub device_id: Id,
    pub name: Text,
    pub label: i64,
    pub op: Text,
}
/// AfcLabelRevoked policy effect.
#[effect]
pub struct AfcLabelRevoked {
    pub device_id: Id,
    pub label: i64,
}
/// AfcBidiChannelCreated policy effect.
#[effect]
pub struct AfcBidiChannelCreated {
    pub device1: Id,
    pub device2: Id,
    pub label: i64,
}
/// Implements all supported policy actions.
#[actions]
pub trait ActorExt {
    fn create_ttc_team(
        &mut self,
        ttc_team_name: Text,
        device_name: Text,
        ident_pk: Vec<u8>,
        sign_pk: Vec<u8>,
        enc_pk: Vec<u8>,
    ) -> Result<(), ClientError>;
    fn add_owner(
        &mut self,
        device_id: Id,
        name: Text,
        ident_pk: Vec<u8>,
        sign_pk: Vec<u8>,
        enc_pk: Vec<u8>,
    ) -> Result<(), ClientError>;
    fn add_admin(
        &mut self,
        device_id: Id,
        name: Text,
        ident_pk: Vec<u8>,
        sign_pk: Vec<u8>,
        enc_pk: Vec<u8>,
    ) -> Result<(), ClientError>;
    fn add_operator(
        &mut self,
        device_id: Id,
        name: Text,
        ident_pk: Vec<u8>,
        sign_pk: Vec<u8>,
        enc_pk: Vec<u8>,
    ) -> Result<(), ClientError>;
    fn add_satellite(
        &mut self,
        device_id: Id,
        name: Text,
        ident_pk: Vec<u8>,
        sign_pk: Vec<u8>,
        enc_pk: Vec<u8>,
    ) -> Result<(), ClientError>;
    fn remove_owner(&mut self, device_id: Id) -> Result<(), ClientError>;
    fn remove_admin(&mut self, device_id: Id) -> Result<(), ClientError>;
    fn remove_operator(&mut self, device_id: Id) -> Result<(), ClientError>;
    fn remove_satellite(&mut self, device_id: Id) -> Result<(), ClientError>;
    fn create_afc_label(&mut self, name: Text, label: i64) -> Result<(), ClientError>;
    fn assign_afc_label(
        &mut self,
        device_id: Id,
        label: i64,
        op: Text,
    ) -> Result<(), ClientError>;
    fn revoke_afc_label(&mut self, device_id: Id, label: i64) -> Result<(), ClientError>;
    fn create_afc_bidi_channel(
        &mut self,
        peer_id: Id,
        label: i64,
    ) -> Result<(), ClientError>;
    fn create_afc_uni_channel(
        &mut self,
        seal_id: Id,
        open_id: Id,
        label: i64,
    ) -> Result<(), ClientError>;
}
