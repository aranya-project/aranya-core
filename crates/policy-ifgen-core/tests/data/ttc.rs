#![allow(clippy::enum_variant_names, non_snake_case, unused_imports)]
extern crate alloc;
use alloc::{borrow::Cow, string::String, vec, vec::Vec};
use policy_vm::{Id, KVPair, Value};
use runtime::{ClientError, Policy, VmPolicy};
pub type VmActions<'a> = <VmPolicy as Policy>::Actions<'a>;
pub type VmEffects = <VmPolicy as Policy>::Effects;
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NewUser {
    pub user_id: Id,
    pub sign_pk_id: Id,
    pub sign_pk: Vec<u8>,
    pub enc_pk_id: Id,
    pub enc_pk: Vec<u8>,
    pub role: String,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct User {
    pub user_id: Id,
    pub sign_pk_id: Id,
    pub enc_pk_id: Id,
    pub role: String,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Effects {
    TtcTeamCreated(TtcTeamCreated),
    OwnerAdded(OwnerAdded),
    AdminAdded(AdminAdded),
    OperatorAdded(OperatorAdded),
    SatelliteAdded(SatelliteAdded),
    OwnerRemoved(OwnerRemoved),
    AdminRemoved(AdminRemoved),
    OperatorRemoved(OperatorRemoved),
    SatelliteRemoved(SatelliteRemoved),
    ApsLabelCreated(ApsLabelCreated),
    ApsLabelAssigned(ApsLabelAssigned),
    ApsLabelRevoked(ApsLabelRevoked),
    ApsBidiChannelCreated(ApsBidiChannelCreated),
}
impl TryFrom<(String, Vec<KVPair>)> for Effects {
    type Error = EffectsParseError;
    fn try_from((name, fields): VmEffects) -> Result<Self, Self::Error> {
        match name.as_str() {
            "TtcTeamCreated" => fields.try_into().map(Self::TtcTeamCreated),
            "OwnerAdded" => fields.try_into().map(Self::OwnerAdded),
            "AdminAdded" => fields.try_into().map(Self::AdminAdded),
            "OperatorAdded" => fields.try_into().map(Self::OperatorAdded),
            "SatelliteAdded" => fields.try_into().map(Self::SatelliteAdded),
            "OwnerRemoved" => fields.try_into().map(Self::OwnerRemoved),
            "AdminRemoved" => fields.try_into().map(Self::AdminRemoved),
            "OperatorRemoved" => fields.try_into().map(Self::OperatorRemoved),
            "SatelliteRemoved" => fields.try_into().map(Self::SatelliteRemoved),
            "ApsLabelCreated" => fields.try_into().map(Self::ApsLabelCreated),
            "ApsLabelAssigned" => fields.try_into().map(Self::ApsLabelAssigned),
            "ApsLabelRevoked" => fields.try_into().map(Self::ApsLabelRevoked),
            "ApsBidiChannelCreated" => fields.try_into().map(Self::ApsBidiChannelCreated),
            _ => Err(EffectsParseError::UnknownEffectName),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TtcTeamCreated {
    pub name: String,
    pub owner_id: Id,
}
impl TryFrom<Vec<KVPair>> for TtcTeamCreated {
    type Error = EffectsParseError;
    fn try_from(value: Vec<KVPair>) -> Result<Self, Self::Error> {
        let mut iter = value.into_iter();
        Ok(Self {
            name: parse_field("name", iter.next())?,
            owner_id: parse_field("owner_id", iter.next())?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OwnerAdded {
    pub user_id: Id,
    pub name: String,
    pub ident_pk: Vec<u8>,
    pub sign_pk: Vec<u8>,
    pub enc_pk: Vec<u8>,
}
impl TryFrom<Vec<KVPair>> for OwnerAdded {
    type Error = EffectsParseError;
    fn try_from(value: Vec<KVPair>) -> Result<Self, Self::Error> {
        let mut iter = value.into_iter();
        Ok(Self {
            user_id: parse_field("user_id", iter.next())?,
            name: parse_field("name", iter.next())?,
            ident_pk: parse_field("ident_pk", iter.next())?,
            sign_pk: parse_field("sign_pk", iter.next())?,
            enc_pk: parse_field("enc_pk", iter.next())?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdminAdded {
    pub user_id: Id,
    pub name: String,
    pub ident_pk: Vec<u8>,
    pub sign_pk: Vec<u8>,
    pub enc_pk: Vec<u8>,
}
impl TryFrom<Vec<KVPair>> for AdminAdded {
    type Error = EffectsParseError;
    fn try_from(value: Vec<KVPair>) -> Result<Self, Self::Error> {
        let mut iter = value.into_iter();
        Ok(Self {
            user_id: parse_field("user_id", iter.next())?,
            name: parse_field("name", iter.next())?,
            ident_pk: parse_field("ident_pk", iter.next())?,
            sign_pk: parse_field("sign_pk", iter.next())?,
            enc_pk: parse_field("enc_pk", iter.next())?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OperatorAdded {
    pub user_id: Id,
    pub name: String,
    pub ident_pk: Vec<u8>,
    pub sign_pk: Vec<u8>,
    pub enc_pk: Vec<u8>,
}
impl TryFrom<Vec<KVPair>> for OperatorAdded {
    type Error = EffectsParseError;
    fn try_from(value: Vec<KVPair>) -> Result<Self, Self::Error> {
        let mut iter = value.into_iter();
        Ok(Self {
            user_id: parse_field("user_id", iter.next())?,
            name: parse_field("name", iter.next())?,
            ident_pk: parse_field("ident_pk", iter.next())?,
            sign_pk: parse_field("sign_pk", iter.next())?,
            enc_pk: parse_field("enc_pk", iter.next())?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SatelliteAdded {
    pub user_id: Id,
    pub name: String,
    pub ident_pk: Vec<u8>,
    pub sign_pk: Vec<u8>,
    pub enc_pk: Vec<u8>,
}
impl TryFrom<Vec<KVPair>> for SatelliteAdded {
    type Error = EffectsParseError;
    fn try_from(value: Vec<KVPair>) -> Result<Self, Self::Error> {
        let mut iter = value.into_iter();
        Ok(Self {
            user_id: parse_field("user_id", iter.next())?,
            name: parse_field("name", iter.next())?,
            ident_pk: parse_field("ident_pk", iter.next())?,
            sign_pk: parse_field("sign_pk", iter.next())?,
            enc_pk: parse_field("enc_pk", iter.next())?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OwnerRemoved {
    pub user_id: Id,
}
impl TryFrom<Vec<KVPair>> for OwnerRemoved {
    type Error = EffectsParseError;
    fn try_from(value: Vec<KVPair>) -> Result<Self, Self::Error> {
        let mut iter = value.into_iter();
        Ok(Self {
            user_id: parse_field("user_id", iter.next())?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdminRemoved {
    pub user_id: Id,
}
impl TryFrom<Vec<KVPair>> for AdminRemoved {
    type Error = EffectsParseError;
    fn try_from(value: Vec<KVPair>) -> Result<Self, Self::Error> {
        let mut iter = value.into_iter();
        Ok(Self {
            user_id: parse_field("user_id", iter.next())?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OperatorRemoved {
    pub user_id: Id,
}
impl TryFrom<Vec<KVPair>> for OperatorRemoved {
    type Error = EffectsParseError;
    fn try_from(value: Vec<KVPair>) -> Result<Self, Self::Error> {
        let mut iter = value.into_iter();
        Ok(Self {
            user_id: parse_field("user_id", iter.next())?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SatelliteRemoved {
    pub user_id: Id,
}
impl TryFrom<Vec<KVPair>> for SatelliteRemoved {
    type Error = EffectsParseError;
    fn try_from(value: Vec<KVPair>) -> Result<Self, Self::Error> {
        let mut iter = value.into_iter();
        Ok(Self {
            user_id: parse_field("user_id", iter.next())?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApsLabelCreated {
    pub name: String,
    pub label: i64,
}
impl TryFrom<Vec<KVPair>> for ApsLabelCreated {
    type Error = EffectsParseError;
    fn try_from(value: Vec<KVPair>) -> Result<Self, Self::Error> {
        let mut iter = value.into_iter();
        Ok(Self {
            name: parse_field("name", iter.next())?,
            label: parse_field("label", iter.next())?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApsLabelAssigned {
    pub user_id: Id,
    pub name: String,
    pub label: i64,
    pub op: String,
}
impl TryFrom<Vec<KVPair>> for ApsLabelAssigned {
    type Error = EffectsParseError;
    fn try_from(value: Vec<KVPair>) -> Result<Self, Self::Error> {
        let mut iter = value.into_iter();
        Ok(Self {
            user_id: parse_field("user_id", iter.next())?,
            name: parse_field("name", iter.next())?,
            label: parse_field("label", iter.next())?,
            op: parse_field("op", iter.next())?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApsLabelRevoked {
    pub user_id: Id,
    pub label: i64,
}
impl TryFrom<Vec<KVPair>> for ApsLabelRevoked {
    type Error = EffectsParseError;
    fn try_from(value: Vec<KVPair>) -> Result<Self, Self::Error> {
        let mut iter = value.into_iter();
        Ok(Self {
            user_id: parse_field("user_id", iter.next())?,
            label: parse_field("label", iter.next())?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApsBidiChannelCreated {
    pub user1: Id,
    pub user2: Id,
    pub label: i64,
}
impl TryFrom<Vec<KVPair>> for ApsBidiChannelCreated {
    type Error = EffectsParseError;
    fn try_from(value: Vec<KVPair>) -> Result<Self, Self::Error> {
        let mut iter = value.into_iter();
        Ok(Self {
            user1: parse_field("user1", iter.next())?,
            user2: parse_field("user2", iter.next())?,
            label: parse_field("label", iter.next())?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EffectsParseError {
    NoMoreFields,
    FieldNameMismatch,
    FieldTypeMismatch,
    UnknownEffectName,
}
fn parse_field<T: TryFrom<Value>>(
    name: &str,
    pair: Option<KVPair>,
) -> Result<T, EffectsParseError> {
    let (key, value) = pair.ok_or(EffectsParseError::NoMoreFields)?.into();
    if key != name {
        return Err(EffectsParseError::FieldNameMismatch);
    }
    value.try_into().map_err(|_| EffectsParseError::FieldTypeMismatch)
}
pub trait Actor {
    fn call_action(&mut self, action: VmActions<'_>) -> Result<(), ClientError>;
    fn create_ttc_team(
        &mut self,
        ttc_team_name: String,
        user_name: String,
        ident_pk: Vec<u8>,
        sign_pk: Vec<u8>,
        enc_pk: Vec<u8>,
    ) -> Result<(), ClientError> {
        self.call_action((
            "create_ttc_team",
            Cow::Owned(
                vec![
                    Value::from(ttc_team_name), Value::from(user_name),
                    Value::from(ident_pk), Value::from(sign_pk), Value::from(enc_pk)
                ],
            ),
        ))
    }
    fn add_owner(
        &mut self,
        user_id: Id,
        name: String,
        ident_pk: Vec<u8>,
        sign_pk: Vec<u8>,
        enc_pk: Vec<u8>,
    ) -> Result<(), ClientError> {
        self.call_action((
            "add_owner",
            Cow::Owned(
                vec![
                    Value::from(user_id), Value::from(name), Value::from(ident_pk),
                    Value::from(sign_pk), Value::from(enc_pk)
                ],
            ),
        ))
    }
    fn add_admin(
        &mut self,
        user_id: Id,
        name: String,
        ident_pk: Vec<u8>,
        sign_pk: Vec<u8>,
        enc_pk: Vec<u8>,
    ) -> Result<(), ClientError> {
        self.call_action((
            "add_admin",
            Cow::Owned(
                vec![
                    Value::from(user_id), Value::from(name), Value::from(ident_pk),
                    Value::from(sign_pk), Value::from(enc_pk)
                ],
            ),
        ))
    }
    fn add_operator(
        &mut self,
        user_id: Id,
        name: String,
        ident_pk: Vec<u8>,
        sign_pk: Vec<u8>,
        enc_pk: Vec<u8>,
    ) -> Result<(), ClientError> {
        self.call_action((
            "add_operator",
            Cow::Owned(
                vec![
                    Value::from(user_id), Value::from(name), Value::from(ident_pk),
                    Value::from(sign_pk), Value::from(enc_pk)
                ],
            ),
        ))
    }
    fn add_satellite(
        &mut self,
        user_id: Id,
        name: String,
        ident_pk: Vec<u8>,
        sign_pk: Vec<u8>,
        enc_pk: Vec<u8>,
    ) -> Result<(), ClientError> {
        self.call_action((
            "add_satellite",
            Cow::Owned(
                vec![
                    Value::from(user_id), Value::from(name), Value::from(ident_pk),
                    Value::from(sign_pk), Value::from(enc_pk)
                ],
            ),
        ))
    }
    fn remove_owner(&mut self, user_id: Id) -> Result<(), ClientError> {
        self.call_action(("remove_owner", Cow::Borrowed(&[Value::from(user_id)])))
    }
    fn remove_admin(&mut self, user_id: Id) -> Result<(), ClientError> {
        self.call_action(("remove_admin", Cow::Borrowed(&[Value::from(user_id)])))
    }
    fn remove_operator(&mut self, user_id: Id) -> Result<(), ClientError> {
        self.call_action(("remove_operator", Cow::Borrowed(&[Value::from(user_id)])))
    }
    fn remove_satellite(&mut self, user_id: Id) -> Result<(), ClientError> {
        self.call_action(("remove_satellite", Cow::Borrowed(&[Value::from(user_id)])))
    }
    fn create_aps_label(&mut self, name: String, label: i64) -> Result<(), ClientError> {
        self.call_action((
            "create_aps_label",
            Cow::Owned(vec![Value::from(name), Value::from(label)]),
        ))
    }
    fn assign_aps_label(
        &mut self,
        user_id: Id,
        label: i64,
        op: String,
    ) -> Result<(), ClientError> {
        self.call_action((
            "assign_aps_label",
            Cow::Owned(vec![Value::from(user_id), Value::from(label), Value::from(op)]),
        ))
    }
    fn revoke_aps_label(&mut self, user_id: Id, label: i64) -> Result<(), ClientError> {
        self.call_action((
            "revoke_aps_label",
            Cow::Borrowed(&[Value::from(user_id), Value::from(label)]),
        ))
    }
    fn create_aps_bidi_channel(
        &mut self,
        peer_id: Id,
        label: i64,
    ) -> Result<(), ClientError> {
        self.call_action((
            "create_aps_bidi_channel",
            Cow::Borrowed(&[Value::from(peer_id), Value::from(label)]),
        ))
    }
    fn create_aps_uni_channel(
        &mut self,
        seal_id: Id,
        open_id: Id,
        label: i64,
    ) -> Result<(), ClientError> {
        self.call_action((
            "create_aps_uni_channel",
            Cow::Borrowed(
                &[Value::from(seal_id), Value::from(open_id), Value::from(label)],
            ),
        ))
    }
}
