#![allow(clippy::enum_variant_names, non_snake_case, unused_imports)]
extern crate alloc;
use alloc::{borrow::Cow, string::String, vec, vec::Vec};
use policy_vm::{Id, KVPair, Value};
use runtime::{ClientError, Policy, VmPolicy};
pub type VmActions<'a> = <VmPolicy as Policy>::Actions<'a>;
pub type VmEffects = <VmPolicy as Policy>::Effects;
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Effects {
    GameStart(GameStart),
    GameUpdate(GameUpdate),
    GameOver(GameOver),
}
impl TryFrom<(String, Vec<KVPair>)> for Effects {
    type Error = EffectsParseError;
    fn try_from((name, fields): VmEffects) -> Result<Self, Self::Error> {
        match name.as_str() {
            "GameStart" => fields.try_into().map(Self::GameStart),
            "GameUpdate" => fields.try_into().map(Self::GameUpdate),
            "GameOver" => fields.try_into().map(Self::GameOver),
            _ => Err(EffectsParseError::UnknownEffectName),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct GameStart {
    pub gameID: Id,
    pub x: Id,
    pub o: Id,
}
impl TryFrom<Vec<KVPair>> for GameStart {
    type Error = EffectsParseError;
    fn try_from(value: Vec<KVPair>) -> Result<Self, Self::Error> {
        let mut fields = &mut value
            .into_iter()
            .map(|kv| kv.into())
            .collect::<alloc::collections::BTreeMap<String, Value>>();
        let parsed = Self {
            gameID: parse_field(fields, "gameID")?,
            x: parse_field(fields, "x")?,
            o: parse_field(fields, "o")?,
        };
        if !fields.is_empty() {
            return Err(EffectsParseError::ExtraFields);
        }
        Ok(parsed)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct GameUpdate {
    pub gameID: Id,
    pub player: Id,
    pub p: String,
    pub X: i64,
    pub Y: i64,
}
impl TryFrom<Vec<KVPair>> for GameUpdate {
    type Error = EffectsParseError;
    fn try_from(value: Vec<KVPair>) -> Result<Self, Self::Error> {
        let mut fields = &mut value
            .into_iter()
            .map(|kv| kv.into())
            .collect::<alloc::collections::BTreeMap<String, Value>>();
        let parsed = Self {
            gameID: parse_field(fields, "gameID")?,
            player: parse_field(fields, "player")?,
            p: parse_field(fields, "p")?,
            X: parse_field(fields, "X")?,
            Y: parse_field(fields, "Y")?,
        };
        if !fields.is_empty() {
            return Err(EffectsParseError::ExtraFields);
        }
        Ok(parsed)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct GameOver {
    pub gameID: Id,
    pub winner: Id,
    pub p: String,
}
impl TryFrom<Vec<KVPair>> for GameOver {
    type Error = EffectsParseError;
    fn try_from(value: Vec<KVPair>) -> Result<Self, Self::Error> {
        let mut fields = &mut value
            .into_iter()
            .map(|kv| kv.into())
            .collect::<alloc::collections::BTreeMap<String, Value>>();
        let parsed = Self {
            gameID: parse_field(fields, "gameID")?,
            winner: parse_field(fields, "winner")?,
            p: parse_field(fields, "p")?,
        };
        if !fields.is_empty() {
            return Err(EffectsParseError::ExtraFields);
        }
        Ok(parsed)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EffectsParseError {
    ExtraFields,
    MissingField,
    FieldTypeMismatch,
    UnknownEffectName,
}
fn parse_field<T: TryFrom<Value>>(
    fields: &mut alloc::collections::BTreeMap<String, Value>,
    name: &str,
) -> Result<T, EffectsParseError> {
    fields
        .remove(name)
        .ok_or(EffectsParseError::MissingField)?
        .try_into()
        .map_err(|_| EffectsParseError::FieldTypeMismatch)
}
pub trait Actor {
    fn call_action(&mut self, action: VmActions<'_>) -> Result<(), ClientError>;
    fn StartGame(&mut self, profileX: Id, profileO: Id) -> Result<(), ClientError> {
        self.call_action((
            "StartGame",
            Cow::Borrowed(&[Value::from(profileX), Value::from(profileO)]),
        ))
    }
    fn MakeMove(&mut self, gameID: Id, x: i64, y: i64) -> Result<(), ClientError> {
        self.call_action((
            "MakeMove",
            Cow::Borrowed(&[Value::from(gameID), Value::from(x), Value::from(y)]),
        ))
    }
}
