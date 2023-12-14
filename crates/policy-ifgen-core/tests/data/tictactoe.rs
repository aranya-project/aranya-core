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
        let mut iter = value.into_iter();
        Ok(Self {
            gameID: parse_field("gameID", iter.next())?,
            x: parse_field("x", iter.next())?,
            o: parse_field("o", iter.next())?,
        })
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
        let mut iter = value.into_iter();
        Ok(Self {
            gameID: parse_field("gameID", iter.next())?,
            player: parse_field("player", iter.next())?,
            p: parse_field("p", iter.next())?,
            X: parse_field("X", iter.next())?,
            Y: parse_field("Y", iter.next())?,
        })
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
        let mut iter = value.into_iter();
        Ok(Self {
            gameID: parse_field("gameID", iter.next())?,
            winner: parse_field("winner", iter.next())?,
            p: parse_field("p", iter.next())?,
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
