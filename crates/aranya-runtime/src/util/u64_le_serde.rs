use rend::u64_le;
use serde::{Deserialize as _, Serialize as _, de::Deserializer, ser::Serializer};

pub fn serialize<S>(val: &u64_le, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    val.to_native().serialize(serializer)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<u64_le, D::Error>
where
    D: Deserializer<'de>,
{
    u64::deserialize(deserializer).map(u64_le::from_native)
}
