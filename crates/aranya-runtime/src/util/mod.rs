pub(crate) mod nonempty;
pub(crate) mod u64_le_serde;

pub(crate) use nonempty::NonEmpty;

pub trait DeserInfallible<T>:
    rkyv::Deserialize<T, rkyv::api::low::LowDeserializer<core::convert::Infallible>>
{
    fn deser_infallible(&self) -> T;
}

impl<T, U> DeserInfallible<T> for U
where
    U: rkyv::Deserialize<T, rkyv::api::low::LowDeserializer<core::convert::Infallible>>,
{
    fn deser_infallible(&self) -> T {
        match rkyv::api::low::deserialize(self) {
            Ok(v) => v,
        }
    }
}
