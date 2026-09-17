pub(crate) mod nonempty;
pub(crate) mod u64_le_serde;

pub(crate) use nonempty::NonEmpty;

/// Helper function for defining constants which differ based on the `low-mem-usage` feature.
pub(crate) const fn mem_usage<T: Copy>(low: T, high: T) -> T {
    if cfg!(doc) {
        // show high value in rustdoc since it is more common.
        high
    } else if cfg!(feature = "low-mem-usage") {
        low
    } else {
        high
    }
}

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
