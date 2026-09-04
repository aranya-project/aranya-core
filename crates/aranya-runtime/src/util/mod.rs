pub(crate) mod u64_le_serde;

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
