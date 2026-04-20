//! Ensures the `id` facade in aranya-core is usable without importing aranya-id.

use aranya_core::id::{BaseId, Id, IdTag, ParseIdError, custom_id};

custom_id! {
    /// A test ID.
    pub struct TestId;
}

custom_id! {
    pub struct OtherId;
}

#[test]
fn custom_id_decode_and_display() {
    let bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
    let id = TestId::from(bytes);
    let s = id.to_string();
    let parsed: TestId = s.parse().unwrap();
    assert_eq!(id, parsed);
    assert_eq!(id.as_array(), &bytes);
}

#[test]
fn custom_id_transmute_roundtrip() {
    let bytes: [u8; 32] = core::array::from_fn(|i| !(i as u8));
    let id = TestId::from(bytes);
    let base: BaseId = id.as_base();
    let other: OtherId = OtherId::from_base(base);
    assert_eq!(other.as_array(), &bytes);
}

#[test]
fn parse_err_is_error_type() {
    let err: Result<TestId, ParseIdError> = "not-base58-!!!".parse();
    assert!(err.is_err());
}

fn accepts_any_id<T: IdTag>(_: Id<T>) {}

#[test]
fn generic_usage_across_facade() {
    let id = TestId::default();
    accepts_any_id(id);
}
