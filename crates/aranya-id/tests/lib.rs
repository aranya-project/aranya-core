aranya_id::custom_id! {
    struct MyId;
}

fn make_id() -> MyId {
    MyId::from(std::array::from_fn(|i| !(i as u8)))
}

#[test]
fn json_roundtrip() {
    let id = make_id();
    let ser = serde_json::to_string(&id).unwrap();
    assert_eq!(ser, format!("\"{id}\""));
    let got: MyId = serde_json::from_str(&ser).unwrap();
    assert_eq!(id, got);
}

#[test]
fn postcard_roundtrip() {
    let id = make_id();
    let ser = postcard::to_allocvec(&id).unwrap();
    assert_eq!(32, ser[0]); // Length
    assert_eq!(id.as_bytes(), &ser[1..]);
    let got: MyId = postcard::from_bytes(&ser).unwrap();
    assert_eq!(id, got);
}
