use policy_ifgen::{macros::*, KVPair};

#[effect]
pub struct TestEffect {
    pub a: i64,
    pub b: String,
}

#[value]
pub struct TestStruct {
    _int: i64,
    _bool: bool,
    _string: String,
    _bytes: Vec<u8>,
    _struct: OtherStruct,
    _enum: TestEnum,
    // _optional: Option<i64>, // TODO(#764)
}

#[value]
struct OtherStruct {}

#[value]
enum TestEnum {
    A,
    B,
    C,
}

#[test]
fn test_parse_effect() {
    let a = 42;
    let b = String::from("b");

    let order1 = vec![
        KVPair::new("a", a.into()),
        KVPair::new("b", b.clone().into()),
    ];

    let order2 = vec![
        KVPair::new("b", b.clone().into()),
        KVPair::new("a", a.into()),
    ];

    let parsed = TestEffect { a, b };

    assert_eq!(parsed, order1.try_into().unwrap());

    assert_eq!(parsed, order2.try_into().unwrap());
}

#[cfg(feature = "serde")]
#[test]
fn test_serde() {
    use serde::{Deserialize, Serialize};

    fn impl_serde<'de, T: Serialize + Deserialize<'de>>() {}

    impl_serde::<TestEffect>();
}
