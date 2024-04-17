use policy_ifgen::{macros::effect, KVPair};

#[effect]
pub struct Thing {
    pub a: i64,
    pub b: String,
}

#[test]
fn parse_effect() {
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

    let parsed = Thing { a, b };

    assert_eq!(parsed, order1.try_into().unwrap());

    assert_eq!(parsed, order2.try_into().unwrap());
}

#[cfg(feature = "serde")]
#[test]
fn serde() {
    use serde::{Deserialize, Serialize};

    fn impl_serde<'de, T: Serialize + Deserialize<'de>>() {}

    impl_serde::<Thing>();
}
