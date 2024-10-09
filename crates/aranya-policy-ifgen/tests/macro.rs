use aranya_policy_ifgen::{macros::*, ClientError, KVPair};

#[effects]
pub enum EffectEnum {
    TestEffect(TestEffect),
    TestEffectFields(TestEffectFields),
}

#[effect]
#[derive(Default)]
pub struct TestEffect {
    pub a: i64,
    pub b: String,
}

#[effect]
#[derive(Default)]
pub struct TestEffectFields {
    _int: i64,
    _bool: bool,
    _string: String,
    _bytes: Vec<u8>,
    _struct: OtherStruct,
    _enum: TestEnum,
    _optional_int: Option<i64>,
    _optional_struct: Option<TestStructFields>,
    _optional_enum: Option<TestEnum>,
    _optional_nested: Option<Option<Option<Option<i64>>>>,
}

#[value]
#[derive(Default)]
pub struct TestStructFields {
    _int: i64,
    _bool: bool,
    _string: String,
    _bytes: Vec<u8>,
    _struct: OtherStruct,
    _enum: TestEnum,
    _optional_int: Option<i64>,
    _optional_struct: Option<OtherStruct>,
    _optional_enum: Option<TestEnum>,
    _optional_nested: Option<Option<Option<Option<i64>>>>,
}

#[value]
#[derive(Default)]
pub struct OtherStruct {}

#[value]
#[derive(Default)]
pub enum TestEnum {
    #[default]
    A,
    B,
    C,
}

#[allow(clippy::too_many_arguments)]
#[actions]
pub trait TestActions {
    fn act(
        &mut self,
        _int: i64,
        _bool: bool,
        _string: String,
        _bytes: Vec<u8>,
        _struct: TestStructFields,
        _enum: TestEnum,
        _optional_int: Option<i64>,
        _optional_struct: Option<TestStructFields>,
        _optional_enum: Option<TestEnum>,
        _optional_nested: Option<Option<Option<Option<i64>>>>,
    ) -> Result<(), ClientError>;
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

#[test]
fn test_effect_enum() {
    let effect = TestEffect::default();
    assert_eq!(effect.name(), "TestEffect");
    let effect = EffectEnum::TestEffect(effect);
    assert_eq!(effect.name(), "TestEffect");

    let effect = TestEffectFields::default();
    assert_eq!(effect.name(), "TestEffectFields");
    let effect = EffectEnum::TestEffectFields(effect);
    assert_eq!(effect.name(), "TestEffectFields");
}

#[cfg(feature = "serde")]
#[test]
fn test_serde() {
    use serde::{Deserialize, Serialize};

    fn impl_serde<'de, T: Serialize + Deserialize<'de>>() {}

    impl_serde::<TestEffect>();
}
