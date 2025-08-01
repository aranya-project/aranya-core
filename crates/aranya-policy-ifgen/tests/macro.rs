#![allow(non_camel_case_types)]
#![allow(clippy::too_many_arguments)]

use aranya_policy_ifgen::{KVPair, macros::*};
use aranya_policy_vm::{Text, ident, text};

#[effects]
pub enum EffectEnum {
    TestEffect(TestEffect),
    TestEffectFields(TestEffectFields),
}

#[effect]
#[derive(Default)]
pub struct TestEffect {
    pub a: i64,
    pub b: Text,
}

#[effect]
#[derive(Default)]
pub struct TestEffectFields {
    int: i64,
    bool: bool,
    string: Text,
    bytes: Vec<u8>,
    r#struct: OtherStruct,
    r#enum: TestEnum,
    optional_int: Option<i64>,
    optional_struct: Option<TestStructFields>,
    optional_enum: Option<TestEnum>,
    optional_nested: Option<Option<Option<Option<i64>>>>,
}

#[value]
#[derive(Default)]
pub struct TestStructFields {
    int: i64,
    bool: bool,
    string: Text,
    bytes: Vec<u8>,
    r#struct: OtherStruct,
    r#enum: TestEnum,
    optional_int: Option<i64>,
    optional_struct: Option<OtherStruct>,
    optional_enum: Option<TestEnum>,
    optional_nested: Option<Option<Option<Option<i64>>>>,
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

pub struct Interface;

#[actions(interface = Interface)]
pub enum TestActions {
    act(act),
}

#[action(interface = Interface)]
pub struct act {
    pub int: i64,
    pub bool: bool,
    pub string: Text,
    pub bytes: Vec<u8>,
    pub r#struct: TestStructFields,
    pub r#enum: TestEnum,
    pub optional_int: Option<i64>,
    pub optional_struct: Option<TestStructFields>,
    pub optional_enum: Option<TestEnum>,
    pub optional_nested: Option<Option<Option<Option<i64>>>>,
}

#[test]
fn test_parse_effect() {
    let a = 42;
    let b = text!("b");

    let order1 = vec![
        KVPair::new(ident!("a"), a.into()),
        KVPair::new(ident!("b"), b.clone().into()),
    ];

    let order2 = vec![
        KVPair::new(ident!("b"), b.clone().into()),
        KVPair::new(ident!("a"), a.into()),
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
