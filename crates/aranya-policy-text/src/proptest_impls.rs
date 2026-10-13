#![cfg(feature = "proptest")]

use alloc::string::String;

use proptest::{
    collection::{SizeRange, vec},
    prelude::*,
    strategy::Union,
};

use crate::{Identifier, Text};

#[cfg_attr(docsrs, doc(cfg(feature = "proptest")))]
impl Arbitrary for Text {
    type Parameters = SizeRange;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(size_range: Self::Parameters) -> Self::Strategy {
        // [^\0]*
        vec(proptest::char::range('\x01', char::MAX), size_range)
            .prop_map(|chars| {
                let string: String = chars.into_iter().collect();
                string.try_into().expect("strategy produces valid text")
            })
            .boxed()
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "proptest")))]
impl Arbitrary for Identifier {
    type Parameters = SizeRange;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(size_range: Self::Parameters) -> Self::Strategy {
        // [a-zA-Z][a-zA-Z0-9_]*
        (
            Union::new([b'a'..=b'z', b'A'..=b'Z']),
            vec(
                Union::new([b'a'..=b'z', b'A'..=b'Z', b'0'..=b'9', b'_'..=b'_']),
                size_range,
            ),
        )
            .prop_map(|(first, mut bytes)| {
                bytes.insert(0, first);
                let string: String = String::from_utf8(bytes).expect("strategy produces utf8");
                string
                    .try_into()
                    .expect("strategy produces valid identifiers")
            })
            .boxed()
    }
}
