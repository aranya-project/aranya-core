#![cfg(feature = "proptest")]

use proptest::prelude::*;

use crate::{Identifier, Text};

#[cfg_attr(docsrs, doc(cfg(feature = "proptest")))]
impl Arbitrary for Text {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
        ("[^\0]*")
            .prop_map(|s| s.try_into().expect("regex produces valid text"))
            .boxed()
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "proptest")))]
impl Arbitrary for Identifier {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
        ("[a-zA-Z][a-zA-Z0-9_]*")
            .prop_map(|s| s.try_into().expect("regex produces valid identifiers"))
            .boxed()
    }
}
