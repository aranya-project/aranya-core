use std::marker::PhantomData;

use crate::{
    ctx::{Ctx, Results},
    diag::ErrorGuaranteed,
    pass::{Access, DepList, Pass},
};
