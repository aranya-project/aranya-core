#![cfg_attr(not(any(test, doctest)), no_std)]

extern crate alloc;

mod client;
mod command;
mod engine;
mod storage;
mod sync;

pub use crate::{client::*, command::*, engine::*, storage::*, sync::*};

#[cfg(test)]
mod tests;

type HVec2<T> = heapless::Vec<T, 2>;
#[macro_export]
macro_rules! hvec2 {
    () => {
        HVec2::new()
    };
    ($x:expr) => {{
        let mut ret = HVec2::new();
        let _ = ret.push($x);
        ret
    }};
    ($x:expr, $y:expr) => {{
        let mut ret = HVec2::new();
        let _ = ret.push($x);
        let _ = ret.push($y);
        ret
    }};
}
