// Depending on the configuration, we might not use some of the
// macros.
#![allow(unused_macros, dead_code, unused_qualifications, clippy::ptr_as_ptr)]

#[cfg(not(feature = "core_intrinsics"))]
#[cold]
pub(crate) fn cold() {}

#[cfg(not(feature = "core_intrinsics"))]
macro_rules! likely {
    ($expr:expr) => {
        if $expr {
            true
        } else {
            $crate::features::cold();
            false
        }
    };
}

#[cfg(feature = "core_intrinsics")]
macro_rules! likely {
    ($expr:expr) => {
        core::intrinsics::likely($expr)
    };
}

#[cfg(not(feature = "core_intrinsics"))]
macro_rules! unlikely {
    ($expr:expr) => {
        if $expr {
            $crate::features::cold();
            true
        } else {
            false
        }
    };
}

#[cfg(feature = "core_intrinsics")]
macro_rules! unlikely {
    ($expr:expr) => {
        core::intrinsics::unlikely($expr)
    };
}

#[cfg(test)]
mod tests {
    use core::hint;

    #[test]
    fn test_likely() {
        assert!(likely!(hint::black_box(true)));
        assert!(!likely!(hint::black_box(false)));
    }

    #[test]
    fn test_unlikely() {
        assert!(unlikely!(hint::black_box(true)));
        assert!(!unlikely!(hint::black_box(false)));
    }
}
