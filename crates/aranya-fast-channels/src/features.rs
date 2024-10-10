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

#[cfg(not(feature = "try_find"))]
pub trait FromResidual<R = <Self as Try>::Residual> {
    // Required method
    fn from_residual(residual: R) -> Self;
}

#[cfg(not(feature = "try_find"))]
pub trait Try: FromResidual<Self::Residual> {
    type Output;
    type Residual;

    // Required methods
    fn from_output(output: Self::Output) -> Self;
    fn branch(self) -> core::ops::ControlFlow<Self::Residual, Self::Output>;
}

#[cfg(not(feature = "try_find"))]
impl<T, E> Try for Result<T, E> {
    type Output = T;
    type Residual = Result<core::convert::Infallible, E>;

    #[inline]
    fn from_output(output: Self::Output) -> Self {
        Ok(output)
    }

    #[inline]
    fn branch(self) -> core::ops::ControlFlow<Self::Residual, Self::Output> {
        match self {
            Ok(v) => core::ops::ControlFlow::Continue(v),
            Err(e) => core::ops::ControlFlow::Break(Err(e)),
        }
    }
}

#[cfg(not(feature = "try_find"))]
impl<T, E, F: From<E>> FromResidual<Result<core::convert::Infallible, E>> for Result<T, F> {
    #[inline]
    #[track_caller]
    fn from_residual(residual: Result<core::convert::Infallible, E>) -> Self {
        match residual {
            Err(e) => Err(From::from(e)),
            Ok(v) => match v {},
        }
    }
}

#[cfg(not(feature = "try_find"))]
impl<T, E> Residual<T> for Result<core::convert::Infallible, E> {
    type TryType = Result<T, E>;
}

#[cfg(not(feature = "try_find"))]
pub trait Residual<O> {
    type TryType: Try<Output = O, Residual = Self>;
}

#[cfg(not(feature = "try_find"))]
pub(crate) trait TryFind: Iterator {
    fn try_find<F, R>(
        &mut self,
        f: F,
    ) -> <<R as Try>::Residual as Residual<Option<Self::Item>>>::TryType
    where
        Self: Sized,
        F: FnMut(&Self::Item) -> R,
        R: Try<Output = bool>,
        <R as Try>::Residual: Residual<Option<Self::Item>>;
}

#[cfg(not(feature = "try_find"))]
impl<T: Iterator> TryFind for T {
    fn try_find<F, R>(
        &mut self,
        f: F,
    ) -> <<R as Try>::Residual as Residual<Option<Self::Item>>>::TryType
    where
        Self: Sized,
        F: FnMut(&Self::Item) -> R,
        R: Try<Output = bool>,
        <R as Try>::Residual: Residual<Option<Self::Item>>,
    {
        use core::ops::ControlFlow;

        #[inline]
        fn check<I, V, R>(
            mut f: impl FnMut(&I) -> V,
        ) -> impl FnMut((), I) -> ControlFlow<R::TryType>
        where
            V: Try<Output = bool, Residual = R>,
            R: Residual<Option<I>>,
        {
            move |(), x| match f(&x).branch() {
                ControlFlow::Continue(false) => ControlFlow::Continue(()),
                ControlFlow::Continue(true) => ControlFlow::Break(Try::from_output(Some(x))),
                ControlFlow::Break(r) => ControlFlow::Break(FromResidual::from_residual(r)),
            }
        }

        match self.try_fold((), check(f)) {
            ControlFlow::Break(x) => x,
            ControlFlow::Continue(()) => Try::from_output(None),
        }
    }
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
