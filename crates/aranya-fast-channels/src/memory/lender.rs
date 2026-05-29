use core::{cell::UnsafeCell, fmt};

mod biarc {
    use alloc::boxed::Box;
    use core::{
        ptr::NonNull,
        sync::atomic::{AtomicBool, Ordering},
    };

    // BiArc is an Arc-like type which supports 1 or 2 handles.
    pub struct BiArc<T>(NonNull<BiArcInner<T>>);

    // SAFETY: BiArc is thread-safe.
    unsafe impl<T: Send> Send for BiArc<T> {}
    // SAFETY: BiArc is thread-safe.
    unsafe impl<T: Sync> Sync for BiArc<T> {}

    struct BiArcInner<T> {
        /// Indicates whether a second `BiArc` points to this.
        state: AtomicBool,
        value: T,
    }

    /// Only one [`BiArc`] handle to this instance exists.
    const STATE_UNSHARED: bool = false;
    /// Two [`BiArc`] handles to this instance exist.
    const STATE_SHARED: bool = true;

    impl<T> BiArc<T> {
        pub fn new(value: T) -> Self {
            let ptr = Box::into_raw(Box::new(BiArcInner {
                state: AtomicBool::new(STATE_UNSHARED),
                value,
            }));
            // SAFETY: `Box::into_raw` returns a non-null pointer.
            let ptr = unsafe { NonNull::new_unchecked(ptr) };
            Self(ptr)
        }

        fn inner(&self) -> &BiArcInner<T> {
            // SAFETY: `inner` is valid while this is live.
            unsafe { self.0.as_ref() }
        }

        /// Try to create a second handle, if it doesn't already exist.
        pub fn try_clone(&self) -> Option<Self> {
            // Try to transition to SHARED.
            match self.inner().state.swap(STATE_SHARED, Ordering::AcqRel) {
                // We were not already shared so we can create another handle.
                STATE_UNSHARED => Some(Self(self.0)),
                // We were already shared so we can't create a third handle.
                STATE_SHARED => None,
            }
        }

        /// Get the inner data unconditionally.
        pub fn get_unconditional(&self) -> &T {
            &self.inner().value
        }

        /// Get the inner data only if there is currently a second handle.
        pub fn get_if_shared(&self) -> Option<&T> {
            match self.inner().state.load(Ordering::Acquire) {
                STATE_UNSHARED => None,
                STATE_SHARED => Some(&self.inner().value),
            }
        }
    }

    impl<T> Drop for BiArc<T> {
        fn drop(&mut self) {
            // We transition to UNSHARED since there will no longer be multiple BiArcs active.
            // If we were already UNSHARED then we are the sole holder of the data.
            if self.inner().state.swap(STATE_UNSHARED, Ordering::AcqRel) == STATE_UNSHARED {
                // SAFETY: The data is not shared, so we can immediately drop it.
                unsafe {
                    drop(Box::from_raw(self.0.as_ptr()));
                }
            }
        }
    }
}
use biarc::BiArc;

/// `Lender<S, X>` holds shared data `S` and exclusive data `X`.
///
/// It can access `&S` and lend access to `(&S, &mut X)` via [`Loan`].
///
/// Dropping `Lender` will revoke access from `Loan`. If there is an active `Loan`,
/// the data will not be dropped until the `Loan` is dropped.
pub struct Lender<S, X> {
    data: BiArc<Data<S, X>>,
}

/// `Loan<S, X>` can access shared data `S` and exclusive data `X` while the
/// [`Lender`] is alive.
pub struct Loan<S, X> {
    data: BiArc<Data<S, X>>,
}

struct Data<S, X> {
    /// Shared data which can be accessed as `&S` by both [`Lender`] and [`Loan`].
    shared: S,
    /// Exclusive data which can be accessed as `&X` or `&mut X` only by [`Loan`].
    ///
    /// `Unsafe` cell is needed to allow `&Inner<S, X> -> &mut X`.
    exclusive: UnsafeCell<X>,
}

impl<S, X> Lender<S, X> {
    /// Creates a new [`Lender`] of some shared and exclusive data.
    pub fn new(shared: S, exclusive: X) -> Self {
        Self {
            data: BiArc::new(Data {
                shared,
                exclusive: UnsafeCell::new(exclusive),
            }),
        }
    }

    /// Lends access to the data.
    ///
    /// Only one `Loan` can be live at a time.
    pub fn lend(&self) -> Option<Loan<S, X>> {
        Some(Loan {
            data: self.data.try_clone()?,
        })
    }

    /// Accesses the shared data `S`.
    pub fn shared(&self) -> &S {
        &self.data.get_unconditional().shared
    }
}

impl<S: fmt::Debug, X: fmt::Debug> fmt::Debug for Lender<S, X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lender")
            .field("shared", self.shared())
            .finish_non_exhaustive()
    }
}

impl<S, X> Loan<S, X> {
    /// Accesses the shared and exclusive data.
    ///
    /// Returns `None` if the `Lender` has been dropped. You are encouraged to
    /// drop the `Loan` when this occurs, to drop the underlying data.
    pub fn get_ref(&self) -> Option<(&S, &X)> {
        let data = self.data.get_if_shared()?;
        // SAFETY: Only `Loan` accesses `exclusive`, so we can borrow it as if we held it directly.
        let exclusive = unsafe { &*data.exclusive.get() };
        Some((&data.shared, exclusive))
    }

    /// Accesses the shared and exclusive data.
    ///
    /// Returns `None` if the `Lender` has been dropped. You are encouraged to
    /// drop the `Loan` when this occurs, to drop the underlying data.
    pub fn get_mut(&mut self) -> Option<(&S, &mut X)> {
        let data = self.data.get_if_shared()?;
        // SAFETY: Only `Loan` accesses `exclusive`, so we can borrow it as if we held it directly.
        let exclusive = unsafe { &mut *data.exclusive.get() };
        Some((&data.shared, exclusive))
    }
}

impl<S: fmt::Debug, X: fmt::Debug> fmt::Debug for Loan<S, X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Loan");
        match self.get_ref() {
            Some((shared, exclusive)) => s
                .field("shared", shared)
                .field("exclusive", exclusive)
                .finish(),
            None => s.finish_non_exhaustive(),
        }
    }
}
