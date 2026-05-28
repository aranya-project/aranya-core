use alloc::boxed::Box;
use core::{
    cell::UnsafeCell,
    fmt,
    ptr::NonNull,
    sync::atomic::{AtomicU8, Ordering},
};

/// `Lender<S, X>` holds shared data `S` and exclusive data `X`.
///
/// It can access `&S` and lend access to `(&S, &mut X)` via [`Loan`].
///
/// Dropping `Lender` will revoke access from `Loan`. If there is an active `Loan`,
/// the data will not be dropped until the `Loan` is dropped.
pub struct Lender<S, X> {
    inner: NonNull<Inner<S, X>>,
}

// SAFETY: Lender is thread-safe.
unsafe impl<S: Send, X: Send> Send for Lender<S, X> {}
// SAFETY: Lender is thread-safe.
unsafe impl<S: Sync, X: Sync> Sync for Lender<S, X> {}

/// `Loan<S, X>` can access shared data `S` and exclusive data `X` while the
/// [`Lender`] is alive.
pub struct Loan<S, X> {
    inner: NonNull<Inner<S, X>>,
}

// SAFETY: Loan is thread-safe.
unsafe impl<S: Send, X: Send> Send for Loan<S, X> {}
// SAFETY: Loan is thread-safe.
unsafe impl<S: Sync, X: Sync> Sync for Loan<S, X> {}

struct Inner<S, X> {
    /// Shared data which can be accessed as `&S` by both [`Lender`] and [`Loan`].
    shared: S,
    /// Exclusive data which can be accessed as `&X` or `&mut X` only by [`Loan`].
    ///
    /// `Unsafe` cell is needed to allow `&Inner<S, X> -> &mut X`.
    exclusive: UnsafeCell<X>,
    /// State for tracking whether the data is unshared, shared, or closed.
    state: AtomicU8,
}

/// Only [`Lender`] has access to the data.
const STATE_UNSHARED: u8 = 0;
/// [`Lender`] has lent access to [`Loan`].
const STATE_SHARED: u8 = 1;
/// [`Lender`] has dropped and revoked access from a potential [`Loan`].
const STATE_CLOSED: u8 = 2;

impl<S, X> Lender<S, X> {
    /// Creates a new [`Lender`] of some shared and exclusive data.
    pub fn new(shared: S, exclusive: X) -> Self {
        Self {
            inner: allocate(Inner {
                shared,
                exclusive: UnsafeCell::new(exclusive),
                state: AtomicU8::new(STATE_UNSHARED),
            }),
        }
    }

    fn inner(&self) -> &Inner<S, X> {
        // SAFETY: `inner` is valid while `Lender` is live.
        unsafe { self.inner.as_ref() }
    }

    /// Lends access to the data.
    ///
    /// Only one `Loan` can be live at a time.
    pub fn lend(&self) -> Option<Loan<S, X>> {
        // We must be UNSHARED or SHARED. If we transition to SHARED here, then we can create a `Loan`.
        if self.inner().state.swap(STATE_SHARED, Ordering::AcqRel) != STATE_UNSHARED {
            return None;
        }
        Some(Loan { inner: self.inner })
    }

    /// Accesses the shared data `S`.
    pub fn shared(&self) -> &S {
        &self.inner().shared
    }
}

impl<S, X> Drop for Lender<S, X> {
    fn drop(&mut self) {
        // We must be UNSHARED or SHARED. We transition to CLOSED to revoke access.
        // If we were UNSHARED then there is no `Loan` so we are the sole holder of the data.
        if self.inner().state.swap(STATE_CLOSED, Ordering::AcqRel) == STATE_UNSHARED {
            // SAFETY: The data is not lent out, so we can immediately drop it.
            unsafe { free(self.inner) }
        }
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
    fn inner(&self) -> &Inner<S, X> {
        // SAFETY: `inner` is valid while `Loan` is live.
        unsafe { self.inner.as_ref() }
    }

    /// Accesses the shared and exclusive data.
    ///
    /// Returns `None` if the `Lender` has been dropped. You are encouraged to
    /// drop the `Loan` when this occurs, to drop the underlying data.
    pub fn get_ref(&self) -> Option<(&S, &X)> {
        let inner = self.inner();
        // We must be SHARED or CLOSED. If we are CLOSED, then access has been revoked.
        if inner.state.load(Ordering::Acquire) == STATE_CLOSED {
            return None;
        }
        // SAFETY: Only `Loan` accesses exclusive, so we can borrow it as if we held it directly.
        let exclusive = unsafe { &*inner.exclusive.get() };
        Some((&inner.shared, exclusive))
    }

    /// Accesses the shared and exclusive data.
    ///
    /// Returns `None` if the `Lender` has been dropped. You are encouraged to
    /// drop the `Loan` when this occurs, to drop the underlying data.
    pub fn get_mut(&mut self) -> Option<(&S, &mut X)> {
        let inner = self.inner();
        // We must be SHARED or CLOSED. If we are CLOSED, then access has been revoked.
        if inner.state.load(Ordering::Acquire) == STATE_CLOSED {
            return None;
        }
        // SAFETY: Only `Loan` accesses exclusive, so we can borrow it as if we held it directly.
        let exclusive = unsafe { &mut *inner.exclusive.get() };
        Some((&inner.shared, exclusive))
    }
}

impl<S, X> Drop for Loan<S, X> {
    fn drop(&mut self) {
        // We must be SHARED or CLOSED. We will transition back to UNSHARED here.
        // - If we were SHARED, this will allow the `Lender` to lend again.
        // - If we were CLOSED, the `Lender` has already dropped, so it's fine that we
        //   are erasing the CLOSED state because nobody else can see it. We are the sole
        //   holder of the data so we must free it.
        if self.inner().state.swap(STATE_UNSHARED, Ordering::AcqRel) == STATE_CLOSED {
            // SAFETY: `Lender` was already dropped, but didn't free the data
            // since it was lent out, so we can free it now.
            unsafe { free(self.inner) }
        }
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

/// Allocate a value on the heap.
fn allocate<T>(val: T) -> NonNull<T> {
    let ptr = Box::into_raw(Box::new(val));
    // SAFETY: `Box::into_raw` returns a non-null pointer.
    unsafe { NonNull::new_unchecked(ptr) }
}

/// Free a pointer from `allocate`.
unsafe fn free<T>(ptr: NonNull<T>) {
    // SAFETY: Passed in pointer must be valid.
    unsafe {
        drop(Box::from_raw(ptr.as_ptr()));
    }
}
