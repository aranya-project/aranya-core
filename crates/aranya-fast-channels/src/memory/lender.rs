use alloc::boxed::Box;
use core::{
    cell::UnsafeCell,
    fmt,
    ptr::NonNull,
    sync::atomic::{AtomicU8, Ordering},
};

/// `Owner<S, X>` holds shared data `S` and exclusive data `X`.
///
/// It can access `&S` and lend access to `(&S, &mut X)` via [`Lent`].
///
/// Dropping `Owner` will revoke access from `Lent`. If there is an active `Lent`,
/// the data will not be dropped until the `Lent` is dropped.
pub struct Owner<S, X> {
    inner: NonNull<Inner<S, X>>,
}

// SAFETY: Owner is thread-safe.
unsafe impl<S: Send, X: Send> Send for Owner<S, X> {}
// SAFETY: Owner is thread-safe.
unsafe impl<S: Sync, X: Sync> Sync for Owner<S, X> {}

/// `Lent<S, X>` can access shared data `S` and exclusive data `X` while the
/// [`Owner`] is alive.
pub struct Lent<S, X> {
    inner: NonNull<Inner<S, X>>,
}

// SAFETY: Lent is thread-safe.
unsafe impl<S: Send, X: Send> Send for Lent<S, X> {}
// SAFETY: Lent is thread-safe.
unsafe impl<S: Sync, X: Sync> Sync for Lent<S, X> {}

struct Inner<S, X> {
    /// Shared data which can be accessed as `&S` by both [`Owner`] and [`Lent`].
    shared: S,
    /// Exclusive data which can be accessed as `&X` or `&mut X` only by [`Lent`].
    ///
    /// `Unsafe` cell is needed to allow `&Inner<S, X> -> &mut X`.
    exclusive: UnsafeCell<X>,
    /// State for tracking whether the data is unshared, shared, or closed.
    state: AtomicU8,
}

/// Only [`Owner`] has access to the data.
const STATE_UNSHARED: u8 = 0;
/// [`Owner`] has lent access to [`Lent`].
const STATE_SHARED: u8 = 1;
/// [`Owner`] has dropped and revoked access from a potential [`Lent`].
const STATE_CLOSED: u8 = 2;

impl<S, X> Owner<S, X> {
    /// Creates a new [`Owner`] of some shared and exclusive data.
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
        // SAFETY: `inner` is valid while `Owner` is live.
        unsafe { self.inner.as_ref() }
    }

    /// Lends access to the data.
    ///
    /// Only one `Lent` can be live at a time.
    pub fn lend(&self) -> Option<Lent<S, X>> {
        // We must be UNSHARED or SHARED. If we transition to SHARED here, then we can create a `Lent`.
        if self.inner().state.swap(STATE_SHARED, Ordering::AcqRel) != STATE_UNSHARED {
            return None;
        }
        Some(Lent { inner: self.inner })
    }

    /// Accesses the shared data `S`.
    pub fn shared(&self) -> &S {
        &self.inner().shared
    }
}

impl<S, X> Drop for Owner<S, X> {
    fn drop(&mut self) {
        // We must be UNSHARED or SHARED. We transition to CLOSED to revoke access.
        // If we were UNSHARED then there is no `Lent` so we are the sole holder of the data.
        if self.inner().state.swap(STATE_CLOSED, Ordering::AcqRel) == STATE_UNSHARED {
            // SAFETY: The data is not lent out, so we can immediately drop it.
            unsafe { free(self.inner) }
        }
    }
}

impl<S: fmt::Debug, X: fmt::Debug> fmt::Debug for Owner<S, X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Owner")
            .field("shared", self.shared())
            .finish_non_exhaustive()
    }
}

impl<S, X> Lent<S, X> {
    fn inner(&self) -> &Inner<S, X> {
        // SAFETY: `inner` is valid while `Lent` is live.
        unsafe { self.inner.as_ref() }
    }

    /// Accesses the shared and exclusive data.
    ///
    /// Returns `None` if the `Owner` has been dropped. You are encouraged to
    /// drop the `Lent` when this occurs, to drop the underlying data.
    pub fn get_ref(&self) -> Option<(&S, &X)> {
        let inner = self.inner();
        // We must be SHARED or CLOSED. If we are CLOSED, then access has been revoked.
        if inner.state.load(Ordering::Acquire) == STATE_CLOSED {
            return None;
        }
        // SAFETY: Only `Lent` accesses exclusive, so we can borrow it as if we held it directly.
        let exclusive = unsafe { &*inner.exclusive.get() };
        Some((&inner.shared, exclusive))
    }

    /// Accesses the shared and exclusive data.
    ///
    /// Returns `None` if the `Owner` has been dropped. You are encouraged to
    /// drop the `Lent` when this occurs, to drop the underlying data.
    pub fn get_mut(&mut self) -> Option<(&S, &mut X)> {
        let inner = self.inner();
        // We must be SHARED or CLOSED. If we are CLOSED, then access has been revoked.
        if inner.state.load(Ordering::Acquire) == STATE_CLOSED {
            return None;
        }
        // SAFETY: Only `Lent` accesses exclusive, so we can borrow it as if we held it directly.
        let exclusive = unsafe { &mut *inner.exclusive.get() };
        Some((&inner.shared, exclusive))
    }
}

impl<S, X> Drop for Lent<S, X> {
    fn drop(&mut self) {
        // We must be SHARED or CLOSED. We will transition back to UNSHARED here.
        // - If we were SHARED, this will allow the `Owner` to lend again.
        // - If we were CLOSED, the `Owner` has already dropped, so it's fine that we
        //   are erasing the CLOSED state because nobody else can see it. We are the sole
        //   holder of the data so we must free it.
        if self.inner().state.swap(STATE_UNSHARED, Ordering::AcqRel) == STATE_CLOSED {
            // SAFETY: `Owner` was already dropped, but didn't free the data
            // since it was lent out, so we can free it now.
            unsafe { free(self.inner) }
        }
    }
}

impl<S: fmt::Debug, X: fmt::Debug> fmt::Debug for Lent<S, X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Lent");
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
