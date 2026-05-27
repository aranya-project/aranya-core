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
    shared: S,
    exclusive: UnsafeCell<X>,
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
        if self.inner().state.swap(STATE_SHARED, Ordering::AcqRel) != STATE_UNSHARED {
            return None;
        }
        Some(Lent { inner: self.inner })
    }

    /// Accesses the shared data `S`.
    pub fn shared(&self) -> &S {
        &self.inner().shared
    }

    /// Accesses the exclusive data `X`.
    ///
    /// Returns `None` if access is currently lent via [`Self::lend`].
    pub fn exclusive_ref(&self) -> Option<&X> {
        let inner = self.inner();
        if inner.state.load(Ordering::Acquire) == STATE_SHARED {
            return None;
        }
        // SAFETY: The data is not lent.
        Some(unsafe { &*inner.exclusive.get() })
    }
}

impl<S, X> Drop for Owner<S, X> {
    fn drop(&mut self) {
        if self.inner().state.swap(STATE_CLOSED, Ordering::AcqRel) == STATE_UNSHARED {
            // SAFETY: The data is not lent out, so we can immediately drop it.
            unsafe { free(self.inner) }
        }
    }
}

impl<S: fmt::Debug, X: fmt::Debug> fmt::Debug for Owner<S, X> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Owner")
            .field("shared", self.shared())
            .field("exclusive", self.exclusive_ref().map_or(&"<lent>", |x| x))
            .finish()
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
        if inner.state.load(Ordering::Acquire) == STATE_CLOSED {
            return None;
        }
        // SAFETY: `Lent` has exclusive access.
        let exclusive = unsafe { &*inner.exclusive.get() };
        Some((&inner.shared, exclusive))
    }

    /// Accesses the shared and exclusive data.
    ///
    /// Returns `None` if the `Owner` has been dropped. You are encouraged to
    /// drop the `Lent` when this occurs, to drop the underlying data.
    pub fn get_mut(&mut self) -> Option<(&S, &mut X)> {
        let inner = self.inner();
        if inner.state.load(Ordering::Acquire) == STATE_CLOSED {
            return None;
        }
        // SAFETY: `Lent` has exclusive access and this method is `&mut`.
        let exclusive = unsafe { &mut *inner.exclusive.get() };
        Some((&inner.shared, exclusive))
    }
}

impl<S, X> Drop for Lent<S, X> {
    fn drop(&mut self) {
        if self.inner().state.swap(STATE_UNSHARED, Ordering::AcqRel) == STATE_CLOSED {
            // SAFETY: `Owner` was already dropped, but didn't free the data
            // since it was lent out, so we can free it now.
            unsafe { free(self.inner) }
        }
    }
}

impl<S: fmt::Debug, X: fmt::Debug> fmt::Debug for Lent<S, X> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
