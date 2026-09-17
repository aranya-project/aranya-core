#![expect(unsafe_code)]

use core::{
    cell::UnsafeCell,
    fmt,
    mem::MaybeUninit,
    sync::atomic::{AtomicU8, Ordering},
};

const STATE_UNINIT: u8 = 0;
const STATE_LOCKED: u8 = 1;
const STATE_INIT: u8 = 2;

/// Thread safe caching cell.
///
/// Never blocks, instead recomputing the value when contended.
pub struct CacheCell<T> {
    state: AtomicU8,
    data: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: `CacheCell<T>` is thread-safe and acts as though it holds `T` for the purpose of `Send`.
unsafe impl<T: Send> Send for CacheCell<T> {}
// SAFETY: `CacheCell<T>` is thread-safe. We require `Send` because you can set the value via
// `&Self` in another thread.
unsafe impl<T: Send + Sync> Sync for CacheCell<T> {}

impl<T> CacheCell<T> {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(STATE_UNINIT),
            data: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    const fn with_value(val: T) -> Self {
        Self {
            state: AtomicU8::new(STATE_INIT),
            data: UnsafeCell::new(MaybeUninit::new(val)),
        }
    }

    fn get(&self) -> Option<&T> {
        if self.state.load(Ordering::Acquire) == STATE_INIT {
            // SAFETY: The state indicates the value has been initialized.
            Some(unsafe { self.get_unchecked() })
        } else {
            None
        }
    }

    unsafe fn get_unchecked(&self) -> &T {
        // SAFETY: Caller must ensure the data is initialized.
        unsafe { self.data.get().as_ref_unchecked().assume_init_ref() }
    }
}

impl<T: Clone> CacheCell<T> {
    /// Get the cached value or compute and potentially store it.
    ///
    /// Will call the init function "spuriously" on contention rather than waiting.
    pub fn get_or_init(&self, init: impl FnOnce() -> T) -> T {
        if let Some(val) = self.get() {
            return val.clone();
        }

        core::hint::cold_path();

        // Compute value before trying to lock.
        let val = init();

        if self
            .state
            .compare_exchange(
                STATE_UNINIT,
                STATE_LOCKED,
                // Relaxed because we only need to ensure we are the sole writer.
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            // SAFETY: We exclusively locked the state.
            unsafe { self.data.get().as_mut_unchecked() }.write(val);
            // Release pairs with the Acquire in `Self::get` to guard reading the data.
            self.state.store(STATE_INIT, Ordering::Release);
            // SAFETY: We just initialized the value.
            unsafe { self.get_unchecked() }.clone()
        } else {
            // Someone else is initializing the cache so just return our computed value.
            // We don't want to wait if it is currently locked. We could clone the cached
            // value if it has already been released but there's no point since we already
            // have a value that we computed.
            val
        }
    }
}

impl<T: Clone> Clone for CacheCell<T> {
    fn clone(&self) -> Self {
        match self.get() {
            Some(value) => Self::with_value(value.clone()),
            None => Self::new(),
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for CacheCell<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get() {
            Some(val) => fmt::Debug::fmt(val, f),
            None => f.write_str("<uninit>"),
        }
    }
}

impl<T> Default for CacheCell<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for CacheCell<T> {
    fn drop(&mut self) {
        if *self.state.get_mut() == STATE_INIT {
            let data = self.data.get_mut();
            // SAFETY: The state indicates the data been initialized.
            unsafe {
                data.assume_init_drop();
            }
        }
    }
}
