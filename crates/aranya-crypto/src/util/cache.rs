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

#[cfg(test)]
mod test {
    use std::{
        sync::{Barrier, atomic::AtomicUsize},
        thread,
    };

    use super::*;

    #[test]
    fn test_simple() {
        #![expect(clippy::redundant_clone, reason = "testing clone")]

        let cell = CacheCell::<i32>::new();

        // Starts empty.
        assert_eq!(cell.get(), None);

        // Can initialize and get back the value.
        assert_eq!(cell.get_or_init(|| 42), 42);
        assert_eq!(*cell.get().unwrap(), 42);

        // Doesn't reinitialize.
        assert_eq!(cell.get_or_init(|| 0), 42);
        // Still has old value.
        assert_eq!(*cell.get().unwrap(), 42);

        // Cloning after init clones value.
        assert_eq!(*cell.clone().get().unwrap(), 42);
    }

    #[test]
    fn test_concurrent_init() {
        let cell = CacheCell::<i32>::new();
        // Barrier to ensure concurrent initialization.
        let b1 = Barrier::new(2);
        // Barrier to ensure thread 1 finishes first.
        let b2 = Barrier::new(2);
        // Thread 1 and 2 try to initialize the cell concurrently.
        // Each will receive their own created output value.
        thread::scope(|s| {
            s.spawn(|| {
                let val = cell.get_or_init(|| {
                    // Wait to ensure both threads have called `get_or_init`.
                    b1.wait();
                    1
                });
                assert_eq!(val, 1);
                // Let thread 2 know we've finished.
                b2.wait();
            });
            s.spawn(|| {
                let val = cell.get_or_init(|| {
                    // Wait to ensure both threads have called `get_or_init`.
                    b1.wait();
                    // Wait to let thread 1 finish first.
                    b2.wait();
                    2
                });
                assert_eq!(val, 2);
            });
        });
        // Since thread 1 finished first, the cell will hold 1.
        let val = *cell.get().unwrap();
        assert_eq!(val, 1);
    }

    #[test]
    fn it_creates_empty_cell_when_cloned_during_initialization() {
        let cell = CacheCell::<i32>::new();
        let b1 = Barrier::new(2);
        let b2 = Barrier::new(2);
        let b3 = Barrier::new(2);
        thread::scope(|s| {
            s.spawn(|| {
                let val = cell.get_or_init(|| {
                    b1.wait();
                    b2.wait();
                    1
                });
                assert_eq!(val, 1);
                b3.wait();
            });
            s.spawn(|| {
                b1.wait();
                // Clone during init should create empty cell.
                let cloned = cell.clone();
                b2.wait();
                // Wait for after first cell has been initialized.
                b3.wait();
                assert_eq!(cloned.get(), None);
            });
        });
    }

    #[test]
    fn it_does_not_drop_contents_when_uninitialized() {
        /// Panics when dropped.
        struct Fragile;
        impl Drop for Fragile {
            fn drop(&mut self) {
                panic!("Dropped Fragile");
            }
        }
        // Dropping unitialized cell should not drop `Fragile`.
        drop(CacheCell::<Fragile>::new());
    }

    #[test]
    fn it_drops_value_exactly_when_expected() {
        /// Create a helper type to count the number of drops.
        #[derive(Clone)]
        struct Counter<'a>(&'a AtomicUsize);
        impl Drop for Counter<'_> {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let count = AtomicUsize::new(0);

        let cell = CacheCell::<Counter<'_>>::new();

        let val = cell.get_or_init(|| Counter(&count));
        assert_eq!(
            count.load(Ordering::Relaxed),
            0,
            "initializing cell should not cause any drops"
        );

        drop(val);
        assert_eq!(
            count.load(Ordering::Relaxed),
            1,
            "dropping cloned out value from init should increase drop count"
        );

        drop(cell);
        assert_eq!(
            count.load(Ordering::Relaxed),
            2,
            "dropping cell should increase drop count"
        );
    }

    /// Check that `CacheCell` is `Send` and `Sync` under appropriate conditions.
    ///
    /// This test will fail to compile if not met.
    #[test]
    fn it_is_thread_safe() {
        // These require the provided type to be `Send` or `Sync` respectively.
        fn is_send<T: Send>() {}
        fn is_sync<T: Sync>() {}

        // These two functions check thread safety of `CachceCell<T>` for all `T` with some precondition.
        fn cache_cell_is_send_when_value_is_send<T: Send>() {
            is_send::<CacheCell<T>>();
        }
        fn cache_cell_is_sync_when_value_is_send_and_sync<T: Send + Sync>() {
            is_sync::<CacheCell<T>>();
        }

        // Check thread safety of specific cells. Should be redundant with the definitions above.
        cache_cell_is_send_when_value_is_send::<core::cell::Cell<()>>();
        cache_cell_is_sync_when_value_is_send_and_sync::<()>();
    }
}
