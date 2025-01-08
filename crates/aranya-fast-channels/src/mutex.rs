//! Mutex implementations.

#![cfg(any(test, feature = "memory", feature = "sdlib", feature = "posix"))]

use core::{
    cell::UnsafeCell,
    convert::Infallible,
    marker::PhantomData,
    mem::size_of,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicU32, Ordering},
};

use cfg_if::cfg_if;

use crate::util::const_assert;

// A mutex that can NOT be used in shared memory.
cfg_if! {
    if #[cfg(feature = "std")] {
        pub(crate) type StdMutex<T> = std::sync::Mutex<T>;
    } else {
        pub(crate) type StdMutex<T> = Mutex<T>;
    }
}

/// Releases a [`Mutex`] when dropped.
#[clippy::has_significant_drop]
#[must_use]
pub struct MutexGuard<'a, T: ?Sized> {
    lock: &'a Mutex<T>,
    /// Ensure that MutexGuard is !Send.
    _no_send: PhantomData<*const ()>,
}

#[allow(clippy::undocumented_unsafe_blocks)]
unsafe impl<T: ?Sized + Sync> Sync for MutexGuard<'_, T> {}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        // TODO(eric): it would be nice to do something about
        // `Result` here.
        let _ = self.lock.sys_unlock();
    }
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the mutex prevents data races and the value is
        // being dropped
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the mutex prevents data races and the value is
        // being dropped
        unsafe { &mut *self.lock.data.get() }
    }
}

/// A platform-specific mutex that can be used in shared memory.
///
/// - On macOS + `libc`, this uses the "ulock" API.
/// - On Linux + `libc`, this uses futexes.
/// - Elsewhere, this uses a naive spinlock.
/// 
///   The implementation is taken from the Go standard library.
#[repr(C, align(8))]
#[derive(Default, Debug)]
pub(crate) struct Mutex<T: ?Sized> {
    key: AtomicU32,
    data: UnsafeCell<T>,
}

const_assert!(size_of::<Mutex<()>>() == 8);

#[allow(clippy::undocumented_unsafe_blocks)]
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
#[allow(clippy::undocumented_unsafe_blocks)]
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    /// Creates a new, unlocked mutex.
    #[cfg_attr(
        all(feature = "memory", not(any(feature = "posix", feature = "sdlib"))),
        allow(dead_code)
    )]
    pub fn new(v: T) -> Self {
        Self {
            key: AtomicU32::new(0),
            data: UnsafeCell::new(v),
        }
    }
}

/// The result of locking a [`Mutex`].
pub type LockResult<Guard> = Result<Guard, Infallible>;

impl<T: ?Sized> Mutex<T> {
    /// The mutex is unlocked.
    const MUTEX_UNLOCKED: u32 = 0;
    /// The mutex is locked.
    const MUTEX_LOCKED: u32 = 1;
    /// The mutex is sleeping.
    #[cfg(all(
        not(feature = "cas_mutex"),
        feature = "libc",
        any(target_os = "linux", target_os = "macos")
    ))]
    const MUTEX_SLEEPING: u32 = 2;

    /// Returns the data protected by the mutex without any
    /// synchronization.
    ///
    /// # Safety
    ///
    /// You must provide your own synchronization. Otherwise,
    /// doing anything with `T` is UB.
    #[cfg(any(feature = "posix", feature = "sdlib"))]
    pub unsafe fn inner_unsynchronized(&self) -> &T {
        // SAFETY: the caller is providing their own
        // synchronization, the pointer is non-null and aligned,
        // etc.
        unsafe { &*self.data.get() }
    }

    /// Lock the mutex.
    ///
    /// The mutex will be unlocked when the result is dropped.
    #[cfg_attr(
        all(
            feature = "memory",
            feature = "std",
            not(any(feature = "posix", feature = "sdlib"))
        ),
        allow(dead_code)
    )]
    pub fn lock(&self) -> LockResult<MutexGuard<'_, T>> {
        self.sys_lock();
        Ok(MutexGuard {
            lock: self,
            _no_send: PhantomData,
        })
    }

    #[cfg(any(
        feature = "cas_mutex",
        not(feature = "libc"),
        not(any(target_os = "linux", target_os = "macos"))
    ))]
    fn sys_lock(&self) {
        loop {
            if likely!(self
                .key
                .compare_exchange(
                    Self::MUTEX_UNLOCKED,
                    Self::MUTEX_LOCKED,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok())
            {
                return;
            }
            core::hint::spin_loop();
        }
    }

    #[cfg(all(
        not(feature = "cas_mutex"),
        feature = "libc",
        any(target_os = "linux", target_os = "macos")
    ))]
    fn sys_lock(&self) {
        #[cfg(target_os = "linux")]
        use crate::mutex::linux::futex_wait;
        #[cfg(target_os = "macos")]
        use crate::mutex::macos::futex_wait;

        // Fast path: the mutex is unlocked.
        let mut wait = match self.key.compare_exchange(
            Self::MUTEX_UNLOCKED,
            Self::MUTEX_LOCKED,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => return,
            Err(v) => v,
        };

        const PASSIVE_SPIN: i32 = 5;
        loop {
            for _ in 0..PASSIVE_SPIN {
                while self.key.load(Ordering::Relaxed) == Self::MUTEX_UNLOCKED {
                    if likely!(self
                        .key
                        .compare_exchange(
                            Self::MUTEX_UNLOCKED,
                            wait,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        )
                        .is_ok())
                    {
                        return;
                    }
                    // SAFETY: FFI call, no invariants.
                    unsafe { libc::sched_yield() };
                }
            }

            // Could not grab the lock; go to sleep.
            if self.key.swap(Self::MUTEX_SLEEPING, Ordering::SeqCst) == Self::MUTEX_UNLOCKED {
                return;
            }
            wait = Self::MUTEX_SLEEPING;
            futex_wait(&self.key, Self::MUTEX_SLEEPING);
        }
    }

    #[cfg(any(
        feature = "cas_mutex",
        not(feature = "libc"),
        not(any(target_os = "linux", target_os = "macos"))
    ))]
    pub(crate) fn sys_unlock(&self) -> Result<(), Infallible> {
        self.key.swap(Self::MUTEX_UNLOCKED, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(all(
        not(feature = "cas_mutex"),
        feature = "libc",
        any(target_os = "linux", target_os = "macos")
    ))]
    pub(crate) fn sys_unlock(&self) -> Result<(), ::aranya_buggy::Bug> {
        #[cfg(target_os = "linux")]
        use crate::mutex::linux::futex_wake;
        #[cfg(target_os = "macos")]
        use crate::mutex::macos::futex_wake;

        match self.key.swap(Self::MUTEX_UNLOCKED, Ordering::SeqCst) {
            Self::MUTEX_UNLOCKED => ::aranya_buggy::bug!("unlock of locked mutex"),
            Self::MUTEX_SLEEPING => futex_wake(&self.key, 1)?,
            Self::MUTEX_LOCKED => {}
            _ => ::aranya_buggy::bug!("invalid mutex state"),
        };
        Ok(())
    }
}

#[cfg(all(not(feature = "cas_mutex"), feature = "libc", target_os = "linux"))]
mod linux {
    use core::{ptr, sync::atomic::AtomicU32};

    use aranya_buggy::{Bug, BugExt};
    use libc::{c_int, syscall, timespec, SYS_futex, FUTEX_WAIT, FUTEX_WAKE};

    use crate::errno::{errno, Errno};

    fn futex(
        uaddr: *const AtomicU32,
        futex_op: c_int,
        val: u32,
        timeout: *const timespec,
        uaddr2: *const AtomicU32,
        val3: u32,
    ) -> Result<i64, Errno> {
        // SAFETY: FFI, no invariants.
        let rc = unsafe { syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3) };
        if rc < 0 {
            Err(errno())
        } else {
            #[allow(clippy::useless_conversion)]
            Ok(i64::from(rc))
        }
    }

    pub fn futex_wait(uaddr: &AtomicU32, val: u32) {
        let _ = futex(
            uaddr as *const AtomicU32,
            FUTEX_WAIT,
            val,
            ptr::null_mut(),
            ptr::null_mut(),
            0,
        );
    }

    pub fn futex_wake(uaddr: &AtomicU32, cnt: u32) -> Result<(), Bug> {
        futex(
            uaddr as *const AtomicU32,
            FUTEX_WAKE,
            cnt,
            ptr::null_mut(),
            ptr::null_mut(),
            0,
        )
        // This should be impossible.
        .assume("futex returned <= 0")?;
        Ok(())
    }
}

#[cfg(all(not(feature = "cas_mutex"), feature = "libc", target_os = "macos"))]
mod macos {
    use core::{
        convert::Infallible,
        ffi::{c_int, c_void},
        sync::atomic::AtomicU32,
    };

    use libc::EINTR;

    extern "C" {
        fn __ulock_wait(op: u32, addr: *mut c_void, val: u64, micros: u32) -> c_int;
        fn __ulock_wake(op: u32, addr: *mut c_void, val: u64) -> c_int;
    }

    const UL_COMPARE_AND_WAIT: u32 = 1;
    const ULF_NO_ERRNO: u32 = 0x01000000;

    pub fn futex_wait(addr: &AtomicU32, val: u32) {
        loop {
            // SAFETY: FFI call, no invariants.
            let rc = unsafe {
                __ulock_wait(
                    UL_COMPARE_AND_WAIT | ULF_NO_ERRNO,
                    (addr as *const AtomicU32)
                        .cast::<u32>()
                        .cast_mut()
                        .cast::<c_void>(),
                    u64::from(val),
                    0,
                )
            };
            if rc != -EINTR {
                break;
            }
        }
    }

    pub fn futex_wake(addr: &AtomicU32, cnt: u32) -> Result<(), Infallible> {
        loop {
            // SAFETY: FFI call, no invariants.
            let rc = unsafe {
                __ulock_wake(
                    UL_COMPARE_AND_WAIT | ULF_NO_ERRNO,
                    (addr as *const AtomicU32)
                        .cast::<u32>()
                        .cast_mut()
                        .cast::<c_void>(),
                    u64::from(cnt),
                )
            };
            if rc != -EINTR {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::{
        hint::black_box,
        sync::{Arc, Barrier},
        thread,
    };

    use super::*;

    #[test]
    fn test_hammer() {
        const T: usize = 12; // threads
        const N: usize = 1000; // iters per thread

        let m = Arc::new(Mutex::new(1u128));
        let barrier = Arc::new(Barrier::new(T));
        let mut handles = Vec::with_capacity(T);
        for _ in 0..T {
            let m = Arc::clone(&m);
            let b = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                // Try and have every thread run at the same
                // time.
                b.wait();

                for _ in 0..N {
                    let mut s = black_box(m.lock().expect("should not fail"));
                    *s = s.wrapping_mul(2);
                    // It is obvious that `s` is dropped
                    // here, but for sake of the test make it
                    // explicit.
                    drop(black_box(s));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(
            *m.lock().expect("should not fail"),
            2u128.wrapping_pow((T * N) as u32)
        );
    }
}
