use core::{
    alloc::{Layout, LayoutError},
    cell::UnsafeCell,
    fmt::{self, Debug},
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicU32, Ordering},
};

use derive_where::derive_where;

use crate::util::layout_error;

#[repr(transparent)]
#[derive(Debug)]
pub struct Arena<T>(ArenaInner<[Node<T>]>);

#[repr(C)]
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Index {
    pub index: u32,
    pub generation: u32,
}

#[repr(C)]
pub struct ArenaInner<S: ?Sized> {
    // TODO: remove write lock?
    write_lock: AtomicU32,
    // free: UnsafeCell<u32>,
    // live: UnsafeCell<u32>,
    slots: S,
}

impl<S: Debug + ?Sized> Debug for ArenaInner<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArenaInner")
            .field("write_loc", &self.write_lock)
            // .field("free", unsafe { &*self.free.get() })
            // .field("live", unsafe { &*self.live.get() })
            .field("slots", &&self.slots)
            .finish()
    }
}

#[repr(C)]
struct Node<T> {
    state: AtomicU32,
    // protected by node state lock
    data: UnsafeCell<Data<T>>,
    // protected by arena write lock
    // prev: UnsafeCell<u32>,
}

impl<T> Debug for Node<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("state", &self.state)
            .field("data", unsafe { &*self.data.get() })
            // .field("prev", unsafe { &*self.prev.get() })
            .finish()
    }
}

#[repr(C)]
#[derive_where(Debug)]
struct Data<T> {
    generation: u32,
    // next: u32,
    item: MaybeUninit<T>,
}

const STATE_UNINIT: u32 = 0;
const STATE_INIT_UNLOCKED: u32 = 1;
const STATE_LOCKED: u32 = 2;

#[derive(Debug)]
pub enum Error {
    WouldBlock,
    OutOfSpace,
    NotFound,
    WrongGeneration,
}

impl<T> Arena<T> {
    pub fn layout(len: u32) -> Result<Layout, LayoutError> {
        if len == u32::MAX {
            return Err(layout_error());
        }
        Ok(Layout::new::<ArenaInner<()>>()
            .extend(Layout::array::<Node<T>>(len as usize)?)?
            .0
            .pad_to_align())
    }

    #[cfg(feature = "alloc")]
    pub fn boxed(len: u32) -> Box<Self> {
        let layout = Self::layout(len).expect("could not create layout for arena");
        unsafe {
            let ptr = alloc::alloc::alloc(layout);
            let ptr = Self::init(ptr, len);
            Box::from_raw(ptr)
        }
    }

    pub unsafe fn init(ptr: *mut u8, len: u32) -> *mut Self {
        unsafe {
            let ptr = core::ptr::slice_from_raw_parts_mut(ptr, len as usize)
                as *mut ArenaInner<[MaybeUninit<Node<T>>]>;
            (*ptr).write_lock = AtomicU32::new(0);
            // (*ptr).free = UnsafeCell::new(0);
            // (*ptr).live = UnsafeCell::new(u32::MAX);
            for (i, node) in (*ptr).slots.iter_mut().enumerate() {
                let i = i as u32;
                node.write(Node {
                    state: AtomicU32::new(STATE_UNINIT),
                    data: UnsafeCell::new(Data {
                        generation: 0,
                        // next: i + 1 % len,
                        item: MaybeUninit::uninit(),
                    }),
                    // prev: UnsafeCell::new(u32::MAX),
                });
            }
            ptr as _
        }
    }

    pub fn add(&self, item: T) -> Result<Index, Error> {
        self.0
            .write_lock
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .map_err(|_| Error::WouldBlock)?;

        // let index = unsafe { *self.0.free.get() };
        // if index == u32::MAX {
        //     self.0.write_lock.store(0, Ordering::Release);
        //     return Err(Error::OutOfSpace);
        // }
        let index = self
            .0
            .slots
            .iter()
            .position(|slot| slot.state.load(Ordering::Acquire) == STATE_UNINIT)
            .ok_or(Error::OutOfSpace)? as u32;

        let slot = &self.0.slots[index as usize];
        debug_assert_eq!(slot.state.load(Ordering::Acquire), STATE_UNINIT);
        let data = unsafe { &mut *slot.data.get() };
        data.item.write(item);
        let generation = data.generation;

        // unsafe {
        //     (*self.0.free.get()) = data.next;
        //     data.next = *self.0.live.get();
        //     (*self.0.live.get()) = index;
        //     if data.next != u32::MAX {
        //         let next_node = &self.0.slots[data.next as usize];
        //         *next_node.prev.get() = index;
        //     }
        //     let prev = *slot.prev.get();
        //     if prev != u32::MAX {
        //         let prev_node = &self.0.slots[prev as usize];
        //         (*prev_node.data.get()).next = index;
        //     }
        // }

        slot.state.store(STATE_INIT_UNLOCKED, Ordering::Release);

        self.0.write_lock.store(0, Ordering::Release);

        Ok(Index { index, generation })
    }

    pub fn get(&self, idx: Index) -> Option<NodeGuard<'_, T>> {
        let node = self.0.slots.get(idx.index as usize)?;
        node.state
            .compare_exchange(
                STATE_INIT_UNLOCKED,
                STATE_LOCKED,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .ok()?;
        if unsafe { (*node.data.get()).generation } != idx.generation {
            node.state.store(STATE_INIT_UNLOCKED, Ordering::Release);
            return None;
        }
        Some(NodeGuard { node })
    }

    pub fn remove(&self, idx: Index) -> Result<(), Error> {
        let node = self
            .0
            .slots
            .get(idx.index as usize)
            .ok_or(Error::NotFound)?;
        self.0
            .write_lock
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .map_err(|_| Error::WouldBlock)?;
        node.state
            .compare_exchange(
                STATE_INIT_UNLOCKED,
                STATE_UNINIT,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .map_err(|_| {
                self.0.write_lock.store(0, Ordering::Release);
                Error::WouldBlock
            })?;
        let data = unsafe { &mut *node.data.get() };
        // TODO: load generation before locking?
        if data.generation != idx.generation {
            self.0.write_lock.store(0, Ordering::Release);
            node.state.store(STATE_INIT_UNLOCKED, Ordering::Release);
            return Err(Error::WrongGeneration);
        }
        unsafe {
            data.item.assume_init_drop();
        }
        data.generation += 1;

        // unsafe {
        //     *node.prev.get() = u32::MAX;
        // }

        // {
        //     // TODO: is one of these unnecessary?
        //     let prev = unsafe { *node.prev.get() };
        //     if prev != u32::MAX {
        //         let prev_node = &self.0.slots[prev as usize];
        //         // TODO: Is this safe?
        //         unsafe {
        //             (*prev_node.data.get()).next = data.next;
        //         }
        //     }
        //     let next = data.next;
        //     if next != u32::MAX {
        //         let next_node = &self.0.slots[next as usize];
        //         // TODO: Is this safe?
        //         unsafe {
        //             (*next_node.prev.get()) = *node.prev.get();
        //         }
        //     }
        // }

        // let free = unsafe { &mut *self.0.free.get() };
        // data.next = *free;
        // *free = idx.index;

        self.0.write_lock.store(0, Ordering::Release);

        Ok(())
    }

    pub fn clear(&self) -> Result<(), Error> {
        self.retain(|_, _| false)
    }

    pub fn retain(&self, mut keep: impl FnMut(Index, &T) -> bool) -> Result<(), Error> {
        self.0
            .write_lock
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .map_err(|_| Error::WouldBlock)?;
        for (i, slot) in self.0.slots.iter().enumerate() {
            if slot.state.load(Ordering::Acquire) == STATE_UNINIT {
                continue;
            }
            let data = unsafe { &mut *slot.data.get() };
            if !keep(
                Index {
                    index: i as u32,
                    generation: data.generation,
                },
                unsafe { data.item.assume_init_ref() },
            ) {
                while {
                    slot.state
                        .compare_exchange(
                            STATE_INIT_UNLOCKED,
                            STATE_UNINIT,
                            Ordering::AcqRel,
                            Ordering::Relaxed,
                        )
                        .is_err()
                } {
                    core::hint::spin_loop();
                }
                unsafe {
                    data.item.assume_init_drop();
                }
                data.generation += 1;
            }
        }

        // let free = unsafe { &mut *self.0.free.get() };
        // let mut prev = unsafe { &mut *self.0.live.get() };
        // let mut current = *prev;
        // while current != u32::MAX {
        //     let slot = &self.0.slots[current as usize];
        //     debug_assert_ne!(
        //         slot.state.load(Ordering::Acquire),
        //         STATE_UNINIT,
        //         "{current} {:#?}",
        //         &self.0.slots
        //     );
        //     let data = unsafe { &mut *slot.data.get() };
        //     let next = data.next;
        //     if !keep(
        //         Index {
        //             index: current,
        //             generation: data.generation,
        //         },
        //         unsafe { data.item.assume_init_ref() },
        //     ) {
        //         while {
        //             slot.state
        //                 .compare_exchange(
        //                     STATE_INIT_UNLOCKED,
        //                     STATE_UNINIT,
        //                     Ordering::AcqRel,
        //                     Ordering::Relaxed,
        //                 )
        //                 .is_err()
        //         } {
        //             core::hint::spin_loop();
        //         }
        //         unsafe {
        //             data.item.assume_init_drop();
        //         }
        //         unsafe {
        //             *slot.prev.get() = u32::MAX;
        //         }
        //         data.generation += 1;
        //         data.next = *free;
        //         *prev = next;
        //         *free = current;
        //     }
        //     prev = &mut data.next;
        //     current = next;
        // }
        self.0.write_lock.store(0, Ordering::Release);
        Ok(())
    }

    pub fn from_parts(ptr: *const u8, len: u32) -> *const Self {
        core::ptr::slice_from_raw_parts(ptr, len as usize) as *const Self
    }
}

impl<T> Drop for Arena<T> {
    fn drop(&mut self) {
        self.clear().ok();
    }
}

// Invariant: node has initialized and locked state.
pub struct NodeGuard<'a, T> {
    node: &'a Node<T>,
}

impl<T> Deref for NodeGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { (*self.node.data.get()).item.assume_init_ref() }
    }
}

impl<T> DerefMut for NodeGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { (*self.node.data.get()).item.assume_init_mut() }
    }
}

impl<T> Drop for NodeGuard<'_, T> {
    fn drop(&mut self) {
        self.node
            .state
            .store(STATE_INIT_UNLOCKED, Ordering::Release);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_simple() {
        let arena = Arena::<String>::boxed(10);
        let i0 = arena.add(String::from("first")).unwrap();
        let i1 = arena.add(String::from("second")).unwrap();
        let i2 = arena.add(String::from("third")).unwrap();
        assert_eq!(arena.get(i0).unwrap().as_str(), "first");
        assert_eq!(arena.get(i1).unwrap().as_str(), "second");
        assert_eq!(arena.get(i2).unwrap().as_str(), "third");
        // dbg!(&arena);
        assert!(
            arena
                .get(Index {
                    index: 3,
                    generation: 0
                })
                .is_none()
        );
        arena.remove(i1).unwrap();
        dbg!(&arena);
        assert!(arena.get(i1).is_none());
        let i4 = arena.add(String::from("fourth")).unwrap();
        dbg!(&arena);
        assert_eq!(i4.index, 1);
        assert_eq!(i4.generation, 1);
        arena.clear();
        // arena.clear();
        // arena.clear();
    }
}
