use core::{marker::PhantomData, num::NonZeroUsize};

use buggy::{Bug, BugExt as _};
use rkyv::{
    Archive, Place, Serialize,
    ser::WriterExt as _,
    vec::{ArchivedVec, VecResolver},
};

use super::Adjust;

pub struct BufferOverflow;

/// Serializes items one at a time into a buffer.
pub struct PerfectSer<'a, A> {
    // Updated after finish.
    written: &'a mut usize,
    // Working buffer.
    buf: Buffer<'a>,
    /// The original end of the slice.
    og_end: *mut u8,
    _ph: PhantomData<&'a mut [A]>,
}

impl<'data, A> PerfectSer<'data, A> {
    /// Size of vec metadata
    const VEC_SIZE: NonZeroUsize = NonZeroUsize::new(size_of::<ArchivedVec<A>>()).unwrap();
    /// Size of item metadata
    const ITEM_SIZE: NonZeroUsize = NonZeroUsize::new(size_of::<A>()).unwrap();

    pub fn new(
        mut slice: &'data mut [u8],
        written: &'data mut usize,
    ) -> Result<Self, BufferOverflow> {
        let pos = *written;
        shrink_align(&mut slice, align_of::<ArchivedVec<A>>())?;

        // SAFETY: The end of the slice must be a valid pointer.
        let og_end = unsafe { slice.as_mut_ptr().add(slice.len()) };

        shrink(&mut slice, Self::VEC_SIZE.get())?;
        let slice = &mut slice[pos..];
        Ok(PerfectSer {
            written,
            buf: Buffer { slice, pos },
            og_end,
            _ph: PhantomData,
        })
    }
}

impl<'data, A: Adjust> PerfectSer<'data, A> {
    pub fn push<T>(&mut self, item: &T) -> Result<(), BufferOverflow>
    where
        T: for<'a> Serialize<Buffer<'a>> + Archive<Archived = A>,
    {
        let before = (self.buf.slice.as_ptr(), self.buf.slice.len());
        let mut reserve = self.reserve_item()?;
        let resolver = match item.serialize(&mut self.buf) {
            Ok(r) => r,
            Err(BufferOverflow) => {
                // TODO: hacky
                unsafe {
                    self.unreserve_item();
                }
                let after = (self.buf.slice.as_ptr(), self.buf.slice.len());
                debug_assert_eq!(before, after);
                return Err(BufferOverflow);
            }
        };
        unsafe {
            reserve.resolve_aligned(item, resolver).inspect_err(|_| {
                let after = (self.buf.slice.as_ptr(), self.buf.slice.len());
                debug_assert_eq!(before, after);
            })?;
        }
        Ok(())
    }

    pub fn finish(self) -> Result<(), Bug> {
        // [extra] [empty] [item meta] [vec meta]
        //                                      ^ OG end
        //                             ^--------^ len VEC_SIZE
        //         ^------^ lent buf slice
        //         ^ start_pos

        let start_pos = self.buf.pos;

        let empty_start = self.buf.slice.as_mut_ptr();
        let item_meta_start = unsafe { empty_start.add(self.buf.slice.len()) };
        let vec_meta_start = unsafe { self.og_end.sub(Self::VEC_SIZE.get()) };

        let item_meta_len = unsafe { vec_meta_start.offset_from_unsigned(item_meta_start) };
        // Number of items written
        let count = item_meta_len / Self::ITEM_SIZE;
        debug_assert_eq!(item_meta_len % Self::ITEM_SIZE, 0);

        // Shift and reverse.
        let (align_offset, new_vec_start) = Self::adjust(
            unsafe {
                core::slice::from_raw_parts_mut(
                    empty_start,
                    vec_meta_start.offset_from_unsigned(empty_start),
                )
            },
            self.buf.slice.len(),
        )?;

        let out = unsafe {
            Place::new_unchecked(
                start_pos + new_vec_start.offset_from_unsigned(empty_start),
                new_vec_start,
            )
            .cast_unchecked::<ArchivedVec<A>>()
        };
        debug_assert!(unsafe { out.ptr() }.is_aligned());
        ArchivedVec::<A>::resolve_from_len(
            count,
            VecResolver::from_pos(start_pos + align_offset),
            out,
        );

        *self.written = start_pos
            + unsafe { new_vec_start.offset_from(empty_start) } as usize
            + Self::VEC_SIZE.get();

        Ok(())
    }

    fn reserve_item(&mut self) -> Result<Buffer<'data>, BufferOverflow> {
        self.buf.split(Self::ITEM_SIZE.get())
    }

    unsafe fn unreserve_item(&mut self) {
        unsafe {
            self.buf.slice = core::slice::from_raw_parts_mut(
                self.buf.slice.as_mut_ptr(),
                self.buf.slice.len() + Self::ITEM_SIZE.get(),
            );
        }
    }

    /// Shift, reverse, and update archived items.
    fn adjust(slice: &mut [u8], start: usize) -> Result<(usize, *mut u8), Bug> {
        let align_offset = slice.as_ptr().align_offset(align_of::<A>());
        let slice = &mut slice[align_offset..];
        let start = start - align_offset;

        // Shift
        slice.copy_within(start.., 0);

        // re-slice to contain just the items
        let len = slice.len() - start;
        let slice = &mut slice[..len];
        let new_end = unsafe { slice.as_mut_ptr().add(len) };

        let items = unsafe {
            core::slice::from_raw_parts_mut(
                slice.as_mut_ptr().cast::<A>(),
                slice.len() / Self::ITEM_SIZE,
            )
        };

        // reverse the items
        items.reverse();

        let count = items.len() as isize;

        for (i, item) in items.iter_mut().enumerate() {
            let i = i as isize;
            let delta_index = count - 1 - i - i;
            let offset = start as isize + delta_index * Self::ITEM_SIZE.get() as isize;
            let offset = offset.try_into().assume("offset is valid i32")?;
            unsafe {
                item.adjust(offset);
            }
        }

        Ok((align_offset, new_end))
    }
}

pub struct Buffer<'a> {
    /// Unwritten data.
    slice: &'a mut [u8],
    /// Position in stream.
    pos: usize,
}

impl Buffer<'_> {
    /// Split off another buffer from the end
    fn split(&mut self, size: usize) -> Result<Self, BufferOverflow> {
        let slice = shrink(&mut self.slice, size)?;
        let pos = self.pos + self.slice.len();
        Ok(Buffer { slice, pos })
    }
}

impl rkyv::rancor::Fallible for Buffer<'_> {
    type Error = BufferOverflow;
}

impl rkyv::ser::Positional for Buffer<'_> {
    fn pos(&self) -> usize {
        self.pos
    }
}

impl rkyv::ser::Writer for Buffer<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), <Self as rkyv::rancor::Fallible>::Error> {
        self.slice
            .split_off_mut(..bytes.len())
            .ok_or(BufferOverflow)?
            .copy_from_slice(bytes);
        self.pos += bytes.len();
        Ok(())
    }
}

fn shrink_align(xs: &mut &mut [u8], align: usize) -> Result<(), BufferOverflow> {
    let offset = unsafe { xs.as_ptr().add(xs.len()) }.align_offset(align);
    if offset != 0 {
        shrink(xs, align - offset)?;
    }
    Ok(())
}

fn shrink<'a>(xs: &mut &'a mut [u8], amount: usize) -> Result<&'a mut [u8], BufferOverflow> {
    let new_end = xs.len().checked_sub(amount).ok_or(BufferOverflow)?;
    xs.split_off_mut(new_end..).ok_or(BufferOverflow)
}
