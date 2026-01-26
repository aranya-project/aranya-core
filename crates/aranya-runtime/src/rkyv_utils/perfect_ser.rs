use core::marker::PhantomData;

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
    buf: LentBuf<'a>,
    /// The original end of the slice.
    og_end: *mut u8,
    _ph: PhantomData<&'a mut [A]>,
}

impl<'data, A> PerfectSer<'data, A> {
    const VEC_SIZE: usize = size_of::<ArchivedVec<A>>();
    const ITEM_SIZE: usize = size_of::<A>();

    pub fn new(slice: &'data mut [u8], written: &'data mut usize) -> Result<Self, BufferOverflow> {
        // TODO: align here?
        // SAFETY: The end of the slice must be a valid pointer.
        let og_end = unsafe { slice.as_mut_ptr().add(slice.len()) };
        let slice = slice
            .get_mut(
                *written
                    ..slice
                        .len()
                        .checked_sub(Self::VEC_SIZE)
                        .ok_or(BufferOverflow)?,
            )
            .ok_or(BufferOverflow)?;
        Ok(PerfectSer {
            buf: LentBuf { slice, written },
            og_end,
            _ph: PhantomData,
        })
    }
}

impl<'data, A: Adjust> PerfectSer<'data, A> {
    pub fn push<T>(&mut self, item: &T) -> Result<(), BufferOverflow>
    where
        T: for<'a> Serialize<LentBuf<'a>> + Archive<Archived = A>,
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

        let start_pos = *self.buf.written;

        let empty_start = self.buf.slice.as_mut_ptr();
        let item_meta_start = unsafe { empty_start.add(self.buf.slice.len()) };
        let vec_meta_start = unsafe { self.og_end.sub(Self::VEC_SIZE) };

        let item_meta_len = unsafe { vec_meta_start.offset_from(item_meta_start) as usize };
        // Number of items written
        let count = item_meta_len / Self::ITEM_SIZE;
        debug_assert_eq!(item_meta_len % Self::ITEM_SIZE, 0);

        // Shift and reverse.
        let (align_offset, new_vec_start) = Self::adjust(
            unsafe {
                core::slice::from_raw_parts_mut(
                    empty_start,
                    vec_meta_start.offset_from(empty_start) as usize,
                )
            },
            self.buf.slice.len(),
        )?;

        let out = unsafe {
            Place::new_unchecked(
                start_pos + new_vec_start.offset_from(empty_start) as usize,
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

        *self.buf.written +=
            unsafe { new_vec_start.offset_from(empty_start) } as usize + Self::VEC_SIZE;

        Ok(())
    }

    fn reserve_item(&mut self) -> Result<Reserve<'data>, BufferOverflow> {
        let end = self
            .buf
            .slice
            .len()
            .checked_sub(Self::ITEM_SIZE)
            .ok_or(BufferOverflow)?;
        let slice = self.buf.slice.split_off_mut(end..).ok_or(BufferOverflow)?;
        Ok(Reserve {
            slice,
            pos: *self.buf.written + end,
        })
    }

    unsafe fn unreserve_item(&mut self) {
        unsafe {
            self.buf.slice = core::slice::from_raw_parts_mut(
                self.buf.slice.as_mut_ptr(),
                self.buf.slice.len() + Self::ITEM_SIZE,
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
            let offset = start as isize + delta_index * Self::ITEM_SIZE as isize;
            let offset = offset.try_into().assume("offset is valid i32")?;
            unsafe {
                item.adjust(offset);
            }
        }

        Ok((align_offset, new_end))
    }
}

struct Reserve<'a> {
    slice: &'a mut [u8],
    pos: usize,
}

impl rkyv::rancor::Fallible for Reserve<'_> {
    type Error = BufferOverflow;
}

impl rkyv::ser::Positional for Reserve<'_> {
    fn pos(&self) -> usize {
        self.pos
    }
}

impl rkyv::ser::Writer for Reserve<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), <Self as rkyv::rancor::Fallible>::Error> {
        self.slice
            .split_off_mut(..bytes.len())
            .ok_or(BufferOverflow)?
            .copy_from_slice(bytes);
        self.pos += bytes.len();
        assert_eq!(self.slice.len(), 0);
        Ok(())
    }
}

pub struct LentBuf<'a> {
    /// Unwritten data.
    slice: &'a mut [u8],
    /// Updated with amount written but not an index into slice.
    written: &'a mut usize,
}

impl rkyv::rancor::Fallible for LentBuf<'_> {
    type Error = BufferOverflow;
}

impl rkyv::ser::Positional for LentBuf<'_> {
    fn pos(&self) -> usize {
        *self.written
    }
}

impl rkyv::ser::Writer for LentBuf<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), <Self as rkyv::rancor::Fallible>::Error> {
        self.slice
            .split_off_mut(..bytes.len())
            .ok_or(BufferOverflow)?
            .copy_from_slice(bytes);
        *self.written += bytes.len();
        Ok(())
    }
}
