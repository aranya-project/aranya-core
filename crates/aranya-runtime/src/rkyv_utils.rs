use core::marker::PhantomData;

use rkyv::{
    Archive as _, Portable, RelPtr,
    munge::munge,
    niche::{niched_option::NichedOption, niching::Niching},
    primitive::{ArchivedIsize, ArchivedUsize, FixedIsize, FixedUsize},
    rancor::Fallible,
    ser::Writer,
    with::{ArchiveWith, DefaultNiche, SerializeWith},
};

#[derive(Copy, Clone, Debug, thiserror::Error)]
#[error("overflow during adjustment")]
pub struct AdjustOverflow;

/// Adjust rkyv's relative pointers by a given amount.
///
/// # Safety
///
/// `self` must be valid after being moved  `amount` bytes and then calling `adjust(amount)`.
pub unsafe trait Adjust {
    unsafe fn adjust(&mut self, amount: FixedIsize) -> Result<(), AdjustOverflow>;
}

unsafe impl Adjust for RelPtr<u8> {
    unsafe fn adjust(&mut self, amount: FixedIsize) -> Result<(), AdjustOverflow> {
        let offset = unsafe {
            core::ptr::NonNull::from_mut(self)
                .cast::<ArchivedIsize>()
                .as_mut()
        };
        *offset = ArchivedIsize::from_native(
            offset
                .to_native()
                .checked_add(amount)
                .ok_or(AdjustOverflow)?,
        );
        Ok(())
    }
}

unsafe impl Adjust for ArchivedBytes<'_> {
    unsafe fn adjust(&mut self, amount: FixedIsize) -> Result<(), AdjustOverflow> {
        unsafe { self.ptr.adjust(amount) }
    }
}

unsafe impl Adjust for NichedOption<ArchivedBytes<'_>, DefaultNiche> {
    unsafe fn adjust(&mut self, amount: FixedIsize) -> Result<(), AdjustOverflow> {
        if let Some(bytes) = self.as_mut() {
            unsafe { bytes.adjust(amount) }
        } else {
            Ok(())
        }
    }
}

#[derive(Portable)]
#[repr(C)]
pub struct ArchivedBytes<'a> {
    ptr: RelPtr<u8>,
    len: ArchivedUsize,
    _ph: PhantomData<&'a [u8]>,
}

impl<'a> ArchivedBytes<'a> {
    pub fn as_slice(&self) -> &'a [u8] {
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len.to_native() as usize) }
    }
}

pub struct BytesResolver {
    pos: FixedUsize,
}

pub struct Bytes;

impl<'a> ArchiveWith<&'a [u8]> for Bytes {
    type Archived = ArchivedBytes<'a>;

    type Resolver = BytesResolver;

    fn resolve_with(field: &&[u8], resolver: Self::Resolver, out: rkyv::Place<Self::Archived>) {
        munge!(let ArchivedBytes { ptr, len: out_len, _ph } = out);
        RelPtr::emplace(resolver.pos as usize, ptr);
        usize::resolve(&field.len(), (), out_len);
    }
}

impl<S> SerializeWith<&[u8], S> for Bytes
where
    S: Fallible + Writer + ?Sized,
{
    fn serialize_with(field: &&[u8], serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        let pos = serializer.pos();
        serializer.write(field)?;
        Ok(BytesResolver {
            pos: pos as FixedUsize,
        })
    }
}

// TODO: Need to make sure length can't be max value?
impl Niching<ArchivedBytes<'_>> for DefaultNiche {
    unsafe fn is_niched(niched: *const ArchivedBytes<'_>) -> bool {
        unsafe { (*niched).len == FixedUsize::MAX }
    }

    fn resolve_niched(out: rkyv::Place<ArchivedBytes<'_>>) {
        munge!(let ArchivedBytes { ptr, len: out_len ,_ph} = out);
        RelPtr::emplace(0, ptr);
        usize::resolve(&(FixedUsize::MAX as usize), (), out_len);
    }
}

unsafe impl<C> rkyv::bytecheck::CheckBytes<C> for ArchivedBytes<'_>
where
    C: Fallible + ?Sized,
{
    unsafe fn check_bytes(_value: *const Self, _context: &mut C) -> Result<(), C::Error> {
        // TODO?
        Ok(())
    }
}
