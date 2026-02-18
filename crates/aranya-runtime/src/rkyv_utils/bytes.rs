use rkyv::{
    Archive as _, Portable, RelPtr,
    munge::munge,
    niche::{niched_option::NichedOption, niching::Niching},
    primitive::{ArchivedUsize, FixedIsize, FixedUsize},
    rancor::Fallible,
    ser::Writer,
    with::{ArchiveWith, DefaultNiche, SerializeWith},
};

use super::Adjust;

#[derive(Portable)]
#[repr(C)]
pub struct ArchivedBytes {
    ptr: RelPtr<u8>,
    len: ArchivedUsize,
}

impl ArchivedBytes {
    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len.to_native() as usize) }
    }
}

pub struct BytesResolver {
    pos: FixedUsize,
}

pub struct Bytes;

impl ArchiveWith<&[u8]> for Bytes {
    type Archived = ArchivedBytes;

    type Resolver = BytesResolver;

    fn resolve_with(field: &&[u8], resolver: Self::Resolver, out: rkyv::Place<Self::Archived>) {
        munge!(let ArchivedBytes { ptr, len: out_len } = out);
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
impl Niching<ArchivedBytes> for DefaultNiche {
    unsafe fn is_niched(niched: *const ArchivedBytes) -> bool {
        unsafe { (*niched).len == FixedUsize::MAX }
    }

    fn resolve_niched(out: rkyv::Place<ArchivedBytes>) {
        munge!(let ArchivedBytes { ptr, len: out_len } = out);
        RelPtr::emplace(0, ptr);
        usize::resolve(&(FixedUsize::MAX as usize), (), out_len);
    }
}

unsafe impl<C> rkyv::bytecheck::CheckBytes<C> for ArchivedBytes
where
    C: Fallible + ?Sized,
{
    unsafe fn check_bytes(_value: *const Self, _context: &mut C) -> Result<(), C::Error> {
        // TODO?
        Ok(())
    }
}

unsafe impl Adjust for ArchivedBytes {
    unsafe fn adjust(&mut self, amount: FixedIsize) {
        unsafe {
            self.ptr.adjust(amount);
        }
    }
}

unsafe impl Adjust for NichedOption<ArchivedBytes, DefaultNiche> {
    unsafe fn adjust(&mut self, amount: FixedIsize) {
        if let Some(bytes) = self.as_mut() {
            unsafe {
                bytes.adjust(amount);
            }
        }
    }
}
