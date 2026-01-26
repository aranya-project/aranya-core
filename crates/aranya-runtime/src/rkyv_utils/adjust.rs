use rkyv::{
    RelPtr,
    primitive::{ArchivedIsize, FixedIsize},
};

/// Adjust rkyv's relative pointers by a given amount.
///
/// # Safety
///
/// `self` must be valid after being moved `amount` bytes and then calling `adjust(amount)`.
/// (This implicitly requires to be able to add `amount` without overflow.)
pub unsafe trait Adjust {
    unsafe fn adjust(&mut self, amount: FixedIsize);
}

unsafe impl Adjust for RelPtr<u8> {
    unsafe fn adjust(&mut self, amount: FixedIsize) {
        let offset = unsafe {
            core::ptr::NonNull::from_mut(self)
                .cast::<ArchivedIsize>()
                .as_mut()
        };
        *offset = ArchivedIsize::from_native(unsafe { offset.to_native().unchecked_add(amount) });
    }
}
