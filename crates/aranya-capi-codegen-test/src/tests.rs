#![cfg(test)]

use std::mem::MaybeUninit;

use crate::defs::ExtError;

#[test]
fn test_list_opaque() {
    const N: usize = 100;
    let mut list = [ const { MaybeUninit::uninit() }; N];

    fn helper(errors_out: *mut MaybeUninit<ExtError>, errors_len: &mut usize) -> Result<(), crate::Error> {
        let errors = vec![crate::ExtError::new(crate::Error::BufferTooSmall)];

        if *errors_len < errors.len() {
            *errors_len = errors.len();
            panic!("buffer too small");
        }
        let out = aranya_capi_core::try_as_mut_slice!(errors_out, *errors_len);
        
        *errors_len = errors.len();
        for (dst, src) in out.iter_mut().zip(errors) {
            ExtError::init(dst, src);
        }

        Ok(())
    }

    let mut len = list.len();
    helper(list.as_mut_ptr(), &mut len).expect("is successful");
}