use std::os::raw::*;

use anyhow::Result;

use crate::seal_bindings::*;

pub struct SmallModulus {
    ptr: *mut c_void,
}

impl SmallModulus {
    pub fn create(value: u64) -> Result<SmallModulus> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Modulus_Create1(value, &mut ptr) };
        anyhow::ensure!(ret == 0, "Error creating the small modulus");
        Ok(SmallModulus { ptr })
    }

    pub fn for_batching(poly_modulus_degree: usize, bit_size: u8) -> Result<SmallModulus> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let mut bit_sizes: Vec<i32> = vec![bit_size as i32];
        let ret = unsafe {
            CoeffModulus_Create(
                poly_modulus_degree as u64,
                1,
                bit_sizes.as_mut_ptr(),
                &mut ptr,
            )
        };
        anyhow::ensure!(ret == 0, "Error creating the small modulus");
        // the first element is a SmallModulus
        Ok(SmallModulus { ptr })
    }

    pub fn value(&self) -> Result<u64> {
        let mut value: u64 = 0;
        let ret = unsafe { Modulus_Value(self.ptr, &mut value) };
        anyhow::ensure!(
            ret == 0,
            "Error extracting the value from the small modulus"
        );
        Ok(value)
    }

    #[allow(dead_code)]
    pub(crate) fn ptr(&self) -> *mut c_void {
        self.ptr
    }
}

impl Drop for SmallModulus {
    fn drop(&mut self) {
        unsafe {
            Modulus_Destroy(self.ptr);
        }
    }
}
