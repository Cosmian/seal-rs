use std::os::raw::*;

use anyhow::Result;

use crate::{context::Context, plain_text::Plaintext, seal_bindings::*};

pub struct CKKSEncoder {
    ptr: *mut c_void,
    parms_id: Vec<u64>,
}

impl CKKSEncoder {
    /// Batching is done through an instance of the CKKSEncoder class.
    pub fn create(context: &Context) -> Result<CKKSEncoder> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { CKKSEncoder_Create(context.ptr(), &mut ptr) };
        anyhow::ensure!(ret == 0, "Error creating the CKKS encoder");
        Ok(CKKSEncoder {
            ptr,
            parms_id: context.first_parms_id()?,
        })
    }

    /// The number of slots.
    /// Each slot contains an integer modulo plain_modulus
    pub fn slot_count(&self) -> Result<usize> {
        let mut value: u64 = 0;
        let ret = unsafe { CKKSEncoder_SlotCount(self.ptr, &mut value) };
        anyhow::ensure!(ret == 0, "Error extracting the slot count");
        Ok(value as usize)
    }

    /// Encode the value on a plaintext polynomial
    pub fn encode(&mut self, values: &mut [f64], scale: &f64) -> Result<Plaintext> {
        let plain_text = Plaintext::create()?;
        let mut mem_pool_ptr: *mut c_void = std::ptr::null_mut();
        // this call creates a new object which is
        // managed through a unique_ptr in the create call
        let ret = unsafe { Plaintext_Pool(plain_text.ptr(), &mut mem_pool_ptr) };
        anyhow::ensure!(ret == 0, "Error fetching the plain text memory pool");
        let ret = unsafe {
            CKKSEncoder_Encode1(
                self.ptr,
                values.len() as u64,
                values.as_mut_ptr(),
                self.parms_id.as_mut_ptr(),
                *scale,
                plain_text.ptr(),
                mem_pool_ptr,
            )
        };
        anyhow::ensure!(ret == 0, "Error encoding values with the CKKS encoder");
        Ok(plain_text)
    }

    /// Encode the value on a plaintext polynomial
    pub fn encode_value(&mut self, value: &f64, scale: &f64) -> Result<Plaintext> {
        let plain_text = Plaintext::create()?;
        let mut mem_pool_ptr: *mut c_void = std::ptr::null_mut();
        // this call creates a new object which is
        // managed through a unique_pt in the create call
        let ret = unsafe { Plaintext_Pool(plain_text.ptr(), &mut mem_pool_ptr) };
        anyhow::ensure!(ret == 0, "Error fetching the plain text memory pool");
        let ret = unsafe {
            CKKSEncoder_Encode3(
                self.ptr,
                *value,
                self.parms_id.as_mut_ptr(),
                *scale,
                plain_text.ptr(),
                mem_pool_ptr,
            )
        };
        anyhow::ensure!(ret == 0, "Error encoding value with the CKKS encoder");
        Ok(plain_text)
    }

    /// Decode the values from a plaintext polynomial
    pub fn decode(&self, plain_text: &Plaintext) -> Result<Vec<f64>> {
        let mut decoded: Vec<f64> = vec![0.0; self.slot_count()?];
        let mut count: u64 = decoded.len() as u64;
        let mut mem_pool_ptr: *mut c_void = std::ptr::null_mut();
        // this call creates a new object which is
        // managed through a unique_pt in the create call
        let ret = unsafe { Plaintext_Pool(plain_text.ptr(), &mut mem_pool_ptr) };
        anyhow::ensure!(ret == 0, "Error fetching the plain text memory pool");
        let ret = unsafe {
            CKKSEncoder_Decode1(
                self.ptr,
                plain_text.ptr(),
                &mut count,
                decoded.as_mut_ptr(),
                mem_pool_ptr,
            )
        };
        anyhow::ensure!(ret == 0, "Error decoding the CKKS encoder");
        Ok(decoded)
    }
}

impl Drop for CKKSEncoder {
    fn drop(&mut self) {
        unsafe {
            CKKSEncoder_Destroy(self.ptr);
        }
    }
}
