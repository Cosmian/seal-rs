use std::os::raw::*;

use anyhow::Result;

use crate::{context::Context, plain_text::Plaintext, seal_bindings::*};

pub struct BatchEncoder {
    ptr: *mut c_void,
}

impl BatchEncoder {
    /// Batching is done through an instance of the BatchEncoder class.
    pub fn create(context: &Context) -> Result<BatchEncoder> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { BatchEncoder_Create(context.ptr(), &mut ptr) };
        anyhow::ensure!(ret == 0, "Error creating the batch encoder");
        Ok(BatchEncoder { ptr })
    }

    /// The number of slots.
    /// Each slot contains an integer modulo plain_modulus
    pub fn slot_count(&self) -> Result<usize> {
        let mut value: u64 = 0;
        let ret = unsafe { BatchEncoder_GetSlotCount(self.ptr, &mut value) };
        anyhow::ensure!(ret == 0, "Error extracting the slot count");
        Ok(value as usize)
    }

    /// Encode the values on a plaintext polynomial
    /// The number of values must not exceed the number of slots
    pub fn encode(&self, values: &mut [u64]) -> Result<Plaintext> {
        let plain_text = Plaintext::create()?;
        let ret = unsafe {
            BatchEncoder_Encode1(
                self.ptr,
                values.len() as u64,
                values.as_mut_ptr(),
                plain_text.ptr(),
            )
        };
        anyhow::ensure!(ret == 0, "Error encoding the batch");
        Ok(plain_text)
    }

    /// Decode the values from a plaintext polynomial
    pub fn decode(&self, plain_text: &Plaintext) -> Result<Vec<u64>> {
        let mut decoded: Vec<u64> = vec![0; self.slot_count()?];
        let mut count: u64 = decoded.len() as u64;
        let mut mem_pool_ptr: *mut c_void = std::ptr::null_mut();
        // this call creates a new object which is
        // managed through a unique_ptr in the create call
        let ret = unsafe { Plaintext_Pool(plain_text.ptr(), &mut mem_pool_ptr) };
        anyhow::ensure!(ret == 0, "Error fetching the plain text memory pool");
        let ret = unsafe {
            BatchEncoder_Decode1(
                self.ptr,
                plain_text.ptr(),
                &mut count,
                decoded.as_mut_ptr(),
                mem_pool_ptr,
            )
        };
        anyhow::ensure!(ret == 0, "Error decoding the batch");
        Ok(decoded)
    }

    #[allow(dead_code)]
    pub(crate) fn ptr(&self) -> *mut c_void {
        self.ptr
    }

    // pub fn decrypt(&self, cipher_text: &Ciphertext) -> Result<Plaintext> {
    //     let pt = Plaintext::create_in_pool_of_cipher_text(&cipher_text)?;
    //     let res = unsafe { BatchEncoder_Decrypt(self.ptr, cipher_text.ptr(),
    // pt.ptr()) };     anyhow::ensure!(ret == 0, "Error decrypting");
    //     Ok(pt)
    // }
}

impl Drop for BatchEncoder {
    fn drop(&mut self) {
        unsafe {
            BatchEncoder_Destroy(self.ptr);
        }
    }
}
