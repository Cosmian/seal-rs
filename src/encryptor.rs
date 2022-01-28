use std::os::raw::*;

use anyhow::Result;

use crate::{
    cipher_text::Ciphertext,
    context::Context,
    key_generator::{PublicKey, SecretKey},
    plain_text::Plaintext,
    seal_bindings::*,
};

pub struct Encryptor {
    ptr: *mut ::std::os::raw::c_void,
}

impl Encryptor {
    pub fn create(
        context: &Context,
        public_key: &PublicKey,
        secret_key: &SecretKey,
    ) -> Result<Encryptor> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe {
            Encryptor_Create(context.ptr(), public_key.ptr(), secret_key.ptr(), &mut ptr)
        };
        anyhow::ensure!(ret == 0, "Error creating the encryptor");
        Ok(Encryptor { ptr })
    }

    pub fn encrypt(
        &self,
        plain_text: &Plaintext,
        // memory_pool_handle: &MemoryPool,
    ) -> Result<Ciphertext> {
        let ct = Ciphertext::create_in_pool_of_plain_text(plain_text)?;
        let mut mem_pool_ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Ciphertext_Pool(ct.ptr(), &mut mem_pool_ptr) };
        anyhow::ensure!(ret == 0, "Error fetching the cipher text memory pool");
        let ret = unsafe { Encryptor_Encrypt(self.ptr, plain_text.ptr(), ct.ptr(), mem_pool_ptr) };
        anyhow::ensure!(ret == 0, "Error encrypting");
        Ok(ct)
    }

    #[allow(dead_code)]
    pub(crate) fn ptr(&self) -> *mut c_void {
        self.ptr
    }
}

impl Drop for Encryptor {
    fn drop(&mut self) {
        unsafe {
            Encryptor_Destroy(self.ptr);
        }
    }
}
