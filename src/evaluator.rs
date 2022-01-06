use std::os::raw::*;

use anyhow::{anyhow, Result};

use crate::{
    cipher_text::Ciphertext,
    context::Context,
    key_generator::{GaloisKeys, RelinearizationKeys},
    plain_text::Plaintext,
    seal_bindings::*,
};

pub struct Evaluator {
    ptr: *mut ::std::os::raw::c_void,
}

impl Evaluator {
    pub fn create(context: &Context) -> Result<Evaluator> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Evaluator_Create(context.ptr(), &mut ptr) };
        anyhow::ensure!(ret == 0, "Error creating the evaluator");
        Ok(Evaluator { ptr })
    }

    #[allow(dead_code)]
    pub(crate) fn ptr(&self) -> *mut c_void {
        self.ptr
    }

    pub fn add(
        &self,
        cipher_text_a: &Ciphertext,
        cipher_text_b: &Ciphertext,
    ) -> Result<Ciphertext> {
        let added = Ciphertext::create_in_pool_of_cipher_text(&cipher_text_a)?;
        let ret = unsafe {
            Evaluator_Add(
                self.ptr,
                cipher_text_a.ptr(),
                cipher_text_b.ptr(),
                added.ptr(),
            )
        };
        anyhow::ensure!(ret == 0, "Error adding");
        Ok(added)
    }

    pub fn add_plain(
        &self,
        cipher_text_a: &Ciphertext,
        plain_text_b: &Plaintext,
    ) -> Result<Ciphertext> {
        let added = Ciphertext::create_in_pool_of_cipher_text(&cipher_text_a)?;
        let ret = unsafe {
            Evaluator_AddPlain(
                self.ptr,
                cipher_text_a.ptr(),
                plain_text_b.ptr(),
                added.ptr(),
            )
        };
        anyhow::ensure!(ret == 0, "Error adding a plain text");
        Ok(added)
    }

    pub fn mul(
        &self,
        cipher_text_a: &Ciphertext,
        cipher_text_b: &Ciphertext,
    ) -> Result<Ciphertext> {
        let mul = Ciphertext::create_in_pool_of_cipher_text(&cipher_text_a)?;
        let mut mem_pool_ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Ciphertext_Pool(mul.ptr(), &mut mem_pool_ptr) };
        anyhow::ensure!(ret == 0, "Error fetching the cipher text memory pool");
        let ret = unsafe {
            Evaluator_Multiply(
                self.ptr,
                cipher_text_a.ptr(),
                cipher_text_b.ptr(),
                mul.ptr(),
                mem_pool_ptr,
            )
        };
        anyhow::ensure!(ret == 0, "Error multiplying");
        Ok(mul)
    }

    pub fn mul_plain(
        &self,
        cipher_text_a: &Ciphertext,
        plain_text_b: &Plaintext,
    ) -> Result<Ciphertext> {
        let mul = Ciphertext::create_in_pool_of_cipher_text(&cipher_text_a)?;
        let mut mem_pool_ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Ciphertext_Pool(mul.ptr(), &mut mem_pool_ptr) };
        anyhow::ensure!(ret == 0, "Error fetching the cipher text memory pool");
        let ret = unsafe {
            Evaluator_MultiplyPlain(
                self.ptr,
                cipher_text_a.ptr(),
                plain_text_b.ptr(),
                mul.ptr(),
                mem_pool_ptr,
            )
        };
        //#define COR_E_INVALIDOPERATION _HRESULT_TYPEDEF_(0x80131509L)
        // This error is returned by 'Evaluator_MultiplyPlain' as a logic_error uniquely
        // when the output  ciphertext is transparent, i.e. does not require a
        // secret key to decrypt. In typical security models such transparent
        // ciphertexts would not be  considered to be valid. Starting from the
        // second polynomial in the output  ciphertext, this function returns
        // '0x80131509L' if all following coefficients are  identically zero.
        if ret == 0x80131509 {
            return Err(anyhow!("Transparent output: plaintext must be non zero"))
        }
        anyhow::ensure!(ret == 0, "Error multiplying a plain text");
        Ok(mul)
    }

    pub fn square(&self, cipher_text: &Ciphertext) -> Result<Ciphertext> {
        let squared = Ciphertext::create_in_pool_of_cipher_text(&cipher_text)?;
        let mut mem_pool_ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Ciphertext_Pool(squared.ptr(), &mut mem_pool_ptr) };
        anyhow::ensure!(ret == 0, "Error fetching the cipher text memory pool");
        let ret =
            unsafe { Evaluator_Square(self.ptr, cipher_text.ptr(), squared.ptr(), mem_pool_ptr) };
        anyhow::ensure!(ret == 0, "Error squaring the cipher text");
        Ok(squared)
    }

    pub fn relinearize(
        &self,
        cipher_text_a: &Ciphertext,
        relinearization_keys: &RelinearizationKeys,
    ) -> Result<Ciphertext> {
        let relin = Ciphertext::create_in_pool_of_cipher_text(&cipher_text_a)?;
        let mut mem_pool_ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Ciphertext_Pool(relin.ptr(), &mut mem_pool_ptr) };
        anyhow::ensure!(ret == 0, "Error fetching the cipher text memory pool");
        let ret = unsafe {
            Evaluator_Relinearize(
                self.ptr,
                cipher_text_a.ptr(),
                relinearization_keys.ptr(),
                relin.ptr(),
                mem_pool_ptr,
            )
        };
        anyhow::ensure!(ret == 0, "Error relinearizing");
        Ok(relin)
    }

    pub fn mod_switch_to_next(&self, cipher_text: &Ciphertext) -> Result<Ciphertext> {
        let switch = Ciphertext::create_in_pool_of_cipher_text(&cipher_text)?;
        let mut mem_pool_ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Ciphertext_Pool(switch.ptr(), &mut mem_pool_ptr) };
        anyhow::ensure!(ret == 0, "Error fetching the cipher text memory pool");
        let ret = unsafe {
            Evaluator_ModSwitchToNext1(self.ptr, cipher_text.ptr(), switch.ptr(), mem_pool_ptr)
        };
        anyhow::ensure!(ret == 0, "Error performing modulus switching");
        Ok(switch)
    }

    pub fn mod_switch_to_next_plain_text(&self, plain_text: &Plaintext) -> Result<Plaintext> {
        let switch = Plaintext::create_in_pool_of_plain_text(&plain_text)?;
        let mut mem_pool_ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Plaintext_Pool(switch.ptr(), &mut mem_pool_ptr) };
        anyhow::ensure!(ret == 0, "Error fetching the plain text memory pool");
        let ret = unsafe {
            Evaluator_ModSwitchToNext1(self.ptr, plain_text.ptr(), switch.ptr(), mem_pool_ptr)
        };
        anyhow::ensure!(
            ret == 0,
            "Error performing modulus switching for plain text"
        );
        Ok(switch)
    }

    /// compact the cipher text by performing modulus switching on it
    /// as much as possible. Calling this method will lead to a reduction in
    /// the noise budget.
    pub fn compact_size(&self, cipher_text: &Ciphertext) -> Result<Ciphertext> {
        let mut ct = cipher_text.clone()?;
        loop {
            ct = match self.mod_switch_to_next(&ct) {
                Ok(ct) => ct,
                Err(_) => {
                    // cannot perform more
                    return Ok(ct)
                }
            };
        }
    }

    pub fn mod_switch_to(
        &self,
        cipher_text: &Ciphertext,
        parms_id: &mut [u64],
    ) -> Result<Ciphertext> {
        let switch = Ciphertext::create_in_pool_of_cipher_text(&cipher_text)?;
        let mut mem_pool_ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Ciphertext_Pool(switch.ptr(), &mut mem_pool_ptr) };
        anyhow::ensure!(ret == 0, "Error fetching the cipher text memory pool");
        let ret = unsafe {
            Evaluator_ModSwitchTo1(
                self.ptr,
                cipher_text.ptr(),
                parms_id.as_mut_ptr(),
                switch.ptr(),
                mem_pool_ptr,
            )
        };
        anyhow::ensure!(ret == 0, "Error performing modulus switching");
        Ok(switch)
    }

    pub fn mod_switch_to_plain_text(
        &self,
        plain_text: &Plaintext,
        parms_id: &mut [u64],
    ) -> Result<Plaintext> {
        let switch = Plaintext::create_in_pool_of_plain_text(&plain_text)?;
        let ret = unsafe {
            Evaluator_ModSwitchTo2(
                self.ptr,
                plain_text.ptr(),
                parms_id.as_mut_ptr(),
                switch.ptr(),
            )
        };
        anyhow::ensure!(ret == 0, "Error performing modulus switching");
        Ok(switch)
    }

    pub fn rescale_to_next(&self, cipher_text: &Ciphertext) -> Result<Ciphertext> {
        let rescale = Ciphertext::create_in_pool_of_cipher_text(&cipher_text)?;
        let mut mem_pool_ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Ciphertext_Pool(rescale.ptr(), &mut mem_pool_ptr) };
        anyhow::ensure!(ret == 0, "Error fetching the cipher text memory pool");
        let ret = unsafe {
            Evaluator_RescaleToNext(self.ptr, cipher_text.ptr(), rescale.ptr(), mem_pool_ptr)
        };
        anyhow::ensure!(ret == 0, "Error performing rescale to next");
        Ok(rescale)
    }

    pub fn rotate(
        &self,
        cipher_text: &Ciphertext,
        shift: i32,
        galois_keys: &GaloisKeys,
    ) -> Result<Ciphertext> {
        let rotate = Ciphertext::create_in_pool_of_cipher_text(&cipher_text)?;
        let mut mem_pool_ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Ciphertext_Pool(rotate.ptr(), &mut mem_pool_ptr) };
        anyhow::ensure!(ret == 0, "Error fetching the cipher text memory pool");
        let ret = unsafe {
            Evaluator_RotateVector(
                self.ptr,
                cipher_text.ptr(),
                shift,
                galois_keys.ptr(),
                rotate.ptr(),
                mem_pool_ptr,
            )
        };
        anyhow::ensure!(ret == 0, "Error performing vector rotation");
        Ok(rotate)
    }
}

impl Drop for Evaluator {
    fn drop(&mut self) {
        unsafe {
            Evaluator_Destroy(self.ptr);
        }
    }
}
