use std::os::raw::*;

use anyhow::Result;

use crate::{
    cipher_text::Ciphertext, context::Context, key_generator::SecretKey, plain_text::Plaintext,
    seal_bindings::*,
};

pub struct Decryptor {
    ptr: *mut ::std::os::raw::c_void,
}

impl Decryptor {
    /// Creates a Decryptor instance initialized with the specified SEALContext
    /// and secret key.
    /// @param[in] context The SEALContext
    /// @param[in] secret_key The secret key
    /// @throws std::invalid_argument if the context is not set or encryption
    /// parameters are not valid
    /// @throws std::invalid_argument if secret_key is not valid
    pub fn create(context: &Context, secret_key: &SecretKey) -> Result<Decryptor> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Decryptor_Create(context.ptr(), secret_key.ptr(), &mut ptr) };
        anyhow::ensure!(ret == 0, "Error creating the decryptor");
        Ok(Decryptor { ptr })
    }

    #[allow(dead_code)]
    pub(crate) fn ptr(&self) -> *mut c_void {
        self.ptr
    }

    /// Decrypts a Ciphertext and stores the result in the destination
    /// parameter.
    ///
    /// @param[in] encrypted The ciphertext to decrypt
    /// @param[out] destination The plaintext to overwrite with the decrypted
    /// ciphertext
    /// @throws std::invalid_argument if encrypted is not valid for the
    /// encryption parameters
    /// @throws std::invalid_argument if encrypted is not in the default NTT
    /// form
    pub fn decrypt(&self, cipher_text: &Ciphertext) -> Result<Plaintext> {
        let pt = Plaintext::create_in_pool_of_cipher_text(cipher_text)?;
        let ret = unsafe { Decryptor_Decrypt(self.ptr, cipher_text.ptr(), pt.ptr()) };
        anyhow::ensure!(ret == 0, "Error decrypting");
        Ok(pt)
    }

    /// Computes the invariant noise budget (in bits) of a ciphertext. The
    /// invariant noise budget measures the amount of room there is for the
    /// noise to grow while ensuring correct decryptions. This function
    /// works only with the BFV scheme.
    ///
    /// @par Invariant Noise Budget
    /// The invariant noise polynomial of a ciphertext is a rational coefficient
    /// polynomial, such that a ciphertext decrypts correctly as long as the
    /// coefficients of the invariantnoise polynomial are of absolute value less
    /// than 1/2. Thus, we call the infinity-norm of the invariant noise
    /// polynomial the invariant noise, and for correct decryption requireit
    /// to be less than 1/2. If v denotes the invariant noise, we define the
    /// invariant noise budget as -log2(2v). Thus, the invariant noise
    /// budget starts from some initial value, which depends on the
    /// encryption parameters, and decreases when computations are
    /// performed. When the budget reaches zero, the ciphertext becomes too
    /// noisy to decrypt correctly.
    ///
    /// @param[in] encrypted The ciphertext
    /// @throws std::invalid_argument if the scheme is not BFV
    /// @throws std::invalid_argument if encrypted is not valid for the
    /// encryption parameters
    /// @throws std::invalid_argument if encrypted is in NTT form
    pub fn invariant_noise_budget(&self, cipher_text: &Ciphertext) -> Result<i32> {
        let mut noise_budget = 0i32;
        let ret = unsafe {
            Decryptor_InvariantNoiseBudget(self.ptr, cipher_text.ptr(), &mut noise_budget)
        };
        anyhow::ensure!(ret == 0, "Error getting the noise budget");
        Ok(noise_budget)
    }
}

impl Drop for Decryptor {
    fn drop(&mut self) {
        unsafe {
            Decryptor_Destroy(self.ptr);
        }
    }
}
