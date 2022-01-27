use std::{convert::TryInto, os::raw::*};

use anyhow::{Error, Result};

use crate::{context::Context, seal_bindings::*};

pub struct PublicKey {
    ptr: *mut ::std::os::raw::c_void,
}

impl PublicKey {
    pub(crate) fn ptr(&self) -> *mut c_void {
        self.ptr
    }

    pub fn save(&self) -> Result<Vec<u8>> {
        let compression_mode = 1u8; //bzip
        let mut uncompressed_size: i64 = 0;
        let ret = unsafe { PublicKey_SaveSize(self.ptr, compression_mode, &mut uncompressed_size) };
        anyhow::ensure!(
            ret == 0,
            "Error estimating the save size for the public key"
        );
        let mut actual_size = 0i64;
        let mut bytes: Vec<u8> = vec![0u8; uncompressed_size as usize];
        let ret = unsafe {
            PublicKey_Save(
                self.ptr,
                bytes.as_mut_ptr(),
                uncompressed_size as u64,
                compression_mode,
                &mut actual_size,
            )
        };
        anyhow::ensure!(ret == 0, "Error saving the public key");
        // if compression is 'on', the actual size
        // will be less than the uncompressed_size
        Ok(bytes[0..actual_size as usize].to_vec())
    }

    pub fn load(context: &Context, bytes: &mut [u8]) -> Result<PublicKey> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { PublicKey_Create1(&mut ptr) };
        anyhow::ensure!(
            ret == 0,
            "Error instantiating public key: {}",
            std::io::Error::last_os_error()
        );
        let mut actual_size: i64 = 0;
        let ret = unsafe {
            PublicKey_Load(
                ptr,
                context.ptr(),
                bytes.as_mut_ptr(),
                bytes.len() as u64,
                &mut actual_size,
            )
        };
        anyhow::ensure!(
            ret == 0,
            "Error loading the public key: {}",
            std::io::Error::last_os_error()
        );
        Ok(PublicKey { ptr })
    }
}

impl Drop for PublicKey {
    fn drop(&mut self) {
        unsafe {
            PublicKey_Destroy(self.ptr);
        }
    }
}

pub struct SecretKey {
    ptr: *mut c_void,
}

impl SecretKey {
    pub(crate) fn ptr(&self) -> *mut c_void {
        self.ptr
    }

    pub fn save(&self) -> Result<Vec<u8>> {
        let compression_mode = 1u8; //bzip
        let mut uncompressed_size: i64 = 0;
        let ret = unsafe { SecretKey_SaveSize(self.ptr, compression_mode, &mut uncompressed_size) };
        anyhow::ensure!(
            ret == 0,
            "Error estimating the save size for the secret key"
        );
        let mut actual_size = 0i64;
        let mut bytes: Vec<u8> = vec![0u8; uncompressed_size as usize];
        let ret = unsafe {
            SecretKey_Save(
                self.ptr,
                bytes.as_mut_ptr(),
                uncompressed_size as u64,
                compression_mode,
                &mut actual_size,
            )
        };
        anyhow::ensure!(ret == 0, "Error saving the secret key");
        // if compression is 'on', the actual size
        // will be less than the uncompressed_size
        Ok(bytes[0..actual_size as usize].to_vec())
    }

    pub fn load(context: &Context, bytes: &mut [u8]) -> Result<SecretKey> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { SecretKey_Create1(&mut ptr) };
        anyhow::ensure!(
            ret == 0,
            "Error instantiating secret key: {}",
            std::io::Error::last_os_error()
        );
        let mut actual_size: i64 = 0;
        let ret = unsafe {
            SecretKey_Load(
                ptr,
                context.ptr(),
                bytes.as_mut_ptr(),
                bytes.len() as u64,
                &mut actual_size,
            )
        };
        anyhow::ensure!(
            ret == 0,
            "Error loading the secret key: {}",
            std::io::Error::last_os_error()
        );
        Ok(SecretKey { ptr })
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        unsafe {
            SecretKey_Destroy(self.ptr);
        }
    }
}

pub struct RelinearizationKeys {
    ptr: *mut c_void,
}

impl RelinearizationKeys {
    pub(crate) fn ptr(&self) -> *mut c_void {
        self.ptr
    }

    pub fn save(&self) -> Result<Vec<u8>> {
        let compression_mode = 1u8; //bzip
        let mut uncompressed_size: i64 = 0;
        let ret =
            unsafe { KSwitchKeys_SaveSize(self.ptr, compression_mode, &mut uncompressed_size) };
        anyhow::ensure!(
            ret == 0,
            "Error estimating the save size for the relinearization keys"
        );
        let mut actual_size = 0i64;
        let mut bytes: Vec<u8> = vec![0u8; uncompressed_size as usize];
        let ret = unsafe {
            KSwitchKeys_Save(
                self.ptr,
                bytes.as_mut_ptr(),
                uncompressed_size as u64,
                compression_mode,
                &mut actual_size,
            )
        };
        anyhow::ensure!(ret == 0, "Error saving the relinearization keys");
        // if compression is 'on', the actual size
        // will be less than the uncompressed_size
        Ok(bytes[0..actual_size as usize].to_vec())
    }

    pub fn load(context: &Context, bytes: &mut [u8]) -> Result<RelinearizationKeys> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { KSwitchKeys_Create1(&mut ptr) };
        anyhow::ensure!(
            ret == 0,
            "Error instantiating relinearization keys: {}",
            std::io::Error::last_os_error()
        );
        let mut actual_size: i64 = 0;
        let ret = unsafe {
            KSwitchKeys_Load(
                ptr,
                context.ptr(),
                bytes.as_mut_ptr(),
                bytes.len() as u64,
                &mut actual_size,
            )
        };
        anyhow::ensure!(
            ret == 0,
            "Error loading the relinearization keys: {}",
            std::io::Error::last_os_error()
        );
        Ok(RelinearizationKeys { ptr })
    }

    pub fn clone(&self) -> Result<RelinearizationKeys> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { KSwitchKeys_Create2(self.ptr(), &mut ptr) };
        anyhow::ensure!(
            ret == 0,
            "Error cloning the relinearization text: {}",
            std::io::Error::last_os_error()
        );
        Ok(RelinearizationKeys { ptr })
    }
}

impl PartialEq for RelinearizationKeys {
    fn eq(&self, other: &RelinearizationKeys) -> bool {
        self.ptr == other.ptr
    }
}

impl TryInto<Vec<u8>> for RelinearizationKeys {
    type Error = Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        self.save()
    }
}

impl Drop for RelinearizationKeys {
    fn drop(&mut self) {
        unsafe {
            KSwitchKeys_Destroy(self.ptr);
        }
    }
}

pub struct GaloisKeys {
    ptr: *mut c_void,
}

impl GaloisKeys {
    pub(crate) fn ptr(&self) -> *mut c_void {
        self.ptr
    }

    pub fn save(&self) -> Result<Vec<u8>> {
        let compression_mode = 1u8; //bzip
        let mut uncompressed_size: i64 = 0;
        let ret =
            unsafe { KSwitchKeys_SaveSize(self.ptr, compression_mode, &mut uncompressed_size) };
        anyhow::ensure!(
            ret == 0,
            "Error estimating the save size for the galois keys"
        );
        let mut actual_size = 0i64;
        let mut bytes: Vec<u8> = vec![0u8; uncompressed_size as usize];
        let ret = unsafe {
            KSwitchKeys_Save(
                self.ptr,
                bytes.as_mut_ptr(),
                uncompressed_size as u64,
                compression_mode,
                &mut actual_size,
            )
        };
        anyhow::ensure!(ret == 0, "Error saving the galois keys");
        // if compression is 'on', the actual size
        // will be less than the uncompressed_size
        Ok(bytes[0..actual_size as usize].to_vec())
    }

    pub fn load(context: &Context, bytes: &mut [u8]) -> Result<GaloisKeys> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { KSwitchKeys_Create1(&mut ptr) };
        anyhow::ensure!(
            ret == 0,
            "Error instantiating galois keys: {}",
            std::io::Error::last_os_error()
        );
        let mut actual_size: i64 = 0;
        let ret = unsafe {
            KSwitchKeys_Load(
                ptr,
                context.ptr(),
                bytes.as_mut_ptr(),
                bytes.len() as u64,
                &mut actual_size,
            )
        };
        anyhow::ensure!(
            ret == 0,
            "Error loading the galois keys: {}",
            std::io::Error::last_os_error()
        );
        Ok(GaloisKeys { ptr })
    }

    pub fn clone(&self) -> Result<GaloisKeys> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { KSwitchKeys_Create2(self.ptr(), &mut ptr) };
        anyhow::ensure!(
            ret == 0,
            "Error cloning the galois text: {}",
            std::io::Error::last_os_error()
        );
        Ok(GaloisKeys { ptr })
    }
}

impl TryInto<Vec<u8>> for GaloisKeys {
    type Error = Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        self.save()
    }
}

impl Drop for GaloisKeys {
    fn drop(&mut self) {
        unsafe {
            KSwitchKeys_Destroy(self.ptr);
        }
    }
}

pub struct KeyGenerator {
    ptr: *mut ::std::os::raw::c_void,
}

/// The encryption schemes in Microsoft SEAL are public key encryption schemes.
/// For users unfamiliar with this terminology, a public key encryption scheme
/// has a separate public key for encrypting data, and a separate secret key for
/// decrypting data. This way multiple parties can encrypt data using the same
/// shared public key, but only the proper recipient of the data can decrypt it
/// with the secret key.
impl KeyGenerator {
    pub fn create(context: &Context) -> Result<KeyGenerator> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { KeyGenerator_Create1(context.ptr(), &mut ptr) };
        anyhow::ensure!(ret == 0, "Error creating the key generator");
        Ok(KeyGenerator { ptr })
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { KeyGenerator_CreatePublicKey(self.ptr, 0, &mut ptr) };
        anyhow::ensure!(ret == 0, "Error creating the public key");
        Ok(PublicKey { ptr })
    }

    pub fn secret_key(&self) -> Result<SecretKey> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { KeyGenerator_SecretKey(self.ptr, &mut ptr) };
        anyhow::ensure!(ret == 0, "Error creating the secret key");
        Ok(SecretKey { ptr })
    }

    /// `Relinearization' is an operation that reduces the size of a ciphertext
    /// after multiplication back to the initial size, 2. Thus,
    /// relinearizing one or both input ciphertexts before the next
    /// multiplication can have a huge positive impact on both noise growth
    /// and performance, even though relinearization has a significant
    /// computational cost itself. It is only possible to relinearize size 3
    /// ciphertexts down to size 2, so often the user would want to relinearize
    /// after each multiplication to keep the ciphertext sizes at 2.
    ///
    /// Relinearization requires special `relinearization keys', which can be
    /// thought of as a kind of public key. Relinearization keys can easily
    /// be created with the KeyGenerator.
    ///
    /// Relinearization is used similarly in both the BFV and the CKKS schemes
    pub fn relinearization_keys(&self) -> Result<RelinearizationKeys> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { KeyGenerator_CreateRelinKeys(self.ptr, 0, &mut ptr) };
        anyhow::ensure!(ret == 0, "Error creating the relinearization key");
        Ok(RelinearizationKeys { ptr })
    }

    /// Galois keys are used to rotate vector, similarly in both the BFV and the
    /// CKKS schemes
    pub fn galois_keys(&self) -> Result<GaloisKeys> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { KeyGenerator_CreateGaloisKeysAll(self.ptr, 0, &mut ptr) };
        anyhow::ensure!(ret == 0, "Error creating the galois key");
        Ok(GaloisKeys { ptr })
    }
}

impl Drop for KeyGenerator {
    fn drop(&mut self) {
        unsafe {
            KeyGenerator_Destroy(self.ptr);
        }
    }
}
