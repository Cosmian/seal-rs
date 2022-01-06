use std::os::raw::*;

use anyhow::Result;

use crate::{
    context::Context, memory_pool_handle::MemoryPoolHandle, plain_text::Plaintext, seal_bindings::*,
};

pub struct Ciphertext {
    ptr: *mut ::std::os::raw::c_void,
}

impl Ciphertext {
    /// Create a `CipherText` in the thread local memory pool
    pub fn create() -> Result<Ciphertext> {
        let mut handle_ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { MemoryManager_GetPool2(&mut handle_ptr) };
        anyhow::ensure!(ret == 0, "Error creating the memory pool handle");
        let mut ptr: *mut c_void = std::ptr::null_mut();
        // this moves the pointer
        let ret = unsafe { Ciphertext_Create1(handle_ptr, &mut ptr) };
        anyhow::ensure!(ret == 0, "Error creating the cipher text");
        Ok(Ciphertext { ptr })
    }

    pub fn create_in_pool(memory_pool_handle: MemoryPoolHandle) -> Result<Ciphertext> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        // this moves the pointer
        let ret = unsafe { Ciphertext_Create1(memory_pool_handle.ptr(), &mut ptr) };
        anyhow::ensure!(ret == 0, "Error creating the cipher text");
        Ok(Ciphertext { ptr })
    }

    pub(crate) fn create_in_pool_of_cipher_text(other: &Ciphertext) -> Result<Ciphertext> {
        let mut mem_pool_ptr: *mut c_void = std::ptr::null_mut();
        // this call creates a new object which is
        // managed through a unique_pt in the create call
        let ret = unsafe { Ciphertext_Pool(other.ptr(), &mut mem_pool_ptr) };
        anyhow::ensure!(ret == 0, "Error fetching the cipher text memory pool");
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Ciphertext_Create1(mem_pool_ptr, &mut ptr) };
        anyhow::ensure!(ret == 0, "Error creating the cipher text");
        Ok(Ciphertext { ptr })
    }

    pub(crate) fn create_in_pool_of_plain_text(other: &Plaintext) -> Result<Ciphertext> {
        let mut mem_pool_ptr: *mut c_void = std::ptr::null_mut();
        // this call creates a new object which is
        // managed through a unique_pt in the create call
        let ret = unsafe { Plaintext_Pool(other.ptr(), &mut mem_pool_ptr) };
        anyhow::ensure!(ret == 0, "Error fetching the plain text memory pool");
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Ciphertext_Create1(mem_pool_ptr, &mut ptr) };
        anyhow::ensure!(ret == 0, "Error creating the cipher text");
        Ok(Ciphertext { ptr })
    }

    pub(crate) fn ptr(&self) -> *mut c_void {
        self.ptr
    }

    pub fn save(&self) -> Result<Vec<u8>> {
        let compression_mode = 1u8; //bzip
        let mut uncompressed_size: i64 = 0;
        let ret =
            unsafe { Ciphertext_SaveSize(self.ptr, compression_mode, &mut uncompressed_size) };
        anyhow::ensure!(
            ret == 0,
            "Error estimating the save size for the cipher text"
        );
        let mut actual_size = 0i64;
        let mut bytes: Vec<u8> = vec![0u8; uncompressed_size as usize];
        let ret = unsafe {
            Ciphertext_Save(
                self.ptr,
                bytes.as_mut_ptr(),
                uncompressed_size as u64,
                compression_mode,
                &mut actual_size,
            )
        };
        anyhow::ensure!(ret == 0, "Error saving the cipher text");
        // if compression is 'on', the actual size
        // will be less than the uncompressed_size
        Ok(bytes[0..actual_size as usize].to_vec())
    }

    /// load the cipher text from compressed bytes
    /// in a thread local memory pool
    pub fn load(context: &Context, bytes: &mut [u8]) -> Result<Ciphertext> {
        let pool_handle = MemoryPoolHandle::to_thread_local_pool()?;
        Ciphertext::load_in_pool(context, pool_handle, bytes)
    }

    pub fn load_in_pool(
        context: &Context,
        pool_handle: MemoryPoolHandle,
        bytes: &mut [u8],
    ) -> Result<Ciphertext> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Ciphertext_Create1(pool_handle.ptr(), &mut ptr) };
        anyhow::ensure!(
            ret == 0,
            "Error instantiating cipher text: {}",
            std::io::Error::last_os_error()
        );
        let mut _actual_size: i64 = 0;
        let ret = unsafe {
            Ciphertext_Load(
                ptr,
                context.ptr(),
                bytes.as_mut_ptr(),
                bytes.len() as u64,
                &mut _actual_size,
            )
        };
        anyhow::ensure!(
            ret == 0,
            "Error loading the cipher text: {}",
            std::io::Error::last_os_error()
        );
        Ok(Ciphertext { ptr })
    }

    pub fn clone(&self) -> Result<Ciphertext> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Ciphertext_Create2(self.ptr(), &mut ptr) };
        anyhow::ensure!(
            ret == 0,
            "Error cloning the cipher text: {}",
            std::io::Error::last_os_error()
        );
        Ok(Ciphertext { ptr })
    }

    pub fn size(&self) -> Result<u64> {
        let mut size: u64 = 0;
        let ret = unsafe { Ciphertext_Size(self.ptr(), &mut size) };
        anyhow::ensure!(
            ret == 0,
            "Error getting the cipher text size: {}",
            std::io::Error::last_os_error()
        );
        Ok(size)
    }

    pub fn scale(&self) -> Result<f64> {
        let mut scale: f64 = 0.0;
        let ret = unsafe { Ciphertext_Scale(self.ptr(), &mut scale) };
        anyhow::ensure!(ret == 0, "Error getting the scale");
        Ok(scale)
    }

    pub fn set_scale(&self, scale: &f64) -> Result<()> {
        let ret = unsafe { Ciphertext_SetScale(self.ptr(), *scale) };
        anyhow::ensure!(ret == 0, "Error setting the scale {}", scale);
        Ok(())
    }

    pub fn parms_id(&self) -> Result<Vec<u64>> {
        let mut parms_id = vec![0u64; 4];
        let ret = unsafe { Ciphertext_ParmsId(self.ptr(), parms_id.as_mut_ptr()) };
        anyhow::ensure!(ret == 0, "Error getting the parms id");
        Ok(parms_id)
    }
}

impl Drop for Ciphertext {
    fn drop(&mut self) {
        unsafe {
            Ciphertext_Destroy(self.ptr);
        }
    }
}
