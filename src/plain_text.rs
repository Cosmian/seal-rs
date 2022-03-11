use crate::{
    cipher_text::Ciphertext, context::Context, memory_pool_handle::MemoryPoolHandle,
    seal_bindings::*,
};
use anyhow::Result;
use core::convert::TryFrom;
use std::os::raw::*;

pub struct Plaintext {
    ptr: *mut c_void,
}

#[derive(Debug)]
pub enum PlainTextError {
    Creation,
    GetCoeff,
    GetCoeffCount,
}

impl Plaintext {
    /// Create a PlainText in the thread local memory pool
    pub fn create() -> Result<Plaintext> {
        let mut handle_ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { MemoryManager_GetPool2(&mut handle_ptr) };
        anyhow::ensure!(ret == 0, "Error creating the memory pool handle");
        let mut ptr: *mut c_void = std::ptr::null_mut();
        // the memory pool pointer is dereferenced to a MemoryPoolHandle
        // and copied
        let ret = unsafe { Plaintext_Create1(handle_ptr, &mut ptr) };
        anyhow::ensure!(ret == 0, "Error creating the plain text");
        Ok(Plaintext { ptr })
    }

    pub fn create_in_pool(memory_pool: MemoryPoolHandle) -> Result<Plaintext> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        // the memory pool pointer is dereferenced to a MemoryPoolHandle
        // and copied
        let ret = unsafe { Plaintext_Create1(memory_pool.ptr(), &mut ptr) };
        anyhow::ensure!(ret == 0, "Error creating the plain text");
        Ok(Plaintext { ptr })
    }

    /// Create a constant (i.e. a polynomial of degree 0)
    /// in the thread local memory pool
    pub fn create_constant(value: u64) -> Result<Plaintext> {
        let pt = Plaintext::create()?;
        let ret = unsafe { Plaintext_Set3(pt.ptr(), value) };
        anyhow::ensure!(
            ret == 0,
            "Error creating the constant plain text with value: {}",
            value
        );
        Ok(pt)
    }

    pub(crate) fn create_in_pool_of_plain_text(other: &Plaintext) -> Result<Plaintext> {
        let mut mem_pool_ptr: *mut c_void = std::ptr::null_mut();
        // this call creates a new object which is
        // managed through a unique_pt in the create call
        let ret = unsafe { Plaintext_Pool(other.ptr(), &mut mem_pool_ptr) };
        anyhow::ensure!(ret == 0, "Error fetching the plain text memory pool");
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Plaintext_Create1(mem_pool_ptr, &mut ptr) };
        anyhow::ensure!(ret == 0, "Error creating the plain text");
        Ok(Plaintext { ptr })
    }

    pub(crate) fn create_in_pool_of_cipher_text(other: &Ciphertext) -> Result<Plaintext> {
        let mut mem_pool_ptr: *mut c_void = std::ptr::null_mut();
        // this call creates a new object which is
        // managed through a unique_pt in the create call
        let ret = unsafe { Ciphertext_Pool(other.ptr(), &mut mem_pool_ptr) };
        anyhow::ensure!(ret == 0, "Error fetching the cipher text memory pool");
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Plaintext_Create1(mem_pool_ptr, &mut ptr) };
        anyhow::ensure!(ret == 0, "Error creating the plain text");
        Ok(Plaintext { ptr })
    }

    pub fn coeff_at(&self, index: usize) -> Result<u64> {
        let mut value: u64 = 0;
        let ret = unsafe { Plaintext_CoeffAt(self.ptr(), index as u64, &mut value) };
        anyhow::ensure!(ret == 0, "Error getting the coefficient at: {}", index);
        Ok(value)
    }

    pub fn coeffs_count(&self) -> Result<usize> {
        let mut value: u64 = 0;
        let ret = unsafe { Plaintext_CoeffCount(self.ptr(), &mut value) };
        anyhow::ensure!(ret == 0, "Error getting the coefficients count");
        Ok(value as usize)
    }

    pub(crate) fn ptr(&self) -> *mut c_void {
        self.ptr
    }

    pub fn make_constant(&self, value: u64) -> Result<()> {
        let ret = unsafe { Plaintext_Set3(self.ptr(), value) };
        anyhow::ensure!(
            ret == 0,
            "Error making the plain text as a constant with value: {}",
            value
        );
        Ok(())
    }

    pub fn save(&self) -> Result<Vec<u8>> {
        let compression_mode = 1u8; //bzip
        let mut uncompressed_size: i64 = 0;
        let ret = unsafe { Plaintext_SaveSize(self.ptr, compression_mode, &mut uncompressed_size) };
        anyhow::ensure!(
            ret == 0,
            "Error estimating the save size for the plain text"
        );
        let mut actual_size = 0i64;
        let mut bytes: Vec<u8> = vec![0u8; uncompressed_size as usize];
        let ret = unsafe {
            Plaintext_Save(
                self.ptr,
                bytes.as_mut_ptr(),
                uncompressed_size as u64,
                compression_mode,
                &mut actual_size,
            )
        };
        anyhow::ensure!(ret == 0, "Error saving the plain text");
        // if compression is 'on', the actual size
        // will be less than the uncompressed_size
        Ok(bytes[0..actual_size as usize].to_vec())
    }

    /// load the plain text from compressed bytes
    /// in a thread local memory pool
    pub fn load(context: &Context, bytes: &mut [u8]) -> Result<Plaintext> {
        let pool_handle = MemoryPoolHandle::to_thread_local_pool()?;
        Plaintext::load_in_pool(context, pool_handle, bytes)
    }

    pub fn load_in_pool(
        context: &Context,
        pool_handle: MemoryPoolHandle,
        bytes: &mut [u8],
    ) -> Result<Plaintext> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Plaintext_Create1(pool_handle.ptr(), &mut ptr) };
        anyhow::ensure!(
            ret == 0,
            "Error instantiating plain text: {}",
            std::io::Error::last_os_error()
        );
        let mut _actual_size: i64 = 0;
        let ret = unsafe {
            Plaintext_Load(
                ptr,
                context.ptr(),
                bytes.as_mut_ptr(),
                bytes.len() as u64,
                &mut _actual_size,
            )
        };
        anyhow::ensure!(
            ret == 0,
            "Error loading the plain text: {}",
            std::io::Error::last_os_error()
        );
        Ok(Plaintext { ptr })
    }

    pub fn clone(&self) -> Result<Plaintext> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Plaintext_Create5(self.ptr(), &mut ptr) };
        anyhow::ensure!(
            ret == 0,
            "Error cloning the plain text: {}",
            std::io::Error::last_os_error()
        );
        Ok(Plaintext { ptr })
    }
}

impl<'a> TryFrom<&'a [u64]> for Plaintext {
    type Error = PlainTextError;

    fn try_from(v: &'a [u64]) -> Result<Self, Self::Error> {
        let p = Plaintext::create().map_err(|_| Self::Error::Creation)?;
        let ret = unsafe { Plaintext_Set4(p.ptr(), v.len() as u64, &v[0] as *const _ as *mut _) };
        match ret {
            0 => Ok(p),
            _ => Err(Self::Error::Creation),
        }
    }
}

impl<'a> TryFrom<&'a Plaintext> for Vec<u64> {
    type Error = PlainTextError;

    fn try_from(value: &'a Plaintext) -> Result<Self, Self::Error> {
        (0..value
            .coeffs_count()
            .map_err(|_| Self::Error::GetCoeffCount)?)
            .map(|i| value.coeff_at(i).map_err(|_| Self::Error::GetCoeffCount))
            .collect()
    }
}

impl Drop for Plaintext {
    fn drop(&mut self) {
        unsafe {
            Plaintext_Destroy(self.ptr);
        }
    }
}
