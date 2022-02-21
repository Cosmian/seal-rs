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

    /// Create a `CipherText` in the thread local memory pool
    pub fn create_with_context(context: &Context) -> Result<Ciphertext> {
        let mut handle_ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { MemoryManager_GetPool2(&mut handle_ptr) };
        anyhow::ensure!(ret == 0, "Error creating the memory pool handle");
        let mut ptr: *mut c_void = std::ptr::null_mut();
        // this moves the pointer
        let ret =
            unsafe { Ciphertext_Create3(context as *const _ as *mut _, handle_ptr, &mut ptr) };
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

    pub fn size(&self) -> Result<usize> {
        let mut size: u64 = 0;
        let ret = unsafe { Ciphertext_Size(self.ptr(), &mut size) };
        anyhow::ensure!(
            ret == 0,
            "Error getting the cipher text size: {}",
            std::io::Error::last_os_error()
        );
        Ok(size as usize)
    }

    pub fn get_poly_modulus_degree(&self) -> Result<usize> {
        let mut n: u64 = 0;
        let ret = unsafe { Ciphertext_PolyModulusDegree(self.ptr(), &mut n) };
        anyhow::ensure!(ret == 0, "Error getting the polymodulus degree",);
        Ok(n as usize)
    }

    pub fn get_coeff_modulus_size(&self) -> Result<usize> {
        let mut k: u64 = 0;
        let ret = unsafe { Ciphertext_CoeffModulusSize(self.ptr(), &mut k) };
        anyhow::ensure!(ret == 0, "Error getting the coeff modulus size",);
        // TODO: why is it not equal to parms.get_coeff_modulus().size() ?
        Ok(k as usize)
    }

    pub fn poly_size(&self) -> Result<usize> {
        Ok(self.get_coeff_modulus_size()? * self.get_poly_modulus_degree()?)
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

    //pub fn get_raw(&self) -> Result<Vec<Vec<u64>>> {
    //let (size, coeff_modulus_size, poly_modulus_degree) = (
    //self.size()?,
    //self.get_coeff_modulus_size()?,
    //self.get_poly_modulus_degree()?,
    //);
    //Ok((0..size)
    //.map(|i| {
    //(0..poly_modulus_degree)
    //.map(|j| -> u64 {
    //(0..coeff_modulus_size)
    //.map(|k| {
    //let mut coeff = 0;
    //unsafe {
    //Ciphertext_GetDataAt1(
    //self.ptr(),
    //(i * (coeff_modulus_size * poly_modulus_degree)
    //+ k * poly_modulus_degree
    //+ j) as u64,
    //&mut coeff,
    //)
    //};
    //coeff
    //})
    //.sum()
    //})
    //.collect()
    //})
    //.collect())
    //}

    pub fn get_raw_rns(&self) -> Result<Vec<u64>> {
        (0..self.size()? * self.get_coeff_modulus_size()? * self.get_poly_modulus_degree()?)
            .map(|index| -> Result<u64> {
                let mut coeff = 0;
                let ret = unsafe { Ciphertext_GetDataAt1(self.ptr(), index as u64, &mut coeff) };
                anyhow::ensure!(
                    ret == 0,
                    "Could not get coefficient {} from the given ciphertext ({})!",
                    index,
                    ret
                );
                Ok(coeff)
            })
            .collect()
    }

    pub fn set_raw_rns(&self, polynomials: Vec<u64>) -> Result<()> {
        for (index, coeff) in polynomials.iter().enumerate() {
            let ret = unsafe { Ciphertext_SetDataAt(self.ptr(), index as u64, *coeff) };
            anyhow::ensure!(
                ret == 0,
                "Could not set polynomial on index {} of the given ciphertext: {}",
                index,
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }

    pub fn try_add_assign(&self, other: &Self, modulus: &[u64]) -> Result<()> {
        let (mut a, b) = (self.get_raw_rns()?, other.get_raw_rns()?);
        let mut index = 0;
        for _ in 0..self.size()? {
            for modulus in modulus.iter().take(self.get_coeff_modulus_size()?) {
                for _ in 0..self.get_poly_modulus_degree()? {
                    a[index] = (a[index] + b[index]) % modulus;
                    index += 1;
                }
            }
        }
        self.set_raw_rns(a)
    }
}

impl Drop for Ciphertext {
    fn drop(&mut self) {
        unsafe {
            Ciphertext_Destroy(self.ptr);
        }
    }
}
