use std::os::raw::*;

use anyhow::Result;

use crate::{params::Params, seal_bindings::*};

pub struct Context {
    ptr: *mut ::std::os::raw::c_void,
    // these parameters can be recovered from the C++ API level
    // and hence duplicate them... but we do not carry usually more
    // than one context
    params: Params,
    security_level: u8,
}

impl Context {
    pub fn create(params: Params, security_level: u8, expand_mod_chain: bool) -> Result<Context> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe {
            SEALContext_Create(
                params.ptr(),
                if expand_mod_chain { 1 } else { 0 },
                security_level as i32,
                &mut ptr,
            )
        };
        anyhow::ensure!(
            ret == 0,
            "Error creating the context with security level {}",
            security_level
        );
        Ok(Context {
            ptr,
            params,
            security_level,
        })
    }

    pub(crate) fn ptr(&self) -> *mut c_void {
        self.ptr
    }

    pub fn security_level(&self) -> u8 {
        self.security_level
    }

    pub fn parameters(&self) -> &Params {
        &self.params
    }

    pub fn first_parms_id(&self) -> Result<Vec<u64>> {
        let mut parms_id = vec![0u64; 4];
        let ret = unsafe { SEALContext_FirstParmsId(self.ptr, parms_id.as_mut_ptr()) };
        anyhow::ensure!(ret == 0, "unable to get the first parms id: ");
        Ok(parms_id)
    }

    pub fn get_coeff_modulus_count(&self) -> Result<u64> {
        let mut count: u64 = 0;
        let mut data_ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { SEALContext_FirstContextData(self.ptr, &mut data_ptr) };
        anyhow::ensure!(ret == 0, "unable to get the context: ");
        let ret =
            unsafe { ContextData_TotalCoeffModulus(data_ptr, &mut count, std::ptr::null_mut()) };
        anyhow::ensure!(ret == 0, "unable to get the number of Coeff Modulus");
        Ok(count)
    }

    pub fn get_coeff_modulus(&self) -> Result<Vec<u64>> {
        let mut coeffs_len: u64 = self.get_coeff_modulus_count()? + 1;
        let mut primes = vec![std::ptr::null_mut(); coeffs_len as usize];
        let ret = unsafe {
            EncParams_GetCoeffModulus(self.params.ptr(), &mut coeffs_len, primes.as_mut_ptr())
        };
        anyhow::ensure!(ret == 0, "unable to get the Coeff Modulus: ");
        let mut coeffs = vec![0; coeffs_len as usize];
        for i in 0..coeffs_len as usize {
            unsafe { Modulus_Value(primes[i], &mut coeffs[i]) };
        }
        Ok(coeffs)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            SEALContext_Destroy(self.ptr);
        }
    }
}
