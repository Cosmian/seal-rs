use crate::{params::Params, seal_bindings::*};
use anyhow::Result;
use std::os::raw::*;

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
        let mut ptr = std::ptr::null_mut();
        unsafe {
            // `ret` is always 0 here
            SEALContext_Create(
                params.ptr(),
                if expand_mod_chain { 1 } else { 0 },
                security_level as i32,
                &mut ptr,
            );
        };

        let context = Context {
            ptr,
            params,
            security_level,
        };

        // Check if there is a parameter error
        let (err, msg) = (context.get_error_name(), context.get_error_msg());
        if err != "success" || msg != "valid" {
            anyhow::bail!("Error {}: {}", err, msg);
        } else {
            Ok(context)
        }
    }

    pub fn get_error_name(&self) -> String {
        let mut length: u64 = 0;
        let mut buf = vec![0_u8; 512];
        unsafe {
            SEALContext_ParameterErrorName(self.ptr, buf.as_mut_ptr() as *mut i8, &mut length);
        }
        buf.resize(length as usize, 0_u8);
        String::from_utf8_lossy(&buf).to_string()
    }

    pub fn get_error_msg(&self) -> String {
        let mut length: u64 = 0;
        let mut buf = vec![0_u8; 512];
        unsafe {
            SEALContext_ParameterErrorMessage(self.ptr, buf.as_mut_ptr() as *mut i8, &mut length);
        }
        buf.resize(length as usize, 0_u8);
        String::from_utf8_lossy(&buf).to_string()
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
