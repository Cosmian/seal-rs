use crate::{seal_bindings::*, SmallModulus};
use anyhow::Result;
use std::os::raw::*;

pub const SCHEME_BFV: u8 = 0x01;
pub const SCHEME_CKKS: u8 = 0x02;

pub struct Params {
    ptr: *mut ::std::os::raw::c_void,
}

#[allow(dead_code)]
impl Params {
    pub fn create(scheme: u8) -> Result<Params> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { EncParams_Create1(scheme, &mut ptr) };
        anyhow::ensure!(
            ret == 0,
            "failed creating the Params with scheme: {}",
            scheme
        );
        // seal_bindings::Enc
        Ok(Params { ptr })
    }

    pub(crate) fn ptr(&self) -> *mut c_void {
        self.ptr
    }

    pub fn clone(&self) -> Result<Params> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { EncParams_Create2(self.ptr(), &mut ptr) };
        anyhow::ensure!(
            ret == 0,
            "Error cloning the params: {}",
            std::io::Error::last_os_error()
        );
        Ok(Params { ptr })
    }

    pub fn load(scheme: u8, bytes: &mut [u8]) -> Result<Params> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { EncParams_Create1(scheme, &mut ptr) };
        anyhow::ensure!(
            ret == 0,
            "failed creating the Params with scheme: {}",
            scheme
        );
        let mut uncompressed_size = 0i64;
        let mut retry = 5;
        while retry > 0 {
            let ret = unsafe {
                EncParams_Load(
                    ptr,
                    bytes.as_mut_ptr(),
                    bytes.len() as u64,
                    &mut uncompressed_size,
                )
            };
            if ret == 0 {
                return Ok(Params { ptr });
            }
            retry -= 1;
        }
        anyhow::bail!(
            "Error loading the params: {}",
            std::io::Error::last_os_error()
        )
    }

    pub fn save(&self) -> Result<Vec<u8>> {
        let compression_mode = 1u8; //bzip
        let mut uncompressed_size: i64 = 0;
        let ret = unsafe { EncParams_SaveSize(self.ptr, compression_mode, &mut uncompressed_size) };
        anyhow::ensure!(ret == 0, "Error estimating the save size for the params");
        let mut actual_size = 0i64;
        let mut bytes: Vec<u8> = vec![0u8; uncompressed_size as usize];
        let ret = unsafe {
            EncParams_Save(
                self.ptr,
                bytes.as_mut_ptr(),
                uncompressed_size as u64,
                compression_mode,
                &mut actual_size,
            )
        };
        anyhow::ensure!(ret == 0, "Error saving the params");
        // if compression is 'on', the actual size
        // will be less than the uncompressed_size
        Ok(bytes[0..actual_size as usize].to_vec())
    }

    ///The first parameter we set is the degree of the `polynomial modulus'.
    /// This must be a positive power of 2, representing the degree of a
    /// power-of-two cyclotomic polynomial; it is not necessary to
    /// understand what this means.
    ///
    ///Larger poly_modulus_degree makes ciphertext sizes larger and all
    /// operations slower, but enables more complicated encrypted
    /// computations. Recommended values are 1024, 2048, 4096, 8192, 16384,
    /// 32768, but it is also possible to go beyond this range.
    pub fn set_poly_modulus_degree(&self, modulus_degree: usize) -> Result<()> {
        let ret = unsafe { EncParams_SetPolyModulusDegree(self.ptr, modulus_degree as u64) };
        anyhow::ensure!(
            ret == 0,
            "failed setting modulus degree: {}",
            modulus_degree
        );
        Ok(())
    }

    /// see setter
    pub fn get_poly_modulus_degree(&self) -> Result<usize> {
        let mut modulus_degree: u64 = 0;
        let ret = unsafe { EncParams_GetPolyModulusDegree(self.ptr, &mut modulus_degree) };
        anyhow::ensure!(ret == 0, "failed getting modulus degree");
        Ok(modulus_degree as usize)
    }

    /// Next we set the [ciphertext] `coefficient modulus' (coeff_modulus). This
    /// parameter is a large integer, which is a product of distinct prime
    /// numbers, each up to 60 bits in size. It is represented as a vector
    /// of these prime numbers, each represented by an instance of the
    /// SmallModulus class. The bit-length of coeff_modulus means the sum of
    /// the bit-lengths of its prime factors.
    ///
    /// A larger coeff_modulus implies a larger noise budget, hence more
    /// encrypted computation capabilities. However, an upper bound for the
    /// total bit-length of the coeff_modulus is determined by the
    /// poly_modulus_degree, as follows:
    ///
    ///   +----------------------------------------------------+
    ///   | poly_modulus_degree | max coeff_modulus bit-length |
    ///   +---------------------+------------------------------+
    ///   | 1024                | 27                           |
    ///   | 2048                | 54                           |
    ///   | 4096                | 109                          |
    ///   | 8192                | 218                          |
    ///   | 16384               | 438                          |
    ///   | 32768               | 881                          |
    ///   +---------------------+------------------------------+
    ///
    ///    These numbers can also be found in native/src/seal/util/hestdparms.h
    /// encoded    in the function SEAL_HE_STD_PARMS_128_TC, and can also be
    /// obtained from the    function
    ///
    ///    CoeffModulus::MaxBitCount(poly_modulus_degree)
    ///
    ///    For example, if poly_modulus_degree is 4096, the coeff_modulus could
    /// consist    of three 36-bit primes (108 bits).
    pub fn set_coeff_modulus(&self, primes: &[SmallModulus]) -> Result<()> {
        let mut coeffs: Vec<*mut c_void> = primes.iter().map(|prime| prime.ptr).collect();
        // set the coeff modulus
        let ret = unsafe {
            EncParams_SetCoeffModulus(self.ptr, primes.len() as u64, coeffs.as_mut_ptr())
        };
        anyhow::ensure!(ret == 0, "unable to set the coefficient modulus",);
        Ok(())
    }

    ///    Microsoft SEAL comes with helper functions for selecting the
    /// coeff_modulus. For new users the easiest way is to simply use
    ///
    ///    CoeffModulus::BFVDefault(poly_modulus_degree)
    ///
    ///    which returns std::vector<SmallModulus> consisting of a generally
    /// good choice for the given poly_modulus_degree.
    pub fn bfv_default(&self, security_level: u8) -> Result<Vec<SmallModulus>> {
        let poly_modulus_degree = self.get_poly_modulus_degree()?;
        anyhow::ensure!(
            poly_modulus_degree != 0,
            "set the polynomials modulus degree first"
        );
        let mut coeffs_length = 0u64;
        // first call to get the size
        let ret = unsafe {
            CoeffModulus_BFVDefault(
                poly_modulus_degree as u64,
                security_level as i32,
                &mut coeffs_length,
                std::ptr::null_mut(),
            )
        };
        anyhow::ensure!(
            ret == 0,
            "unable to get the size in coefficients modulus init for security: {}",
            security_level
        );
        // now get the coeffs
        let mut coeffs = vec![std::ptr::null_mut(); coeffs_length as usize];
        let ret = unsafe {
            CoeffModulus_BFVDefault(
                poly_modulus_degree as u64,
                security_level as i32,
                &mut coeffs_length,
                coeffs.as_mut_ptr(),
            )
        };
        anyhow::ensure!(
            ret == 0,
            "unable to get the default coefficients modulus for security: {}",
            security_level
        );
        Ok(coeffs
            .iter()
            .map(|&coeff| SmallModulus { ptr: coeff })
            .collect())
    }

    pub fn set_coeff_modulus_ckks(&self, bits_sizes: &mut [i32]) -> Result<()> {
        let poly_modulus_degree = self.get_poly_modulus_degree()?;
        anyhow::ensure!(
            poly_modulus_degree != 0,
            "set the polynomials modulus degree first"
        );
        let mut coeffs = vec![std::ptr::null_mut(); bits_sizes.len() as usize];
        let ret = unsafe {
            CoeffModulus_Create(
                poly_modulus_degree as u64,
                bits_sizes.len() as u64,
                bits_sizes.as_mut_ptr(),
                coeffs.as_mut_ptr(),
            )
        };
        anyhow::ensure!(
            ret == 0,
            "unable to get the CKKS default coefficients modulus for coeffs: {:?}",
            &bits_sizes
        );
        let ret = unsafe {
            EncParams_SetCoeffModulus(self.ptr, bits_sizes.len() as u64, coeffs.as_mut_ptr())
        };
        anyhow::ensure!(
            ret == 0,
            "unable to set the coefficients modulus for CKKS security: {:?}",
            bits_sizes
        );
        Ok(())
    }

    /// The plaintext modulus can be any positive integer, even though here
    /// we take it to be a power of two. In fact, in many cases one might
    /// instead want it to be a prime number; we will see this in later
    /// examples. The plaintext modulus determines the size of the
    /// plaintext data type and the consumption of noise budget in
    /// multiplications. Thus, it is essential to try to keep the
    /// plaintext data type as small as possible for best performance. The
    /// noise budget in a freshly encrypted ciphertext is
    ///
    ///    around log2(coeff_modulus/plain_modulus) (bits)
    ///
    /// and the noise budget consumption in a homomorphic multiplication is
    /// of the form log2(plain_modulus) + (other terms).
    ///
    /// The plaintext modulus is specific to the BFV scheme, and cannot be
    /// set when using the CKKS scheme.
    pub fn set_plain_modulus(&self, plain_modulus: u64) -> Result<()> {
        let ret = unsafe { EncParams_SetPlainModulus2(self.ptr, plain_modulus) };
        anyhow::ensure!(
            ret == 0,
            "unable to set the plain modulus to: {}",
            plain_modulus
        );
        Ok(())
    }

    /// see setter
    pub fn get_plain_modulus(&self) -> Result<u64> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { EncParams_GetPlainModulus(self.ptr, &mut ptr) };
        anyhow::ensure!(ret == 0, "failed getting the plain modulus");
        let mut modulus_degree: u64 = 0;
        let ret = unsafe { Modulus_Value(ptr, &mut modulus_degree) };
        anyhow::ensure!(ret == 0, "failed extracting the plain modulus");
        Ok(modulus_degree)
    }
}

impl Drop for Params {
    fn drop(&mut self) {
        unsafe {
            EncParams_Destroy(self.ptr);
        }
    }
}
