use std::os::raw::*;

use anyhow::Result;

use crate::seal_bindings::*;

pub struct SmallModulus {
    pub(crate) ptr: *mut c_void,
}

impl SmallModulus {
    pub fn create(value: u64) -> Result<SmallModulus> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { Modulus_Create1(value, &mut ptr) };
        anyhow::ensure!(ret == 0, "Error creating the small modulus");
        Ok(SmallModulus { ptr })
    }

    pub fn for_batching(poly_modulus_degree: usize, bit_size: u8) -> Result<SmallModulus> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let mut bit_sizes: Vec<i32> = vec![bit_size as i32];
        let ret = unsafe {
            CoeffModulus_Create(
                poly_modulus_degree as u64,
                1,
                bit_sizes.as_mut_ptr(),
                &mut ptr,
            )
        };
        anyhow::ensure!(ret == 0, "Error creating the small modulus");
        // the first element is a SmallModulus
        Ok(SmallModulus { ptr })
    }

    pub fn value(&self) -> Result<u64> {
        let mut value: u64 = 0;
        let ret = unsafe { Modulus_Value(self.ptr, &mut value) };
        anyhow::ensure!(
            ret == 0,
            "Error extracting the value from the small modulus"
        );
        Ok(value)
    }
}

impl Drop for SmallModulus {
    fn drop(&mut self) {
        unsafe {
            Modulus_Destroy(self.ptr);
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum ModulusError {
    ConversionError,
    CreationError,
}

impl TryFrom<u64> for SmallModulus {
    type Error = crate::small_modulus::ModulusError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Err(Self::Error::ConversionError),
            _ => {
                let mut res = Self {
                    ptr: std::ptr::null_mut(),
                };
                unsafe {
                    Modulus_Create1(value, &mut res.ptr);
                }
                Ok(res)
            }
        }
    }
}

impl<'a> TryFrom<&'a SmallModulus> for u64 {
    type Error = crate::small_modulus::ModulusError;

    fn try_from(m: &'a SmallModulus) -> Result<u64, Self::Error> {
        m.value().map_err(|err| -> Self::Error {
            println!("{:?}", err);
            Self::Error::ConversionError
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_modulus() -> Result<()> {
        let m = 256;
        anyhow::ensure!(
            m == (&SmallModulus::try_from(m).expect("Should not fail!"))
                .try_into()
                .expect("Should not fail"),
            "Wrong conversion from u64 to Modulus!"
        );
        Ok(())
    }
}
