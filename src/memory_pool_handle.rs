use std::os::raw::*;

use anyhow::Result;

use crate::seal_bindings::*;

#[derive(Clone)]
pub struct MemoryPoolHandle {
    ptr: *mut ::std::os::raw::c_void,
}

impl MemoryPoolHandle {
    /// Create a Handle to a system provided  Memory Pool
    pub fn to_thread_local_pool() -> Result<MemoryPoolHandle> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let ret = unsafe { MemoryManager_GetPool2(&mut ptr) };
        anyhow::ensure!(ret == 0, "Error creating the memory pool");
        Ok(MemoryPoolHandle { ptr })
    }

    pub(crate) fn ptr(&self) -> *mut c_void {
        self.ptr
    }
}

impl Drop for MemoryPoolHandle {
    fn drop(&mut self) {
        unsafe {
            MemoryPoolHandle_Destroy(self.ptr);
        }
    }
}
