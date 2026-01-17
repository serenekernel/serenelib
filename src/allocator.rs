extern crate alloc;
use core::alloc::{GlobalAlloc, Layout};

use crate::syscalls::{MemObjPerms, sys_mem_alloc, sys_mem_free};

pub struct SysAllocator;
unsafe impl GlobalAlloc for SysAllocator {
    unsafe fn alloc(&self, mut layout: Layout) -> *mut u8 {
        layout = layout.align_to(4096).expect("Failed to align layout to page size");
        layout = layout.pad_to_align();
        let ptr = sys_mem_alloc(layout.size(), layout.align(), MemObjPerms::READ | MemObjPerms::WRITE)
            .expect("sys_mem_alloc failed") as *mut u8;
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        let _ = sys_mem_free(ptr as usize);
    }
}

#[global_allocator]
pub static ALLOCATOR: SysAllocator = SysAllocator;