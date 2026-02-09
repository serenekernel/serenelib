#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Handle(pub u64);

#[repr(C)]
pub struct IpcMessageHeader {
    pub length: u32,   
    pub sender_pid: u64,
    pub reply_handle: u64,
}

impl IpcMessageHeader {
    pub unsafe fn payload(&self) -> &[u8] {
        let payload_ptr = (self as *const Self).add(1) as *const u8;
        core::slice::from_raw_parts(payload_ptr, self.length as usize)
    }
    pub unsafe fn payload_mut(&mut self) -> &mut [u8] {
        let payload_ptr = (self as *mut Self).add(1) as *mut u8;
        core::slice::from_raw_parts_mut(payload_ptr, self.length as usize)
    }
}
