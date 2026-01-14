use core::arch::asm;

use crate::ipc::{Handle, IpcMessageHeader};

#[inline(always)]
#[doc(hidden)]
pub fn raw_syscall(a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> u128 {
    let lo: u64;
    let hi: u64;

    unsafe {
        asm!(
            "syscall",
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            in("r8")  a4,
            in("r9")  a5,
            lateout("rax") lo,
            lateout("rdx") hi,
            lateout("rcx") _,
            lateout("r11") _,
            lateout("r15") _,
            options(nostack),
        );
    }


    ((hi as u128) << 64) | (lo as u128)
}

const SYS_EXIT: usize = 1;

const SYS_CAP_PORT_GRANT: usize = 32;
const SYS_CAP_IPC_DISCOVERY: usize = 33;

const SYS_WAIT_FOR: usize = 48;

const SYS_ENDPOINT_CREATE: usize = 64;
const SYS_ENDPOINT_DESTROY: usize = 65;
const SYS_ENDPOINT_SEND: usize = 66;
const SYS_ENDPOINT_RECEIVE: usize = 67;
const SYS_ENDPOINT_FREE_MESSAGE: usize = 68;

#[repr(isize)]
#[derive(Debug, Copy, Clone)]
pub enum SyscallError {
    InvalidArgument = -1,
    InvalidSyscallNumber = -2,
    InvalidHandle = -3,
    WouldBlock = -4,
}

#[inline(always)]
#[doc(hidden)]
fn decode_ret(ret: u128) -> Result<usize, SyscallError> {
    let v = ret as isize;
    if v < 0 {
        Err(unsafe { core::mem::transmute(v) })
    } else {
        Ok(ret as usize)
    }
}

pub fn sys_exit(code: usize) -> ! {
    let _ = raw_syscall(SYS_EXIT, code, 0, 0, 0, 0);
    loop {}
}

pub fn sys_cap_port_grant(start_port: u16, number_of_ports: u16) -> Result<(), SyscallError> {
    let ret = raw_syscall(
        SYS_CAP_PORT_GRANT,
        start_port as usize,
        number_of_ports as usize,
        0,
        0,
        0,
    );
    decode_ret(ret).map(|_| ())
}

// @maybetemp
pub fn sys_cap_ipc_discovery() -> Result<Handle, SyscallError> {
    let ret = raw_syscall(
        SYS_CAP_IPC_DISCOVERY,
        0,
        0,
        0,
        0,
        0,
    );
    decode_ret(ret).map(|handle_value| Handle(handle_value as u64))
}

pub fn sys_endpoint_create() -> Result<Handle, SyscallError> {
    let ret = raw_syscall(
        SYS_ENDPOINT_CREATE,
        0,
        0,
        0,
        0,
        0,
    );
    decode_ret(ret).map(|handle_value| Handle(handle_value as u64))
}

pub fn sys_endpoint_destroy(handle: Handle) -> Result<(), SyscallError> {
    let ret = raw_syscall(SYS_ENDPOINT_DESTROY, handle.0 as usize, 0, 0, 0, 0);
    decode_ret(ret).map(|_| ())
}

/// Send a message to an endpoint.
/// `payload` is the message payload to send. The payload is copied into kernel memory.
pub fn sys_endpoint_send(handle: Handle, payload: &[u8]) -> Result<(), SyscallError> {
    let ret = raw_syscall(
        SYS_ENDPOINT_SEND,
        handle.0 as usize,
        payload.as_ptr() as usize,
        payload.len(),
        0,
        0,
    );
    decode_ret(ret).map(|_| ())
}

/// Receive a message from an endpoint.
///
/// Returns a pointer to the IPC message header and the total size of the allocation
/// (including the header and payload).
///
/// # Safety
/// The returned pointer is kernel-allocated memory that must be freed by calling
/// `sys_endpoint_free_message` when done. The pointer is valid for the returned size.
pub fn sys_endpoint_receive(
    handle: Handle,
) -> Result<(*mut IpcMessageHeader, usize), SyscallError> {
    let ret = raw_syscall(
        SYS_ENDPOINT_RECEIVE,
        handle.0 as usize,
        0,
        0,
        0,
        0,
    );
    decode_ret(ret).map(|ptr_value| {
        let message_ptr = ptr_value as *mut IpcMessageHeader;
        // Safety: we trust the kernel to return a valid pointer
        // User must read the length field from the message structure
        let total_size = unsafe { 
            let length = (*message_ptr).length as usize;
            core::mem::size_of::<IpcMessageHeader>() + length
        };
        (message_ptr, total_size)
    })
}

/// Free a received IPC message.
/// # Safety
/// The `message` pointer must be a valid pointer returned by `sys_endpoint_receive`.
pub unsafe fn sys_endpoint_free_message(message: *mut IpcMessageHeader) -> Result<(), SyscallError> {
    let ret = raw_syscall(
        SYS_ENDPOINT_FREE_MESSAGE, // Free message syscall
        message as usize,
        0,
        0,
        0,
        0,
    );
    decode_ret(ret).map(|_| ())
}

/// Wait for a handle to become ready.
pub fn sys_wait_for(handle: Handle) -> Result<(), SyscallError> {
    let ret = raw_syscall(SYS_WAIT_FOR, handle.0 as usize, 0, 0, 0, 0);
    decode_ret(ret).map(|_| ())
}