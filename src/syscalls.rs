use core::arch::asm;

use crate::ipc::{Handle, IpcMessageHeader};

#[inline(always)]
#[doc(hidden)]
pub fn raw_syscall(a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> usize {
    let ret: usize;

    unsafe {
        asm!(
            "syscall",
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            in("r8")  a4,
            in("r9")  a5,
            lateout("rax") ret,
            lateout("r15") _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }

    ret
}

const SYS_EXIT: usize = 1;
const SYS_CAP_PORT_GRANT: usize = 32;

const SYS_ENDPOINT_CREATE: usize = 1;
const SYS_ENDPOINT_DESTROY: usize = 65;
const SYS_ENDPOINT_SEND: usize = 66;
const SYS_ENDPOINT_RECEIVE: usize = 67;

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
fn decode_ret(ret: usize) -> Result<usize, SyscallError> {
    let v = ret as isize;
    if v < 0 {
        Err(unsafe { core::mem::transmute(v) })
    } else {
        Ok(ret)
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

pub fn sys_endpoint_create() -> Result<Handle, SyscallError> {
    let mut handle: u64 = 0;
    let ret = raw_syscall(
        SYS_ENDPOINT_CREATE,
        &mut handle as *mut u64 as usize,
        0,
        0,
        0,
        0,
    );
    decode_ret(ret).map(|_| Handle(handle))
}

pub fn sys_endpoint_destroy(handle: Handle) -> Result<(), SyscallError> {
    let ret = raw_syscall(SYS_ENDPOINT_DESTROY, handle.0 as usize, 0, 0, 0, 0);
    decode_ret(ret).map(|_| ())
}

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
    let mut out_payload: u64 = 0;
    let mut out_payload_length: u64 = 0;
    let ret = raw_syscall(
        SYS_ENDPOINT_RECEIVE,
        handle.0 as usize,
        &mut out_payload as *mut u64 as usize,
        &mut out_payload_length as *mut u64 as usize,
        0,
        0,
    );
    decode_ret(ret).map(|_| {
        (
            out_payload as *mut IpcMessageHeader,
            out_payload_length as usize,
        )
    })
}
