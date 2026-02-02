use core::arch::asm;
use crate::ipc::{Handle, IpcMessageHeader};
use bitflags::bitflags;

#[inline(always)]
#[doc(hidden)]
pub fn raw_syscall(syscall_nr: usize, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize) -> Result<usize, SyscallError> {
    let return_value: u64;
    let is_error: u64;
    
    unsafe {
        asm!(
            "syscall",
            in("rax") syscall_nr,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            in("r10") arg4,
            in("r8")  arg5,
            in("r9")  arg6,
            lateout("rax") return_value,
            lateout("rdx") is_error,
            lateout("rcx") _,
            lateout("r11") _,
            lateout("r15") _,
            options(nostack),
        );
    }

    if is_error == 0 {
        Ok(return_value as usize)
    } else {
        Err(unsafe { core::mem::transmute(return_value) })
    }
}

const SYS_EXIT: usize = 1;

const SYS_PROCESS_CREATE_EMPTY: usize = 16;
const SYS_START: usize = 17;
const SYS_MEMOBJ_CREATE: usize = 18;
const SYS_MAP: usize = 19;
const SYS_COPY_TO: usize = 20;

const SYS_CAP_PORT_GRANT: usize = 32;

// @note: these ones will HOPEFULLY be temporary
const SYS_CAP_IPC_DISCOVERY: usize = 33;
const SYS_CAP_INITRAMFS: usize = 34;

const SYS_WAIT_FOR: usize = 48;

const SYS_ENDPOINT_CREATE: usize = 64;
const SYS_ENDPOINT_SEND: usize = 66;
const SYS_ENDPOINT_RECEIVE: usize = 67;
const SYS_ENDPOINT_FREE_MESSAGE: usize = 68;

const SYS_HANDLE_DUP: usize = 80;
const SYS_HANDLE_CLOSE: usize = 81;
const SYS_HANDLE_GET_OWNER: usize = 82;
const SYS_HANDLE_SET_OWNER: usize = 83;

const SYS_MEM_ALLOC: usize = 128;
const SYS_MEM_FREE: usize = 129;

#[repr(isize)]
#[derive(Debug, Copy, Clone)]
pub enum SyscallError {
    InvalidArgument = -1,
    InvalidSyscallNumber = -2,
    InvalidHandle = -3,
    WouldBlock = -4,
    PermissionDenied = -5,
    OutOfMemory = -6,
    AddressInUse = -7,
}

pub fn sys_exit(code: usize) -> ! {
    let _ = raw_syscall(SYS_EXIT, code, 0, 0, 0, 0, 0);
    loop {}
}

pub fn sys_cap_port_grant(start_port: u16, number_of_ports: u16) -> Result<(), SyscallError> {
    raw_syscall(
        SYS_CAP_PORT_GRANT,
        start_port as usize,
        number_of_ports as usize,
        0,
        0,
        0,
        0,
    ).map(|_| ())
}

// @maybetemp
pub fn sys_cap_ipc_discovery() -> Result<Handle, SyscallError> {
    raw_syscall(
        SYS_CAP_IPC_DISCOVERY,
        0,
        0,
        0,
        0,
        0,
        0,
    ).map(|handle_value| Handle(handle_value as u64))
}

// @maybetemp
pub fn sys_cap_initramfs() -> Result<u64, SyscallError> {
    raw_syscall(
        SYS_CAP_INITRAMFS,
        0,
        0,
        0,
        0,
        0,
        0,
    ).map(|handle_value| handle_value as u64)
}

pub fn sys_endpoint_create() -> Result<Handle, SyscallError> {
    raw_syscall(
        SYS_ENDPOINT_CREATE,
        0,
        0,
        0,
        0,
        0,
        0,
    ).map(|handle_value| Handle(handle_value as u64))
}

/// Send a message to an endpoint.
/// `payload` is the message payload to send. The payload is copied into kernel memory.
pub fn sys_endpoint_send(handle: Handle, payload: &[u8], handles: &[Handle]) -> Result<(), SyscallError> {
    raw_syscall(
        SYS_ENDPOINT_SEND,
        handle.0 as usize,
        payload.as_ptr() as usize,
        payload.len(),
        handles.as_ptr() as usize,
        handles.len(),
        0,
    ).map(|_| ())
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
    raw_syscall(
        SYS_ENDPOINT_RECEIVE,
        handle.0 as usize,
        0,
        0,
        0,
        0,
        0,
    ).map(|ptr_value| {
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
    raw_syscall(
        SYS_ENDPOINT_FREE_MESSAGE,
        message as usize,
        0,
        0,
        0,
        0,
        0,
    ).map(|_| ())
}

pub fn sys_endpoint_destroy(handle: Handle) -> Result<(), SyscallError> {
    raw_syscall(SYS_ENDPOINT_CREATE + 1, handle.0 as usize, 0, 0, 0, 0, 0).map(|_| ())
}

pub fn sys_handle_dup(handle: &Handle) -> Result<Handle, SyscallError> {
    raw_syscall(SYS_HANDLE_DUP, handle.0 as usize, 0, 0, 0, 0, 0)
        .map(|handle_value| Handle(handle_value as u64))
}

pub fn sys_handle_close(handle: Handle) -> Result<(), SyscallError> {
    raw_syscall(SYS_HANDLE_CLOSE, handle.0 as usize, 0, 0, 0, 0, 0).map(|_| ())
}

pub fn sys_handle_get_owner(handle: &Handle) -> Result<u64, SyscallError> {
    raw_syscall(SYS_HANDLE_GET_OWNER, handle.0 as usize, 0, 0, 0, 0, 0)
        .map(|handle_value| handle_value as u64)
}

pub fn sys_handle_set_owner(handle: Handle, new_owner: u64) -> Result<(), SyscallError> {
    raw_syscall(SYS_HANDLE_SET_OWNER, handle.0 as usize, new_owner as usize, 0, 0, 0, 0)
        .map(|_| ())
}

/// Wait for a handle to become ready.
pub fn sys_wait_for(handle: Handle) -> Result<(), SyscallError> {
    raw_syscall(SYS_WAIT_FOR, handle.0 as usize, 0, 0, 0, 0, 0).map(|_| ())
}

bitflags! {
    #[repr(transparent)]
    #[derive(Copy, Clone, Debug)]
    pub struct MemObjPerms: u64 {
        const READ  = 1 << 0;
        const WRITE = 1 << 1;
        const EXEC  = 1 << 2;
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Copy, Clone, Debug)]
    pub struct MemObjMapFlags: u64 {
        const NONE = 0;
        const FIXED = 1 << 0;  // Map at exact address
    }
}

/// Create an empty process with no mappings or threads
pub fn sys_process_create_empty() -> Result<Handle, SyscallError> {
    raw_syscall(
        SYS_PROCESS_CREATE_EMPTY,
        0,
        0,
        0,
        0,
        0,
        0,
    ).map(|handle_value| Handle(handle_value as u64))
}

/// Create a memory object with the given size and permissions
pub fn sys_memobj_create(size: usize, perms: MemObjPerms) -> Result<Handle, SyscallError> {
    raw_syscall(
        SYS_MEMOBJ_CREATE,
        size,
        perms.bits() as usize,
        0,
        0,
        0,
        0,
    ).map(|handle_value| Handle(handle_value as u64))
}

/// Map a memory object into a process's address space
/// # Returns Virtual address where the memory was mapped
pub fn sys_map(
    process: Handle,
    memobj: Handle,
    vaddr_hint: Option<u64>,
    perms: MemObjPerms,
    flags: MemObjMapFlags,
) -> Result<usize, SyscallError> {
    raw_syscall(
        SYS_MAP,
        process.0 as usize,
        memobj.0 as usize,
        vaddr_hint.unwrap_or(0) as usize,
        perms.bits() as usize,
        flags.bits() as usize,
        0,
    )
}

/// Copy data from current process to target process
pub fn sys_copy_to(
    process: Handle,
    dst: usize,
    src: *const u8,
    size: usize,
) -> Result<(), SyscallError> {
    raw_syscall(
        SYS_COPY_TO,
        process.0 as usize,
        dst,
        src as usize,
        size,
        0,
        0,
    ).map(|_| ())
}

/// Start a process by creating its first thread
pub fn sys_start(process: Handle, entry: usize) -> Result<(), SyscallError> {
    raw_syscall(
        SYS_START,
        process.0 as usize,
        entry,
        0,
        0,
        0,
        0,
    ).map(|_| ())
}

/// Allocate memory from the kernel
pub fn sys_mem_alloc(size: usize, align: usize, perms: MemObjPerms) -> Result<usize, SyscallError> {
    raw_syscall(
        SYS_MEM_ALLOC,
        size,
        align,
        perms.bits() as usize,
        0,
        0,
        0
    )
}

/// Free memory previously allocated with `sys_mem_alloc`
pub fn sys_mem_free(ptr: usize) -> Result<(), SyscallError> {
    raw_syscall(
        SYS_MEM_FREE,
        ptr,
        0,
        0,
        0,
        0,
        0,
    ).map(|_| ())
}