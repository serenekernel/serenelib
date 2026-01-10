#![no_std]
#![no_main]
use core::arch::asm;

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

#[repr(isize)]
#[derive(Debug, Copy, Clone)]
pub enum SyscallError {
    InvalidArgument = -1,
    InvalidSyscallNumber = -2,
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
