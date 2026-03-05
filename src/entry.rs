#[macro_export]
macro_rules! serene_entry {
    ($path:path) => {
        use core::arch::global_asm;
        
        global_asm!(
            ".section .text",
            ".global _start",
            "_start:",
            "    mov rdi, rsp",
            "    call _entry"
        );

        #[unsafe(no_mangle)]
        pub extern "C" fn _entry(stack: u64) -> ! {
            extern crate alloc;
            use alloc::vec::Vec;
            
            sys_cap_port_grant(0xe9, 1).expect("sys_cap_port_grant failed");

            let stack_ptr = stack as *mut u64;
            let argc = unsafe { *stack_ptr.offset(0) } as usize;

            let mut argv: Vec<&[u8]> = Vec::with_capacity(argc);
            let mut envp: Vec<&[u8]> = Vec::new();
            let mut auxv: Vec<(u64, u64)> = Vec::new();

            for i in 0..argc {
                let arg_ptr = unsafe { *stack_ptr.offset(1 + i as isize) } as *const u8;
                let arg_len = unsafe {
                    let mut l = 0;
                    while *arg_ptr.offset(l) != 0 { l += 1; }
                    l as usize
                };
                let arg_slice = unsafe { core::slice::from_raw_parts(arg_ptr, arg_len) };
                argv.push(arg_slice);
            }

            let mut envp_offset = 1 + argc + 1;
            loop {
                let env_ptr = unsafe { *stack_ptr.offset(envp_offset as isize) } as *const u8;
                if env_ptr.is_null() { break; }
                let env_len = unsafe {
                    let mut l = 0;
                    while *env_ptr.offset(l) != 0 { l += 1; }
                    l as usize
                };
                let env_slice = unsafe { core::slice::from_raw_parts(env_ptr, env_len) };
                envp.push(env_slice);
                envp_offset += 1;
            }

            let mut auxv_offset = envp_offset + 1;
            loop {
                let aux_type = unsafe { *stack_ptr.offset(auxv_offset as isize) } as u64;
                if aux_type == 0 { break; }
                let aux_val = unsafe { *stack_ptr.offset((auxv_offset + 1) as isize) } as u64;
                auxv.push((aux_type, aux_val));
                auxv_offset += 2;
            }

            let main: fn(Vec<&[u8]>, Vec<&[u8]>, Vec<(u64, u64)>) -> i32 = $path;
            
            $crate::syscalls::sys_exit(main(argv, envp, auxv) as usize);
        }
    };
}
