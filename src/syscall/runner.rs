use std::arch::asm;

/// Generic runner for up to 10 arguments
#[inline(always)]
pub unsafe fn run_syscall10(
    stub: *mut u8,
    args: [usize; 10],
) -> i32 {
    let ret: i32;

    asm!(
    // 1-4 arguments into registries
    "sub rsp, 0x60",
    "and rsp, -16",
    "mov rcx, {0}",
    "mov rdx, {1}",
    "mov r8,  {2}",
    "mov r9,  {3}",

    // Shadow space + stack args 5-10

    "mov [rsp + 0x20], {4}",   // arg5
    "mov [rsp + 0x28], {5}",   // arg6
    "mov [rsp + 0x30], {6}",   // arg7
    "mov [rsp + 0x38], {7}",   // arg8
    "mov [rsp + 0x40], {8}",   // arg9
    "mov [rsp + 0x48], {9}",   // arg10

    // Call stub
    "call {10}",

    // Restore stack
    "add rsp, 0x60",

    in(reg) args[0],
    in(reg) args[1],
    in(reg) args[2],
    in(reg) args[3],
    in(reg) args[4],
    in(reg) args[5],
    in(reg) args[6],
    in(reg) args[7],
    in(reg) args[8],
    in(reg) args[9],
    in(reg) stub,

    lateout("rax") ret,
    options(preserves_flags)
    );

    ret
}