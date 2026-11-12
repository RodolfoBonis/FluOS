//! Low-level context switching and FPU state save/restore.
//!
//! [`context_switch`] saves the callee-saved registers of the outgoing thread
//! onto its own kernel stack, records that stack pointer, loads the incoming
//! thread's stack pointer, and restores its callee-saved registers before
//! returning into it. Caller-saved registers are preserved automatically
//! because every switch happens at a well-defined call boundary. FPU/SSE state
//! is handled separately with FXSAVE/FXRSTOR around the switch.

use core::arch::naked_asm;

/// Switches kernel stacks: saves the current context, records its stack pointer
/// through `old_rsp`, and resumes the context whose stack pointer is `new_rsp`.
///
/// # Safety
/// `old_rsp` must point at a live `u64` to receive the outgoing stack pointer,
/// and `new_rsp` must be a stack prepared by [`super::super::thread`] (either a
/// freshly initialised frame or one previously saved here).
#[unsafe(naked)]
pub unsafe extern "C" fn context_switch(old_rsp: *mut u64, new_rsp: u64) {
    naked_asm!(
        // Save callee-saved registers of the outgoing thread.
        "push rbp",
        "push rbx",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        // *old_rsp = rsp
        "mov [rdi], rsp",
        // rsp = new_rsp
        "mov rsp, rsi",
        // Restore callee-saved registers of the incoming thread (reverse order).
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop rbp",
        // Return into the incoming thread (its saved return address / trampoline).
        "ret",
    );
}

/// Saves the current FPU/SSE state into `area` (512 bytes, 16-byte aligned).
///
/// # Safety
/// `area` must point at 512 writable, 16-byte-aligned bytes owned by the
/// outgoing thread.
pub unsafe fn fxsave(area: *mut u8) {
    // SAFETY: caller guarantees the alignment and size of `area`.
    unsafe { core::arch::asm!("fxsave64 [{}]", in(reg) area, options(nostack, preserves_flags)) };
}

/// Restores FPU/SSE state previously written by [`fxsave`].
///
/// # Safety
/// `area` must point at a valid 16-byte-aligned FXSAVE image.
pub unsafe fn fxrstor(area: *const u8) {
    // SAFETY: caller guarantees `area` holds a valid FXSAVE image.
    unsafe { core::arch::asm!("fxrstor64 [{}]", in(reg) area, options(nostack, preserves_flags)) };
}
